package a10

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
)

// CertificateTarget identifies one certificate slot in a client-SSL template.
// CurrentCertificate is optional for templates with zero or one binding, but
// is required to select a slot when certificate-list has multiple entries.
type CertificateTarget struct {
	// ClientSSLTemplate is the operator-defined ACOS template name.
	ClientSSLTemplate ClientSSLTemplateName `json:"clientSSLTemplate"`
	// CurrentCertificate disambiguates a multi-entry certificate-list.
	CurrentCertificate CertificateFileName `json:"currentCertificate,omitempty"`
}

// ForClientSSLTemplate selects the sole/default binding of a client-SSL
// template. Synchronization rejects an ambiguous multi-certificate template.
func ForClientSSLTemplate(name ClientSSLTemplateName) CertificateTarget {
	return CertificateTarget{ClientSSLTemplate: name}
}

// ForCertificateBinding selects an exact certificate binding in a client-SSL
// template with multiple certificate-list entries. SNI server-name-list
// mappings are inventoried separately and are not mutated by this operation.
func ForCertificateBinding(template ClientSSLTemplateName, currentCertificate CertificateFileName) CertificateTarget {
	return CertificateTarget{ClientSSLTemplate: template, CurrentCertificate: currentCertificate}
}

// SyncOptions controls safe A10 certificate synchronization. The zero value
// creates non-exportable keys, retains the previous files, and writes the final
// running configuration to memory. CleanupOld must be enabled explicitly.
type SyncOptions struct {
	// NamePrefix overrides the checksum-managed file prefix.
	NamePrefix string `json:"namePrefix,omitempty"`
	// ExpectedRevision is an optional compare-before-change precondition.
	ExpectedRevision TemplateRevision `json:"expectedRevision,omitempty"`
	// ExportableKey asks ACOS to mark the uploaded key exportable.
	ExportableKey bool `json:"exportableKey,omitempty"`
	// CleanupOld authorizes deletion of proven-unreferenced old files.
	CleanupOld bool `json:"cleanupOld,omitempty"`
	// NoWriteMemory skips persistence of running configuration.
	NoWriteMemory bool `json:"noWriteMemory,omitempty"`
	// Shared sets the ACOS certificate binding shared flag.
	Shared bool `json:"shared,omitempty"`
}

// CreateOptions controls safe pre-staging of certificate material before a
// client-SSL template exists. NamePrefix is required because ACOS resources
// are operator-visible files rather than anonymous numeric objects.
type CreateOptions struct {
	// NamePrefix is combined with the bundle checksum for immutable file names.
	NamePrefix string `json:"namePrefix"`
	// ExportableKey asks ACOS to mark the uploaded key exportable.
	ExportableKey bool `json:"exportableKey,omitempty"`
	// NoWriteMemory skips persistence of the uploaded files.
	NoWriteMemory bool `json:"noWriteMemory,omitempty"`
}

// CreateResult reports pre-staged, deliberately unbound A10 material.
type CreateResult struct {
	Stage       SyncStage          `json:"stage"`
	Changed     bool               `json:"changed"`
	Uploaded    bool               `json:"uploaded"`
	WroteMemory bool               `json:"wroteMemory"`
	Certificate ManagedCertificate `json:"certificate"`
}

// ManagedCertificate is the public, secret-free state of a managed A10 pair.
type ManagedCertificate struct {
	// Name is the managed ACOS certificate and key file base name.
	Name CertificateFileName `json:"name"`
	// ChainName is the optional managed CA-chain file.
	ChainName CertificateFileName `json:"chainName,omitempty"`
	// CertificateChecksum hashes canonical leaf DER.
	CertificateChecksum Checksum `json:"certificateChecksum"`
	// KeyChecksum hashes canonical unencrypted PKCS#8 DER.
	KeyChecksum Checksum `json:"keyChecksum"`
	// BundleChecksum hashes the complete pair and chain.
	BundleChecksum Checksum `json:"bundleChecksum"`
	// Target is the logical client-SSL certificate slot.
	Target CertificateTarget `json:"target"`
}

// SyncStage identifies the last fully verified phase of a synchronization.
// It lets operators distinguish a harmless retry from a state that requires
// reconciliation after a partial appliance or network failure.
type SyncStage string

const (
	SyncStageStarted               SyncStage = "started"
	SyncStageCompatibilityVerified SyncStage = "compatibility-verified"
	SyncStageStateInspected        SyncStage = "state-inspected"
	SyncStageMaterialReady         SyncStage = "material-ready"
	SyncStageBound                 SyncStage = "bound"
	SyncStageOldBindingRemoved     SyncStage = "old-binding-removed"
	SyncStageCleanupComplete       SyncStage = "cleanup-complete"
	SyncStagePersisted             SyncStage = "persisted"
	SyncStageComplete              SyncStage = "complete"
)

// SyncResult reports the actions performed by SyncCertificate.
type SyncResult struct {
	// Stage is the last fully verified synchronization stage.
	Stage SyncStage `json:"stage"`
	// Changed reports whether desired state differed.
	Changed bool `json:"changed"`
	// Uploaded reports certificate/key/chain file uploads.
	Uploaded bool `json:"uploaded"`
	// Bound reports creation of the desired complete binding.
	Bound bool `json:"bound"`
	// UnboundOld reports explicit removal of the old binding.
	UnboundOld bool `json:"unboundOld"`
	// DeletedOld lists exact old material removed after reference checks.
	DeletedOld []string `json:"deletedOld,omitempty"`
	// WroteMemory reports final running-config persistence.
	WroteMemory bool `json:"wroteMemory"`
	// PreviousBinding is the binding observed before synchronization.
	PreviousBinding *CertificateBinding `json:"previousBinding,omitempty"`
	// Certificate is the final secret-free managed state.
	Certificate ManagedCertificate `json:"certificate"`
	// InitialRevision is the template revision read before mutation.
	InitialRevision TemplateRevision `json:"initialRevision"`
	// FinalRevision is the revision verified after mutation.
	FinalRevision TemplateRevision `json:"finalRevision"`
}

// AmbiguousStateError reports that an appliance mutation may have completed,
// but the observed follow-up state was neither the before nor the expected
// after state. ReconcileCertificate is safe to call after operator review.
type AmbiguousStateError struct {
	Target   CertificateTarget
	Stage    SyncStage
	Expected TemplateRevision
	Actual   TemplateRevision
	Cause    error
}

func (err *AmbiguousStateError) Error() string {
	return fmt.Sprintf("A10 state is ambiguous after %s for client-SSL template %q (expected %s, got %s)",
		err.Stage, err.Target.ClientSSLTemplate, err.Expected, err.Actual)
}

func (err *AmbiguousStateError) Unwrap() error        { return err.Cause }
func (err *AmbiguousStateError) Is(target error) bool { return target == ErrAmbiguousState }

// SyncCertificate performs a checksum-versioned A10 rotation: upload the new
// immutable pair, bind it, verify ACOS's resulting binding state, remove an old
// binding when ACOS did not replace it atomically, clean up only unreferenced
// old files, and write memory.
func (c *Client) SyncCertificate(ctx context.Context, target CertificateTarget, bundle CertificateBundle, options SyncOptions) (result SyncResult, err error) {
	if ctx == nil {
		return result, errors.New("context must not be nil")
	}
	if err := bundle.validateForSync(time.Now()); err != nil {
		return result, err
	}
	if err := validateTarget(target); err != nil {
		return result, err
	}
	c.managedMu.Lock()
	defer c.managedMu.Unlock()
	session, err := c.StartSession(ctx)
	if err != nil {
		return result, err
	}
	defer func() {
		closeErr := session.Close(ctx)
		err = errors.Join(err, closeErr)
	}()
	return session.SyncCertificate(ctx, target, bundle, options)
}

// CreateManagedCertificate uploads checksum-versioned certificate, key, and
// chain files without requiring or modifying a client-SSL template. Managed
// writes invoked through the same Client are serialized for parallel
// producer/consumer pipelines.
func (c *Client) CreateManagedCertificate(ctx context.Context, bundle CertificateBundle, options CreateOptions) (result CreateResult, err error) {
	if ctx == nil {
		return result, errors.New("context must not be nil")
	}
	if err := bundle.validateForSync(time.Now()); err != nil {
		return result, err
	}
	c.managedMu.Lock()
	defer c.managedMu.Unlock()
	session, err := c.StartSession(ctx)
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, session.Close(ctx)) }()
	return session.CreateManagedCertificate(ctx, bundle, options)
}

// CreateManagedCertificate uploads an unbound managed pair through this
// session. Calls sharing the Session are serialized; reads remain concurrent.
func (s *Session) CreateManagedCertificate(ctx context.Context, bundle CertificateBundle, options CreateOptions) (CreateResult, error) {
	s.managedMu.Lock()
	defer s.managedMu.Unlock()
	result := CreateResult{Stage: SyncStageStarted}
	if err := bundle.validateForSync(time.Now()); err != nil {
		return result, err
	}
	if _, err := s.VerifyCompatibility(ctx); err != nil {
		return result, err
	}
	result.Stage = SyncStageCompatibilityVerified
	name, chainName, err := managedNamesForPrefix(bundle, options.NamePrefix)
	if err != nil {
		return result, err
	}
	result.Certificate = ManagedCertificate{
		Name: name, ChainName: chainName, CertificateChecksum: bundle.Certificate.Checksum,
		KeyChecksum: bundle.Key.Checksum, BundleChecksum: bundle.Checksum,
	}
	certificateFiles, err := s.ListCertificateFiles(ctx)
	if err != nil {
		return result, err
	}
	keyFiles, err := s.ListKeyFiles(ctx)
	if err != nil {
		return result, err
	}
	certificates, err := s.ListCertificates(ctx)
	if err != nil {
		return result, err
	}
	if !contains(keyFiles, KeyFileName(name)) {
		if err := s.UploadKey(ctx, KeyFileName(name), bundle.Key.PEM(), UploadOptions{ExportableKey: options.ExportableKey}); err != nil {
			return result, fmt.Errorf("upload A10 private key %q: %w", name, err)
		}
		result.Uploaded, result.Changed = true, true
	}
	if contains(certificateFiles, name) {
		if err := verifyManagedCertificateCollision(certificates, name, bundle.Certificate); err != nil {
			return result, err
		}
	} else {
		if err := s.UploadCertificate(ctx, name, bundle.Certificate.PEM(), UploadOptions{}); err != nil {
			return result, fmt.Errorf("upload A10 certificate %q: %w", name, err)
		}
		result.Uploaded, result.Changed = true, true
	}
	if chainName != "" {
		if contains(certificateFiles, chainName) {
			if err := verifyManagedCertificateCollision(certificates, chainName, bundle.Chain[0]); err != nil {
				return result, err
			}
		} else {
			if err := s.UploadChain(ctx, chainName, bundle.chainPEM(), UploadOptions{}); err != nil {
				return result, fmt.Errorf("upload A10 certificate chain %q: %w", chainName, err)
			}
			result.Uploaded, result.Changed = true, true
		}
	}
	result.Stage = SyncStageMaterialReady
	if result.Changed && !options.NoWriteMemory {
		if err := s.WriteMemory(ctx); err != nil {
			return result, fmt.Errorf("persist A10 pre-staged certificate material: %w", err)
		}
		result.WroteMemory = true
		result.Stage = SyncStagePersisted
	}
	result.Stage = SyncStageComplete
	return result, nil
}

// ReconcileCertificate converges an interrupted synchronization by reusing
// immutable checksum-derived material names and re-reading every relevant
// appliance state. It never guesses or performs a blind rollback.
func (c *Client) ReconcileCertificate(ctx context.Context, target CertificateTarget, bundle CertificateBundle, options SyncOptions) (SyncResult, error) {
	return c.SyncCertificate(ctx, target, bundle, options)
}

// ReconcileCertificate converges an interrupted synchronization through an
// existing authenticated session.
func (s *Session) ReconcileCertificate(ctx context.Context, target CertificateTarget, bundle CertificateBundle, options SyncOptions) (SyncResult, error) {
	return s.SyncCertificate(ctx, target, bundle, options)
}

// SyncCertificate synchronizes through an existing session.
func (s *Session) SyncCertificate(ctx context.Context, target CertificateTarget, bundle CertificateBundle, options SyncOptions) (SyncResult, error) {
	s.managedMu.Lock()
	defer s.managedMu.Unlock()
	result := SyncResult{Stage: SyncStageStarted}
	if err := bundle.validateForSync(time.Now()); err != nil {
		return result, err
	}
	if err := validateTarget(target); err != nil {
		return result, err
	}
	if _, err := s.VerifyCompatibility(ctx); err != nil {
		return result, err
	}
	result.Stage = SyncStageCompatibilityVerified
	name, chainName, err := managedNames(target, bundle, options.NamePrefix)
	if err != nil {
		return result, err
	}
	result.Certificate = ManagedCertificate{
		Name: name, ChainName: chainName,
		CertificateChecksum: bundle.Certificate.Checksum,
		KeyChecksum:         bundle.Key.Checksum,
		BundleChecksum:      bundle.Checksum,
		Target:              target,
	}

	template, err := s.GetClientSSLTemplate(ctx, target.ClientSSLTemplate)
	if err != nil {
		return result, err
	}
	baselineRevision := template.Revision()
	result.InitialRevision = baselineRevision
	result.FinalRevision = baselineRevision
	result.Stage = SyncStageStateInspected
	if options.ExpectedRevision != "" && options.ExpectedRevision != baselineRevision {
		return result, &ConflictError{
			Target: target, Stage: "initial compare", Expected: options.ExpectedRevision, Actual: baselineRevision,
		}
	}
	desired := CertificateBinding{Certificate: name, Key: KeyFileName(name), Chain: chainName}
	if options.Shared {
		desired.Shared = true
	}
	current, err := selectCurrentBinding(template.Certificates, target, desired)
	if err != nil {
		return result, err
	}
	if current != nil {
		copyCurrent := *current
		result.PreviousBinding = &copyCurrent
	}

	certificateFiles, err := s.ListCertificateFiles(ctx)
	if err != nil {
		return result, err
	}
	keyFiles, err := s.ListKeyFiles(ctx)
	if err != nil {
		return result, err
	}
	certificates, err := s.ListCertificates(ctx)
	if err != nil {
		return result, err
	}
	if !contains(keyFiles, desired.Key) {
		if err := s.UploadKey(ctx, desired.Key, bundle.Key.PEM(), UploadOptions{ExportableKey: options.ExportableKey}); err != nil {
			return result, fmt.Errorf("upload A10 private key %q: %w", name, err)
		}
		result.Uploaded = true
		result.Changed = true
	}
	if contains(certificateFiles, name) {
		if err := verifyManagedCertificateCollision(certificates, name, bundle.Certificate); err != nil {
			return result, err
		}
	} else {
		if err := s.UploadCertificate(ctx, name, bundle.Certificate.PEM(), UploadOptions{}); err != nil {
			return result, fmt.Errorf("upload A10 certificate %q: %w", name, err)
		}
		result.Uploaded = true
		result.Changed = true
	}
	if chainName != "" && !contains(certificateFiles, chainName) {
		if err := s.UploadChain(ctx, chainName, bundle.chainPEM(), UploadOptions{}); err != nil {
			return result, fmt.Errorf("upload A10 server certificate chain %q: %w", chainName, err)
		}
		result.Uploaded = true
		result.Changed = true
	} else if chainName != "" {
		if err := verifyManagedCertificateCollision(certificates, chainName, bundle.Chain[0]); err != nil {
			return result, err
		}
	}
	result.Stage = SyncStageMaterialReady

	// Uploading immutable files can take long enough for a GUI user or another
	// automation source to edit the template. Re-read immediately before the
	// first binding mutation and fail closed if its logical state changed.
	if _, err := s.requireTemplateRevision(ctx, target, baselineRevision, "pre-bind verification"); err != nil {
		return result, err
	}
	expectedTemplate := template
	implicitReplacement := false
	if !hasBinding(template.Certificates, desired) {
		appendedTemplate := templateWithBinding(template, desired)
		replacedTemplate := appendedTemplate
		if current != nil && current.Certificate != desired.Certificate {
			replacedTemplate = templateWithoutCertificate(appendedTemplate, current.Certificate)
		}
		bindErr := s.BindCertificate(ctx, target.ClientSSLTemplate, desired, bundle.Key.passphrase)
		if bindErr == nil {
			result.Bound = true
			result.Changed = true
		}
		verified, err := s.GetClientSSLTemplate(ctx, target.ClientSSLTemplate)
		if err != nil {
			if bindErr != nil {
				return result, &AmbiguousStateError{
					Target: target, Stage: SyncStageMaterialReady, Expected: appendedTemplate.Revision(),
					Actual: baselineRevision, Cause: errors.Join(bindErr, err),
				}
			}
			return result, fmt.Errorf("read back A10 certificate binding: %w", err)
		}
		actualRevision := verified.Revision()
		switch {
		case actualRevision == appendedTemplate.Revision():
			expectedTemplate = verified
		case current != nil && current.Certificate != desired.Certificate && actualRevision == replacedTemplate.Revision():
			expectedTemplate = verified
			implicitReplacement = true
		case bindErr != nil && actualRevision == baselineRevision:
			return result, fmt.Errorf("bind A10 certificate %q to client-SSL template %q: %w", name, target.ClientSSLTemplate, bindErr)
		case bindErr != nil:
			return result, &AmbiguousStateError{
				Target: target, Stage: SyncStageMaterialReady,
				Expected: appendedTemplate.Revision(), Actual: actualRevision, Cause: bindErr,
			}
		default:
			return result, &ConflictError{
				Target: target, Stage: "post-bind verification",
				Expected: appendedTemplate.Revision(), Actual: actualRevision,
			}
		}
		result.Bound = true
		result.Changed = true
		result.Stage = SyncStageBound
	} else {
		verified, err := s.requireTemplateRevision(ctx, target, expectedTemplate.Revision(), "post-bind verification")
		if err != nil {
			return result, err
		}
		expectedTemplate = verified
	}

	if current != nil && current.Certificate != desired.Certificate {
		actual, oldStillBound := findBinding(expectedTemplate.Certificates, current.Certificate)
		if oldStillBound && !sameBinding(actual, *current) {
			return result, &ConflictError{
				Target: target, Stage: "old-binding verification",
				Expected: expectedTemplate.Revision(), Actual: expectedTemplate.Revision(),
			}
		}
		if oldStillBound {
			if _, err := s.requireTemplateRevision(ctx, target, expectedTemplate.Revision(), "pre-unbind verification"); err != nil {
				return result, err
			}
			if err := s.UnbindCertificate(ctx, target.ClientSSLTemplate, current.Certificate); err != nil {
				return result, fmt.Errorf("remove previous A10 certificate binding %q: %w", current.Certificate, err)
			}
			expectedTemplate = templateWithoutCertificate(expectedTemplate, current.Certificate)
			if _, err := s.requireTemplateRevision(ctx, target, expectedTemplate.Revision(), "post-unbind verification"); err != nil {
				return result, err
			}
		} else if !implicitReplacement {
			return result, &ConflictError{
				Target: target, Stage: "old-binding verification",
				Expected: expectedTemplate.Revision(), Actual: expectedTemplate.Revision(),
			}
		}
		result.UnboundOld = true
		result.Changed = true
		result.Stage = SyncStageOldBindingRemoved
		if options.CleanupOld {
			deleted, err := s.deleteUnreferenced(ctx, *current, desired)
			if err != nil {
				return result, err
			}
			result.DeletedOld = deleted
			result.Stage = SyncStageCleanupComplete
		}
	}

	result.FinalRevision = expectedTemplate.Revision()
	if result.Changed && !options.NoWriteMemory {
		if _, err := s.requireTemplateRevision(ctx, target, result.FinalRevision, "pre-persistence verification"); err != nil {
			return result, err
		}
		if err := s.WriteMemory(ctx); err != nil {
			return result, fmt.Errorf("A10 running configuration changed but write memory failed: %w", err)
		}
		result.WroteMemory = true
		result.Stage = SyncStagePersisted
	}
	result.Stage = SyncStageComplete
	return result, nil
}

func validateTarget(target CertificateTarget) error {
	if err := validateTemplateName("client-SSL template", target.ClientSSLTemplate.String()); err != nil {
		return err
	}
	if target.CurrentCertificate != "" {
		return validateFileName(target.CurrentCertificate.String())
	}
	return nil
}

func managedNames(target CertificateTarget, bundle CertificateBundle, configuredPrefix string) (CertificateFileName, CertificateFileName, error) {
	prefix := strings.TrimSpace(configuredPrefix)
	if prefix == "" {
		prefix = target.ClientSSLTemplate.String()
	}
	return managedNamesForPrefix(bundle, prefix)
}

func managedNamesForPrefix(bundle CertificateBundle, configuredPrefix string) (CertificateFileName, CertificateFileName, error) {
	prefix := strings.TrimSpace(configuredPrefix)
	if prefix == "" {
		return "", "", errors.New("managed A10 name prefix must not be empty when creating unbound material")
	}
	prefix = sanitizeName(prefix)
	if prefix == "" {
		return "", "", errors.New("managed A10 name prefix contains no usable characters")
	}
	digest := strings.TrimPrefix(string(bundle.Checksum), "sha256:")
	if len(digest) < 32 {
		return "", "", errors.New("certificate bundle checksum is malformed")
	}
	name := CertificateFileName(limitedName(prefix, "-"+digest[:32]))
	var chainName CertificateFileName
	if len(bundle.Chain) != 0 {
		chainName = CertificateFileName(limitedName(prefix, "-chain-"+digest[:32]))
	}
	return name, chainName, nil
}

func sanitizeName(value string) string {
	var builder strings.Builder
	lastDash := false
	for _, r := range value {
		allowed := unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' || r == '_' || r == '-'
		if allowed && r <= unicode.MaxASCII {
			builder.WriteRune(r)
			lastDash = r == '-'
			continue
		}
		if !lastDash {
			builder.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(builder.String(), "-.")
}

func limitedName(prefix, suffix string) string {
	maxPrefix := 245 - len(suffix)
	if len(prefix) > maxPrefix {
		prefix = strings.TrimRight(prefix[:maxPrefix], "-.")
	}
	return prefix + suffix
}

func selectCurrentBinding(bindings []CertificateBinding, target CertificateTarget, desired CertificateBinding) (*CertificateBinding, error) {
	if target.CurrentCertificate != "" {
		binding, ok := findBinding(bindings, target.CurrentCertificate)
		if !ok {
			return nil, fmt.Errorf("certificate %q is not bound to client-SSL template %q", target.CurrentCertificate, target.ClientSSLTemplate)
		}
		return &binding, nil
	}
	if binding, ok := findBinding(bindings, desired.Certificate); ok && sameBinding(binding, desired) {
		return &binding, nil
	}
	switch len(bindings) {
	case 0:
		return nil, nil
	case 1:
		binding := bindings[0]
		return &binding, nil
	default:
		return nil, fmt.Errorf("client-SSL template %q has %d certificate bindings; select one with CurrentCertificate", target.ClientSSLTemplate, len(bindings))
	}
}

func selectTargetBinding(bindings []CertificateBinding, target CertificateTarget) (*CertificateBinding, error) {
	if target.CurrentCertificate != "" {
		binding, ok := findBinding(bindings, target.CurrentCertificate)
		if !ok {
			return nil, fmt.Errorf("certificate %q is not bound to client-SSL template %q", target.CurrentCertificate, target.ClientSSLTemplate)
		}
		return &binding, nil
	}
	switch len(bindings) {
	case 0:
		return nil, nil
	case 1:
		binding := bindings[0]
		return &binding, nil
	default:
		return nil, fmt.Errorf("client-SSL template %q has %d certificate bindings; select one with CurrentCertificate", target.ClientSSLTemplate, len(bindings))
	}
}

func verifyManagedCertificateCollision(inventory []CertificateInfo, name CertificateFileName, desired Certificate) error {
	for _, item := range inventory {
		if item.Name != name {
			continue
		}
		actualSerial := strings.TrimLeft(strings.TrimPrefix(strings.ToUpper(item.Serial), "0X"), "0")
		desiredSerial := strings.TrimLeft(strings.ToUpper(desired.Serial), "0")
		if actualSerial == "" {
			actualSerial = "0"
		}
		if desiredSerial == "" {
			desiredSerial = "0"
		}
		commonName := desired.parsed.Subject.CommonName
		desiredKeySize := 0
		switch publicKey := desired.parsed.PublicKey.(type) {
		case *rsa.PublicKey:
			desiredKeySize = publicKey.N.BitLen()
		case *ecdsa.PublicKey:
			desiredKeySize = publicKey.Curve.Params().BitSize
		}
		if actualSerial != desiredSerial || item.CommonName != commonName ||
			(item.NotAfterNumber != 0 && item.NotAfterNumber != desired.parsed.NotAfter.Unix()) ||
			(item.KeySize != 0 && desiredKeySize != 0 && item.KeySize != desiredKeySize) {
			return fmt.Errorf("managed A10 file name %q already contains a different certificate", name)
		}
		return nil
	}
	return fmt.Errorf("A10 certificate file %q exists but has no operational certificate metadata", name)
}

func (s *Session) deleteUnreferenced(ctx context.Context, previous, desired CertificateBinding) ([]string, error) {
	templates, err := s.ListClientSSLTemplates(ctx)
	if err != nil {
		return nil, fmt.Errorf("check certificate references before cleanup: %w", err)
	}
	serverTemplates, err := s.ListServerSSLTemplates(ctx)
	if err != nil {
		return nil, fmt.Errorf("check server-SSL certificate references before cleanup: %w", err)
	}
	referenced := func(name string) (bool, error) {
		for _, template := range templates {
			found, err := clientTemplateReferences(template, name)
			if err != nil || found {
				return found, err
			}
		}
		for _, template := range serverTemplates {
			found, err := serverTemplateReferences(template, name)
			if err != nil || found {
				return found, err
			}
		}
		return false, nil
	}
	certificateReferenced, err := referenced(previous.Certificate.String())
	if err != nil {
		return nil, fmt.Errorf("inspect previous certificate references: %w", err)
	}
	keyReferenced, err := referenced(previous.Key.String())
	if err != nil {
		return nil, fmt.Errorf("inspect previous private-key references: %w", err)
	}
	chainReferenced, err := referenced(previous.Chain.String())
	if err != nil {
		return nil, fmt.Errorf("inspect previous chain references: %w", err)
	}
	var names MaterialNames
	var deleted []string
	if previous.Certificate != "" && previous.Certificate != desired.Certificate && !certificateReferenced {
		names.Certificate = previous.Certificate
		deleted = append(deleted, "certificate:"+previous.Certificate.String())
	}
	if previous.Key != "" && previous.Key != desired.Key && !keyReferenced {
		names.Key = previous.Key
		deleted = append(deleted, "key:"+previous.Key.String())
	}
	if names != (MaterialNames{}) {
		if err := s.DeleteMaterial(ctx, names); err != nil {
			return nil, fmt.Errorf("delete unreferenced previous certificate material: %w", err)
		}
	}
	if previous.Chain != "" && previous.Chain != desired.Chain && !chainReferenced {
		if err := s.DeleteMaterial(ctx, MaterialNames{Certificate: previous.Chain}); err != nil {
			return nil, fmt.Errorf("delete unreferenced previous certificate chain: %w", err)
		}
		deleted = append(deleted, "chain:"+previous.Chain.String())
	}
	return deleted, nil
}

func clientTemplateReferences(template ClientSSLTemplate, name string) (bool, error) {
	if name == "" {
		return false, nil
	}
	for _, binding := range template.Certificates {
		if binding.Certificate.String() == name || binding.Key.String() == name || binding.Chain.String() == name {
			return true, nil
		}
	}
	for _, binding := range template.ServerNames {
		if binding.Certificate.String() == name || binding.Key.String() == name || binding.Chain.String() == name ||
			binding.RegexCertificate.String() == name || binding.RegexKey.String() == name || binding.RegexChain.String() == name {
			return true, nil
		}
	}
	forward := template.ForwardProxy
	if template.ChainCertificate.String() == name || forward.CACertificate.String() == name || forward.CAKey.String() == name ||
		forward.Certificate.String() == name || forward.Key.String() == name || forward.Chain.String() == name ||
		forward.AlternateCertificate.String() == name || forward.AlternateKey.String() == name || forward.AlternateChain.String() == name {
		return true, nil
	}
	return rawPayloadReferences(template.revisionPayload, name)
}

func serverTemplateReferences(template ServerSSLTemplate, name string) (bool, error) {
	if name == "" {
		return false, nil
	}
	if template.Certificate != nil &&
		(template.Certificate.Certificate.String() == name || template.Certificate.Key.String() == name) {
		return true, nil
	}
	return rawPayloadReferences(template.referencePayload, name)
}

// rawPayloadReferences scans complete, already-decoded aXAPI template
// responses for an exact string value. This deliberately favors retention:
// an unknown ACOS 6.x field or an unrelated equal value can prevent deletion,
// but can never cause referenced material to be deleted.
func rawPayloadReferences(payload []byte, name string) (bool, error) {
	if name == "" || len(payload) == 0 {
		return false, nil
	}
	var value any
	if err := json.Unmarshal(payload, &value); err != nil {
		return false, fmt.Errorf("decode retained aXAPI template response: %w", err)
	}
	return jsonValueContainsString(value, name), nil
}

func jsonValueContainsString(value any, target string) bool {
	switch typed := value.(type) {
	case string:
		return typed == target
	case []any:
		for _, child := range typed {
			if jsonValueContainsString(child, target) {
				return true
			}
		}
	case map[string]any:
		for _, child := range typed {
			if jsonValueContainsString(child, target) {
				return true
			}
		}
	}
	return false
}

func contains[T comparable](values []T, value T) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

func findBinding(bindings []CertificateBinding, certificate CertificateFileName) (CertificateBinding, bool) {
	for _, binding := range bindings {
		if binding.Certificate == certificate {
			return binding, true
		}
	}
	return CertificateBinding{}, false
}

func hasBinding(bindings []CertificateBinding, desired CertificateBinding) bool {
	for _, binding := range bindings {
		if sameBinding(binding, desired) {
			return true
		}
	}
	return false
}

func sameBinding(left, right CertificateBinding) bool {
	return left.Certificate == right.Certificate && left.Key == right.Key && left.Chain == right.Chain && left.Shared == right.Shared
}
