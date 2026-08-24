package a10

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// TemplateRevision is a deterministic SHA-256 fingerprint of a complete
// client-SSL template response. It includes unknown vendor configuration
// fields but excludes generated UUID/URL metadata and binding order. The tested ACOS 6.0.9
// does not expose ETags, object revisions, or a configuration transaction for
// these APIs, so the library uses this value for optimistic conflict detection.
type TemplateRevision string

// String returns the serialized sha256 revision value.
func (revision TemplateRevision) String() string { return string(revision) }

// ParseTemplateRevision validates a revision previously returned by this
// package.
func ParseTemplateRevision(value string) (TemplateRevision, error) {
	value = strings.TrimSpace(value)
	encoded := strings.TrimPrefix(value, "sha256:")
	if !strings.HasPrefix(value, "sha256:") || len(encoded) != sha256.Size*2 {
		return "", errors.New("template revision must use sha256: followed by 64 hexadecimal characters")
	}
	if _, err := hex.DecodeString(encoded); err != nil {
		return "", errors.New("template revision contains non-hexadecimal characters")
	}
	return TemplateRevision(value), nil
}

// Revision returns a stable fingerprint. Binding order and aXAPI-generated
// UUID/URL metadata do not affect it.
func (template ClientSSLTemplate) Revision() TemplateRevision {
	type revisionBinding struct {
		Certificate CertificateFileName `json:"certificate"`
		Key         KeyFileName         `json:"key"`
		Chain       CertificateFileName `json:"chain,omitempty"`
		Shared      bool                `json:"shared"`
	}
	bindings := make([]revisionBinding, len(template.Certificates))
	for index, binding := range template.Certificates {
		bindings[index] = revisionBinding{
			Certificate: binding.Certificate,
			Key:         binding.Key,
			Chain:       binding.Chain,
			Shared:      binding.Shared,
		}
	}
	sort.Slice(bindings, func(left, right int) bool {
		leftJSON, _ := json.Marshal(bindings[left])
		rightJSON, _ := json.Marshal(bindings[right])
		return string(leftJSON) < string(rightJSON)
	})
	var revisionState any
	if len(template.revisionPayload) != 0 {
		var complete map[string]any
		if err := json.Unmarshal(template.revisionPayload, &complete); err == nil {
			complete["name"] = template.Name
			complete["certificate-list"] = bindings
			removeGeneratedA10Metadata(complete)
			revisionState = complete
		}
	}
	if revisionState == nil {
		revisionState = map[string]any{
			"name":             template.Name,
			"certificate-list": bindings,
		}
	}
	canonical, _ := json.Marshal(revisionState)
	digest := sha256.Sum256(canonical)
	return TemplateRevision("sha256:" + hex.EncodeToString(digest[:]))
}

func removeGeneratedA10Metadata(value any) {
	switch typed := value.(type) {
	case map[string]any:
		delete(typed, "uuid")
		delete(typed, "a10-url")
		for _, child := range typed {
			removeGeneratedA10Metadata(child)
		}
	case []any:
		for _, child := range typed {
			removeGeneratedA10Metadata(child)
		}
	}
}

// CertificateState is a secret-free, high-level view of one logical
// certificate slot. Callers can persist TemplateRevision and pass it back as
// SyncOptions.ExpectedRevision for compare-before-change behavior.
type CertificateState struct {
	// Target is the selected logical client-SSL certificate slot.
	Target CertificateTarget `json:"target"`
	// TemplateRevision is derived from normalized complete template JSON.
	TemplateRevision TemplateRevision `json:"templateRevision"`
	// Binding is the selected certificate-list entry, if present.
	Binding *CertificateBinding `json:"binding,omitempty"`
	// Certificate is secret-free operational X.509 metadata.
	Certificate *CertificateInfo `json:"certificate,omitempty"`
	// Key is secret-free operational key metadata.
	Key *KeyInfo `json:"key,omitempty"`
}

// ConflictError reports an optimistic concurrency conflict. No old binding or
// certificate material is removed after this error is detected.
type ConflictError struct {
	Target   CertificateTarget `json:"target"`
	Stage    string            `json:"stage"`
	Expected TemplateRevision  `json:"expected"`
	Actual   TemplateRevision  `json:"actual"`
}

func (err *ConflictError) Error() string {
	return fmt.Sprintf(
		"A10 client-SSL template %q changed concurrently during %s (expected %s, got %s)",
		err.Target.ClientSSLTemplate,
		err.Stage,
		err.Expected,
		err.Actual,
	)
}

func (err *ConflictError) Is(target error) bool { return target == ErrConflict }

// IsConflict reports whether err represents a concurrent appliance change.
func IsConflict(err error) bool {
	return errors.Is(err, ErrConflict)
}

// GetManagedCertificateState reads a logical certificate slot through an independent
// authenticated session.
func (client *Client) GetManagedCertificateState(ctx context.Context, target CertificateTarget) (state CertificateState, err error) {
	if ctx == nil {
		return state, errors.New("context must not be nil")
	}
	session, err := client.StartSession(ctx)
	if err != nil {
		return state, err
	}
	defer func() { err = errors.Join(err, session.Close(ctx)) }()
	return session.GetManagedCertificateState(ctx, target)
}

// GetManagedCertificateState reads one logical certificate slot without exposing
// private-key bytes.
func (session *Session) GetManagedCertificateState(ctx context.Context, target CertificateTarget) (CertificateState, error) {
	if err := validateTarget(target); err != nil {
		return CertificateState{}, err
	}
	template, err := session.GetClientSSLTemplate(ctx, target.ClientSSLTemplate)
	if err != nil {
		return CertificateState{}, err
	}
	state := CertificateState{Target: target, TemplateRevision: template.Revision()}
	binding, err := selectTargetBinding(template.Certificates, target)
	if err != nil {
		return CertificateState{}, err
	}
	if binding == nil {
		return state, nil
	}
	copyBinding := *binding
	state.Binding = &copyBinding
	certificate, err := session.GetCertificate(ctx, binding.Certificate)
	if err != nil {
		return CertificateState{}, fmt.Errorf("resolve bound certificate: %w", err)
	}
	key, err := session.GetKey(ctx, binding.Key)
	if err != nil {
		return CertificateState{}, fmt.Errorf("resolve bound private key: %w", err)
	}
	state.Certificate = &certificate
	state.Key = &key
	return state, nil
}

func (session *Session) requireTemplateRevision(
	ctx context.Context,
	target CertificateTarget,
	expected TemplateRevision,
	stage string,
) (ClientSSLTemplate, error) {
	template, err := session.GetClientSSLTemplate(ctx, target.ClientSSLTemplate)
	if err != nil {
		return ClientSSLTemplate{}, err
	}
	actual := template.Revision()
	if actual != expected {
		return template, &ConflictError{Target: target, Stage: stage, Expected: expected, Actual: actual}
	}
	return template, nil
}

func templateWithBinding(template ClientSSLTemplate, binding CertificateBinding) ClientSSLTemplate {
	copyTemplate := template
	copyTemplate.Certificates = append([]CertificateBinding(nil), template.Certificates...)
	if !hasBinding(copyTemplate.Certificates, binding) {
		copyTemplate.Certificates = append(copyTemplate.Certificates, binding)
	}
	return copyTemplate
}

func templateWithoutCertificate(template ClientSSLTemplate, certificate CertificateFileName) ClientSSLTemplate {
	copyTemplate := template
	copyTemplate.Certificates = make([]CertificateBinding, 0, len(template.Certificates))
	for _, binding := range template.Certificates {
		if binding.Certificate != certificate {
			copyTemplate.Certificates = append(copyTemplate.Certificates, binding)
		}
	}
	return copyTemplate
}
