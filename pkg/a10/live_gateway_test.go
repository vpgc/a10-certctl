package a10

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLiveACOS6CreateManagedCertificateWithoutTemplate(t *testing.T) {
	if os.Getenv("A10_LIVE_TEST") != "1" {
		t.Skip("set A10_LIVE_TEST=1 to run the mutating, self-cleaning appliance test")
	}
	client, err := New(Config{
		Address: os.Getenv("A10_HOST"), Username: os.Getenv("A10_USERNAME"), Password: os.Getenv("A10_PASSWORD"),
		Partition: os.Getenv("A10_PARTITION"), InsecureSkipVerify: liveBool("A10_LIVE_INSECURE_SKIP_VERIFY"), Timeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	prefix := "certctl-unbound-" + suffix
	leafPEM, keyPEM := newTestPEMPair(t, prefix+".example.invalid")
	bundle, err := ParseCertificateBundle(CertificateBundleInput{CertificatePEM: leafPEM, PrivateKeyPEM: keyPEM})
	if err != nil {
		t.Fatal(err)
	}
	name, _, err := managedNamesForPrefix(bundle, prefix)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cleanupCancel()
		session, sessionErr := client.StartSession(cleanupContext)
		if sessionErr != nil {
			t.Errorf("start unbound cleanup session: %v", sessionErr)
			return
		}
		deleteErr := session.DeleteMaterial(cleanupContext, MaterialNames{Certificate: name, Key: KeyFileName(name)})
		writeErr := session.WriteMemory(cleanupContext)
		closeErr := session.Close(cleanupContext)
		if err := errors.Join(deleteErr, writeErr, closeErr); err != nil && !IsNotFound(err) {
			t.Errorf("clean up unbound certificate material: %v", err)
		}
	}()
	result, err := client.CreateManagedCertificate(ctx, bundle, CreateOptions{NamePrefix: prefix})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || !result.Uploaded || !result.WroteMemory || result.RolledBack || result.Certificate.Name != name || result.Certificate.Target != (CertificateTarget{}) {
		t.Fatalf("unexpected unbound create result: %#v", result)
	}
	session, err := client.StartSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	certificateFiles, certificateErr := session.ListCertificateFiles(ctx)
	keyFiles, keyErr := session.ListKeyFiles(ctx)
	closeErr := session.Close(ctx)
	if err := errors.Join(certificateErr, keyErr, closeErr); err != nil {
		t.Fatal(err)
	}
	if !contains(certificateFiles, name) || !contains(keyFiles, KeyFileName(name)) {
		t.Fatalf("pre-staged material missing: certs=%v keys=%v", certificateFiles, keyFiles)
	}
	t.Logf("pre-staged unbound ACOS certificate and key %q", name)
}

type failFirstWriteMemoryTransport struct {
	base   http.RoundTripper
	mutex  sync.Mutex
	failed bool
}

func (transport *failFirstWriteMemoryTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.mutex.Lock()
	if !transport.failed && request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/write/memory") {
		transport.failed = true
		transport.mutex.Unlock()
		_ = request.Body.Close()
		return &http.Response{
			StatusCode: http.StatusBadRequest,
			Status:     "400 injected persistence failure",
			Header:     make(http.Header),
			Body: io.NopCloser(strings.NewReader(
				`{"response":{"err":{"code":1,"msg":"injected persistence failure","location":"memory"}}}`,
			)),
			Request: request,
		}, nil
	}
	transport.mutex.Unlock()
	return transport.base.RoundTrip(request)
}

func TestLiveACOS6CreateRollbackOnPersistenceFailure(t *testing.T) {
	if os.Getenv("A10_LIVE_TEST") != "1" {
		t.Skip("set A10_LIVE_TEST=1 to run the mutating, self-cleaning appliance test")
	}
	baseTransport := http.DefaultTransport.(*http.Transport).Clone()
	baseTransport.TLSClientConfig = &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: liveBool("A10_LIVE_INSECURE_SKIP_VERIFY"), //nolint:gosec -- explicit lab test option
	}
	transport := &failFirstWriteMemoryTransport{base: baseTransport}
	client, err := New(Config{
		Address: os.Getenv("A10_HOST"), Username: os.Getenv("A10_USERNAME"), Password: os.Getenv("A10_PASSWORD"),
		Partition: os.Getenv("A10_PARTITION"), HTTPClient: &http.Client{Transport: transport, Timeout: 30 * time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	prefix := fmt.Sprintf("certctl-rollback-%d", time.Now().UnixNano())
	leafPEM, keyPEM := newTestPEMPair(t, prefix+".example.invalid")
	bundle, err := ParseCertificateBundle(CertificateBundleInput{CertificatePEM: leafPEM, PrivateKeyPEM: keyPEM})
	if err != nil {
		t.Fatal(err)
	}
	name, _, err := managedNamesForPrefix(bundle, prefix)
	if err != nil {
		t.Fatal(err)
	}
	result, createErr := client.CreateManagedCertificate(ctx, bundle, CreateOptions{NamePrefix: prefix})
	if createErr == nil || errors.Is(createErr, ErrAmbiguousState) {
		t.Fatalf("expected injected persistence error after successful rollback, got %v", createErr)
	}
	if !result.RolledBack || result.Stage != SyncStageRolledBack || result.WroteMemory {
		t.Fatalf("unexpected live rollback result: %#v", result)
	}
	verify, err := client.StartSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	certificates, certErr := verify.ListCertificateFiles(ctx)
	keys, keyErr := verify.ListKeyFiles(ctx)
	closeErr := verify.Close(ctx)
	if err := errors.Join(certErr, keyErr, closeErr); err != nil {
		t.Fatal(err)
	}
	if contains(certificates, name) || contains(keys, KeyFileName(name)) {
		t.Fatalf("live rollback left certificate material %q: certs=%v keys=%v", name, certificates, keys)
	}
	t.Logf("verified compensating rollback of live unbound material %q", name)
}

func TestLiveACOS6EmptyPartitionsByNameAndID(t *testing.T) {
	if os.Getenv("A10_LIVE_TEST") != "1" {
		t.Skip("set A10_LIVE_TEST=1 to run the appliance integration tests")
	}
	baseConfig := Config{
		Address: os.Getenv("A10_HOST"), Username: os.Getenv("A10_USERNAME"), Password: os.Getenv("A10_PASSWORD"),
		InsecureSkipVerify: liveBool("A10_LIVE_INSECURE_SKIP_VERIFY"), Timeout: 30 * time.Second,
	}
	client, err := New(baseConfig)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	session, err := client.StartSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	partitions, listErr := session.ListPartitions(ctx)
	sharedWriteErr := session.WriteMemory(ctx)
	closeErr := session.Close(ctx)
	if err := errors.Join(listErr, sharedWriteErr, closeErr); err != nil {
		t.Fatal(err)
	}
	if len(partitions) < 2 {
		t.Fatalf("expected the two test L3V partitions, got %#v", partitions)
	}
	for _, partition := range partitions {
		for _, config := range []Config{
			{Address: baseConfig.Address, Username: baseConfig.Username, Password: baseConfig.Password, Partition: partition.Name.String(), InsecureSkipVerify: true, Timeout: 30 * time.Second},
			{Address: baseConfig.Address, Username: baseConfig.Username, Password: baseConfig.Password, PartitionID: partition.ID, InsecureSkipVerify: true, Timeout: 30 * time.Second},
		} {
			partitionClient, err := New(config)
			if err != nil {
				t.Fatal(err)
			}
			partitionSession, err := partitionClient.StartSession(ctx)
			if err != nil {
				t.Fatalf("select partition %#v: %v", partition, err)
			}
			certificates, certErr := partitionSession.ListCertificateFiles(ctx)
			keys, keyErr := partitionSession.ListKeyFiles(ctx)
			metadata, metadataErr := partitionSession.ListCertificates(ctx)
			writeErr := partitionSession.WriteMemory(ctx)
			closeErr := partitionSession.Close(ctx)
			if err := errors.Join(certErr, keyErr, metadataErr, writeErr, closeErr); err != nil {
				t.Fatalf("exercise partition %#v: %v", partition, err)
			}
			t.Logf("partition %q (ID %d): certificates=%d keys=%d metadata=%d", partition.Name, partition.ID, len(certificates), len(keys), len(metadata))
		}
	}
}

func TestLiveACOS6CertificateLifecycle(t *testing.T) {
	if os.Getenv("A10_LIVE_TEST") != "1" {
		t.Skip("set A10_LIVE_TEST=1 to run the mutating, self-cleaning appliance test")
	}
	client, err := New(Config{
		Address: os.Getenv("A10_HOST"), Username: os.Getenv("A10_USERNAME"), Password: os.Getenv("A10_PASSWORD"),
		Partition: os.Getenv("A10_PARTITION"), InsecureSkipVerify: liveBool("A10_LIVE_INSECURE_SKIP_VERIFY"), Timeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	templateName := ClientSSLTemplateName("certctl-live-" + suffix)
	leafPEM, keyPEM, caPEM := newTestChain(t, "live-"+suffix+".example.invalid")
	bundle, err := ParseCertificateBundle(CertificateBundleInput{
		CertificatePEM: leafPEM, PrivateKeyPEM: keyPEM, CertificateChainPEM: [][]byte{caPEM},
	})
	if err != nil {
		t.Fatal(err)
	}
	managedName, chainName, err := managedNames(ForClientSSLTemplate(templateName), bundle, templateName.String())
	if err != nil {
		t.Fatal(err)
	}
	managedCertificates := []CertificateFileName{managedName}
	managedChains := []CertificateFileName{chainName}

	setup, err := client.StartSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	version, compatibilityErr := setup.VerifyCompatibility(ctx)
	if compatibilityErr != nil {
		_ = setup.Close(ctx)
		t.Fatal(compatibilityErr)
	}
	t.Logf("verified ACOS compatibility: %s (aXAPI %s)", version.SoftwareVersion, version.AXAPIVersion)
	createErr := setup.Raw().DoJSON(ctx, http.MethodPost, "/slb/template/client-ssl", map[string]any{
		"client-ssl": map[string]any{"name": templateName.String()},
	}, nil, http.StatusOK, http.StatusCreated, http.StatusNoContent)
	closeErr := setup.Close(ctx)
	if err := joinErrors(createErr, closeErr); err != nil {
		t.Fatal(err)
	}

	defer func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cleanupCancel()
		session, sessionErr := client.StartSession(cleanupContext)
		if sessionErr != nil {
			t.Errorf("start cleanup session: %v", sessionErr)
			return
		}
		var cleanupErrors []error
		template, getErr := session.GetClientSSLTemplate(cleanupContext, templateName)
		if getErr == nil {
			for _, certificateName := range managedCertificates {
				if _, bound := findBinding(template.Certificates, certificateName); bound {
					cleanupErrors = append(cleanupErrors, session.UnbindCertificate(cleanupContext, templateName, certificateName))
				}
			}
		}
		certificateFiles, certErr := session.ListCertificateFiles(cleanupContext)
		keyFiles, keyErr := session.ListKeyFiles(cleanupContext)
		cleanupErrors = append(cleanupErrors, certErr, keyErr)
		for _, certificateName := range managedCertificates {
			material := MaterialNames{}
			if contains(certificateFiles, certificateName) {
				material.Certificate = certificateName
			}
			if contains(keyFiles, KeyFileName(certificateName)) {
				material.Key = KeyFileName(certificateName)
			}
			if material != (MaterialNames{}) {
				cleanupErrors = append(cleanupErrors, session.DeleteMaterial(cleanupContext, material))
			}
		}
		for _, managedChain := range managedChains {
			if managedChain != "" && contains(certificateFiles, managedChain) {
				cleanupErrors = append(cleanupErrors, session.DeleteMaterial(cleanupContext, MaterialNames{Certificate: managedChain}))
			}
		}
		deleteErr := session.Raw().DoJSON(cleanupContext, http.MethodDelete, "/slb/template/client-ssl/"+templateName.String(), nil, nil, http.StatusOK, http.StatusNoContent)
		_, remainingTemplateErr := session.GetClientSSLTemplate(cleanupContext, templateName)
		if remainingTemplateErr == nil {
			cleanupErrors = append(cleanupErrors, errors.New("live test client-SSL template remained after cleanup"))
		} else if !IsNotFound(remainingTemplateErr) {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("verify live test template cleanup: %w", remainingTemplateErr))
		}
		remainingCertificates, remainingCertErr := session.ListCertificateFiles(cleanupContext)
		remainingKeys, remainingKeyErr := session.ListKeyFiles(cleanupContext)
		cleanupErrors = append(cleanupErrors, remainingCertErr, remainingKeyErr)
		for _, certificateName := range append(append([]CertificateFileName(nil), managedCertificates...), managedChains...) {
			if certificateName != "" && contains(remainingCertificates, certificateName) {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("live test certificate material %q remained after cleanup", certificateName))
			}
		}
		for _, certificateName := range managedCertificates {
			if contains(remainingKeys, KeyFileName(certificateName)) {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("live test private key %q remained after cleanup", certificateName))
			}
		}
		closeErr := session.Close(cleanupContext)
		cleanupErrors = append(cleanupErrors, deleteErr, closeErr)
		if cleanupErr := errors.Join(cleanupErrors...); cleanupErr != nil {
			t.Errorf("clean up live test objects: %v", cleanupErr)
		}
	}()

	result, err := client.SyncCertificate(ctx, ForClientSSLTemplate(templateName), bundle, SyncOptions{
		NamePrefix: templateName.String(), NoWriteMemory: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || !result.Uploaded || !result.Bound || result.WroteMemory {
		t.Fatalf("unexpected live sync result: %#v", result)
	}
	verify, err := client.StartSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	template, verifyErr := verify.GetClientSSLTemplate(ctx, templateName)
	closeErr = verify.Close(ctx)
	if err := joinErrors(verifyErr, closeErr); err != nil {
		t.Fatal(err)
	}
	if len(template.Certificates) != 1 || template.Certificates[0].Certificate != managedName || template.Certificates[0].Key != KeyFileName(managedName) || template.Certificates[0].Chain != chainName {
		t.Fatalf("unexpected live template binding: %#v", template.Certificates)
	}
	state, err := client.GetManagedCertificateState(ctx, ForClientSSLTemplate(templateName))
	if err != nil {
		t.Fatal(err)
	}
	if state.Binding == nil || state.Certificate == nil || state.Key == nil || state.TemplateRevision != result.FinalRevision {
		t.Fatalf("unexpected live logical certificate state: %#v", state)
	}

	rotatedLeafPEM, rotatedKeyPEM, rotatedCAPEM := newTestChain(t, "rotated-"+suffix+".example.invalid")
	rotatedBundle, err := ParseCertificateBundle(CertificateBundleInput{
		CertificatePEM: rotatedLeafPEM, PrivateKeyPEM: rotatedKeyPEM, CertificateChainPEM: [][]byte{rotatedCAPEM},
	})
	if err != nil {
		t.Fatal(err)
	}
	rotatedName, rotatedChain, err := managedNames(ForClientSSLTemplate(templateName), rotatedBundle, templateName.String())
	if err != nil {
		t.Fatal(err)
	}
	managedCertificates = append(managedCertificates, rotatedName)
	managedChains = append(managedChains, rotatedChain)
	rotation, err := client.SyncCertificate(
		ctx,
		ForCertificateBinding(templateName, managedName),
		rotatedBundle,
		SyncOptions{
			NamePrefix: templateName.String(), ExpectedRevision: state.TemplateRevision,
			CleanupOld: true, NoWriteMemory: true,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !rotation.Changed || !rotation.Uploaded || !rotation.Bound || !rotation.UnboundOld || len(rotation.DeletedOld) != 3 || rotation.WroteMemory {
		t.Fatalf("unexpected live rotation result: %#v", rotation)
	}
	rotatedState, err := client.GetManagedCertificateState(ctx, ForClientSSLTemplate(templateName))
	if err != nil {
		t.Fatal(err)
	}
	if rotatedState.Binding == nil || rotatedState.Binding.Certificate != rotatedName || rotatedState.Binding.Key != KeyFileName(rotatedName) || rotatedState.Binding.Chain != rotatedChain || rotatedState.TemplateRevision != rotation.FinalRevision {
		t.Fatalf("unexpected rotated live state: %#v", rotatedState)
	}
	inventorySession, err := client.StartSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	certificateFiles, certificateErr := inventorySession.ListCertificateFiles(ctx)
	keyFiles, keyErr := inventorySession.ListKeyFiles(ctx)
	closeErr = inventorySession.Close(ctx)
	if err := errors.Join(certificateErr, keyErr, closeErr); err != nil {
		t.Fatal(err)
	}
	if contains(certificateFiles, managedName) || contains(certificateFiles, chainName) || contains(keyFiles, KeyFileName(managedName)) {
		t.Fatalf("old live material remained after requested cleanup: certs=%v keys=%v", certificateFiles, keyFiles)
	}
}

func TestLiveACOS6ConcurrentReadSessions(t *testing.T) {
	if os.Getenv("A10_LIVE_TEST") != "1" {
		t.Skip("set A10_LIVE_TEST=1 to run the appliance integration tests")
	}
	client, err := New(Config{
		Address: os.Getenv("A10_HOST"), Username: os.Getenv("A10_USERNAME"), Password: os.Getenv("A10_PASSWORD"),
		Partition: os.Getenv("A10_PARTITION"), InsecureSkipVerify: liveBool("A10_LIVE_INSECURE_SKIP_VERIFY"), Timeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	const workers = 8
	errorsFound := make(chan error, workers)
	var wait sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			session, err := client.StartSession(ctx)
			if err != nil {
				errorsFound <- err
				return
			}
			_, versionErr := session.VerifyCompatibility(ctx)
			_, listErr := session.ListCertificates(ctx)
			_, serverTemplateErr := session.ListServerSSLTemplates(ctx)
			closeErr := session.Close(ctx)
			if err := errors.Join(versionErr, listErr, serverTemplateErr, closeErr); err != nil {
				errorsFound <- err
			}
		}()
	}
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		t.Errorf("concurrent read session failed: %v", err)
	}
}

func TestLiveACOS6VIPInventoryAndTLS(t *testing.T) {
	if os.Getenv("A10_LIVE_TEST") != "1" {
		t.Skip("set A10_LIVE_TEST=1 to run the appliance integration tests")
	}
	vip := strings.TrimSpace(os.Getenv("A10_TEST_VIP"))
	if vip == "" {
		t.Skip("set A10_TEST_VIP to validate an existing data-plane virtual server")
	}
	port := 443
	if value := strings.TrimSpace(os.Getenv("A10_TEST_VIP_PORT")); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 65535 {
			t.Fatalf("invalid A10_TEST_VIP_PORT %q", value)
		}
		port = parsed
	}
	client, err := New(Config{
		Address: os.Getenv("A10_HOST"), Username: os.Getenv("A10_USERNAME"), Password: os.Getenv("A10_PASSWORD"),
		Partition: os.Getenv("A10_PARTITION"), InsecureSkipVerify: liveBool("A10_LIVE_INSECURE_SKIP_VERIFY"), Timeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	session, err := client.StartSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.VerifyCompatibility(ctx); err != nil {
		_ = session.Close(ctx)
		t.Fatal(err)
	}
	bindings, inventoryErr := session.FindClientSSLTemplatesByVIP(ctx, vip)
	if inventoryErr != nil {
		_ = session.Close(ctx)
		t.Fatal(inventoryErr)
	}
	var selected *VirtualServerTLSBinding
	for index := range bindings {
		if int(bindings[index].Port) == port {
			selected = &bindings[index]
			break
		}
	}
	if selected == nil {
		_ = session.Close(ctx)
		t.Fatalf("VIP %s:%d has no client-SSL template binding: %#v", vip, port, bindings)
	}
	state, stateErr := session.GetManagedCertificateState(ctx, ForClientSSLTemplate(selected.ClientSSLTemplate))
	closeErr := session.Close(ctx)
	if err := errors.Join(stateErr, closeErr); err != nil {
		t.Fatal(err)
	}
	if state.Certificate == nil {
		t.Fatalf("VIP template %q has no resolvable certificate", selected.ClientSSLTemplate)
	}
	dialer := tls.Dialer{Config: &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         strings.TrimSpace(os.Getenv("A10_TEST_VIP_SERVER_NAME")),
		InsecureSkipVerify: liveBool("A10_TEST_VIP_INSECURE_SKIP_VERIFY"), //nolint:gosec -- explicit lab acceptance option
	}}
	connection, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", vip, port))
	if err != nil {
		t.Fatal(err)
	}
	tlsConnection, ok := connection.(*tls.Conn)
	if !ok {
		_ = connection.Close()
		t.Fatal("VIP connection is not TLS")
	}
	connectionState := tlsConnection.ConnectionState()
	closeErr = tlsConnection.Close()
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	if len(connectionState.PeerCertificates) == 0 {
		t.Fatal("VIP returned no peer certificate")
	}
	servedSerial := strings.TrimLeft(strings.ToUpper(connectionState.PeerCertificates[0].SerialNumber.Text(16)), "0")
	inventorySerial := strings.TrimLeft(strings.TrimPrefix(strings.ToUpper(state.Certificate.Serial), "0X"), "0")
	if servedSerial != inventorySerial {
		t.Fatalf("VIP served serial %s, but template inventory reports %s", servedSerial, inventorySerial)
	}
	t.Logf("VIP %s:%d serves template %s certificate %s", vip, port, selected.ClientSSLTemplate, state.Certificate.Name)
}

func liveBool(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes":
		return true
	default:
		return false
	}
}

func joinErrors(values ...error) error {
	var messages []string
	for _, value := range values {
		if value != nil {
			messages = append(messages, value.Error())
		}
	}
	if len(messages) == 0 {
		return nil
	}
	return fmt.Errorf("%s", strings.Join(messages, "; "))
}
