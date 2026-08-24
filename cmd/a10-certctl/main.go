package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/vpgc/a10-certctl/pkg/a10"
)

type globalOptions struct {
	host               string
	username           string
	password           string
	partition          string
	insecure           bool
	allowInsecureHTTP  bool
	trustedCertificate string
	timeout            time.Duration
}

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	globals, command, rest, err := parseGlobals(args, stderr)
	if err != nil {
		return err
	}
	if command == "" || command == "help" || command == "-h" || command == "--help" {
		usage(stdout)
		return nil
	}
	if command == "build-info" {
		return printJSON(stdout, struct {
			Version string `json:"version"`
		}{Version: a10.BuildVersion()})
	}
	client, err := newClient(globals)
	if err != nil {
		return err
	}
	ctx := context.Background()

	switch command {
	case "version":
		return withSession(ctx, client, func(session *a10.Session) error {
			version, err := session.ACOSVersion(ctx)
			if err != nil {
				return err
			}
			return printJSON(stdout, version)
		})

	case "preflight":
		return withSession(ctx, client, func(session *a10.Session) error {
			version, err := session.VerifyCompatibility(ctx)
			if err != nil {
				return err
			}
			return printJSON(stdout, struct {
				Compatible bool            `json:"compatible"`
				Contract   string          `json:"contract"`
				TestedWith string          `json:"testedWith"`
				Version    a10.VersionInfo `json:"version"`
			}{true, "ACOS 6.x.y", a10.TestedACOSVersion, version})
		})

	case "list":
		return withSession(ctx, client, func(session *a10.Session) error {
			certificates, err := session.ListCertificates(ctx)
			if err != nil {
				return err
			}
			return printJSON(stdout, certificates)
		})

	case "templates":
		return withSession(ctx, client, func(session *a10.Session) error {
			templates, err := session.ListClientSSLTemplates(ctx)
			if err != nil {
				return err
			}
			return printJSON(stdout, templates)
		})

	case "vip":
		fs := flag.NewFlagSet(command, flag.ContinueOnError)
		fs.SetOutput(stderr)
		address := fs.String("address", "", "exact IPv4 or IPv6 virtual-server address")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		if strings.TrimSpace(*address) == "" {
			return errors.New("vip requires --address")
		}
		return withSession(ctx, client, func(session *a10.Session) error {
			bindings, err := session.FindClientSSLTemplatesByVIP(ctx, *address)
			if err != nil {
				return err
			}
			return printJSON(stdout, bindings)
		})

	case "status":
		fs := flag.NewFlagSet(command, flag.ContinueOnError)
		fs.SetOutput(stderr)
		template := fs.String("template", "", "client-SSL template name")
		current := fs.String("current-cert", "", "exact certificate slot for a multi-certificate template")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		target, err := parseTarget(*template, *current)
		if err != nil {
			return err
		}
		state, err := client.GetManagedCertificateState(ctx, target)
		if err != nil {
			return err
		}
		return printJSON(stdout, state)

	case "find-domain":
		fs := flag.NewFlagSet(command, flag.ContinueOnError)
		fs.SetOutput(stderr)
		domain := fs.String("domain", "", "DNS name to match against operational certificate common names")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		if strings.TrimSpace(*domain) == "" {
			return errors.New("find-domain requires --domain")
		}
		return withSession(ctx, client, func(session *a10.Session) error {
			certificates, err := session.ListCertificates(ctx)
			if err != nil {
				return err
			}
			var matches []a10.CertificateInfo
			for _, certificate := range certificates {
				if domainMatches(*domain, certificate.CommonName) {
					matches = append(matches, certificate)
				}
			}
			return printJSON(stdout, matches)
		})

	case "sync":
		fs := flag.NewFlagSet(command, flag.ContinueOnError)
		fs.SetOutput(stderr)
		template := fs.String("template", "", "client-SSL template name")
		current := fs.String("current-cert", "", "currently bound certificate name; required for templates with multiple certificate-list entries")
		namePrefix := fs.String("name", "", "managed certificate/key name prefix; defaults to the template name")
		certificateFile := fs.String("cert", "", "leaf certificate or full-chain PEM file")
		keyFile := fs.String("key", "", "private-key PEM file")
		passphraseEnv := fs.String("key-passphrase-env", "A10_KEY_PASSPHRASE", "environment variable containing the private-key passphrase")
		var chainFiles stringList
		fs.Var(&chainFiles, "chain", "additional CA-chain PEM file; may be repeated")
		exportableKey := fs.Bool("exportable-key", false, "allow the A10 private key to be exported")
		cleanupOld := fs.Bool("cleanup-old", false, "delete previous files after a complete reference scan")
		expectedRevisionValue := fs.String("expected-revision", "", "require the template revision returned by status")
		noWriteMemory := fs.Bool("no-write-memory", false, "do not persist the final running configuration")
		shared := fs.Bool("shared", false, "mark the client-SSL certificate binding as partition-shared")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		if *template == "" || *certificateFile == "" || *keyFile == "" {
			return errors.New("sync requires --template, --cert, and --key")
		}
		bundle, err := readBundle(*certificateFile, *keyFile, chainFiles, os.Getenv(*passphraseEnv))
		if err != nil {
			return err
		}
		target, err := parseTarget(*template, *current)
		if err != nil {
			return err
		}
		var expectedRevision a10.TemplateRevision
		if *expectedRevisionValue != "" {
			expectedRevision, err = a10.ParseTemplateRevision(*expectedRevisionValue)
			if err != nil {
				return err
			}
		}
		result, err := client.SyncCertificate(ctx, target, bundle, a10.SyncOptions{
			NamePrefix: *namePrefix, ExpectedRevision: expectedRevision,
			ExportableKey: *exportableKey, CleanupOld: *cleanupOld,
			NoWriteMemory: *noWriteMemory, Shared: *shared,
		})
		if err != nil {
			return err
		}
		return printJSON(stdout, result)

	case "import":
		fs := flag.NewFlagSet(command, flag.ContinueOnError)
		fs.SetOutput(stderr)
		name := fs.String("name", "", "A10 certificate and key file name")
		certificateFile := fs.String("cert", "", "leaf certificate or full-chain PEM file")
		keyFile := fs.String("key", "", "private-key PEM file")
		passphraseEnv := fs.String("key-passphrase-env", "A10_KEY_PASSPHRASE", "environment variable containing the private-key passphrase")
		var chainFiles stringList
		fs.Var(&chainFiles, "chain", "additional CA-chain PEM file; may be repeated")
		replace := fs.Bool("replace", false, "replace existing files with the same name")
		exportableKey := fs.Bool("exportable-key", false, "allow the A10 private key to be exported")
		noWriteMemory := fs.Bool("no-write-memory", false, "do not persist the running configuration")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		if *name == "" || *certificateFile == "" || *keyFile == "" {
			return errors.New("import requires --name, --cert, and --key")
		}
		bundle, err := readBundle(*certificateFile, *keyFile, chainFiles, os.Getenv(*passphraseEnv))
		if err != nil {
			return err
		}
		certificateName, err := a10.ParseCertificateFileName(*name)
		if err != nil {
			return err
		}
		keyName, err := a10.ParseKeyFileName(*name)
		if err != nil {
			return err
		}
		return withCompatibleSession(ctx, client, func(session *a10.Session) error {
			options := a10.UploadOptions{Replace: *replace, ExportableKey: *exportableKey}
			if err := session.UploadKey(ctx, keyName, bundle.Key.PEM(), options); err != nil {
				return err
			}
			if err := session.UploadCertificate(ctx, certificateName, bundle.Certificate.PEM(), options); err != nil {
				return err
			}
			var chainName a10.CertificateFileName
			if len(bundle.Chain) != 0 {
				chainName, err = a10.ParseCertificateFileName(*name + "-chain")
				if err != nil {
					return err
				}
				var chainPEM []byte
				for _, certificate := range bundle.Chain {
					chainPEM = append(chainPEM, certificate.PEM()...)
				}
				if err := session.UploadChain(ctx, chainName, chainPEM, options); err != nil {
					return err
				}
			}
			if !*noWriteMemory {
				if err := session.WriteMemory(ctx); err != nil {
					return err
				}
			}
			return printJSON(stdout, struct {
				Certificate a10.CertificateFileName `json:"certificate"`
				Key         a10.KeyFileName         `json:"key"`
				Chain       a10.CertificateFileName `json:"chain,omitempty"`
			}{Certificate: certificateName, Key: keyName, Chain: chainName})
		})

	case "bind":
		fs := flag.NewFlagSet(command, flag.ContinueOnError)
		fs.SetOutput(stderr)
		template := fs.String("template", "", "client-SSL template name")
		certificate := fs.String("cert", "", "installed certificate file name")
		key := fs.String("key", "", "installed key file name")
		chain := fs.String("chain", "", "optional installed CA-chain file name")
		passphraseEnv := fs.String("key-passphrase-env", "A10_KEY_PASSPHRASE", "environment variable containing the private-key passphrase")
		noWriteMemory := fs.Bool("no-write-memory", false, "do not persist the running configuration")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		if *template == "" || *certificate == "" || *key == "" {
			return errors.New("bind requires --template, --cert, and --key")
		}
		templateName, err := a10.ParseClientSSLTemplateName(*template)
		if err != nil {
			return err
		}
		certificateName, err := a10.ParseCertificateFileName(*certificate)
		if err != nil {
			return err
		}
		keyName, err := a10.ParseKeyFileName(*key)
		if err != nil {
			return err
		}
		var chainName a10.CertificateFileName
		if *chain != "" {
			chainName, err = a10.ParseCertificateFileName(*chain)
			if err != nil {
				return err
			}
		}
		return withCompatibleSession(ctx, client, func(session *a10.Session) error {
			binding := a10.CertificateBinding{Certificate: certificateName, Key: keyName, Chain: chainName}
			if err := session.BindCertificate(ctx, templateName, binding, []byte(os.Getenv(*passphraseEnv))); err != nil {
				return err
			}
			if !*noWriteMemory {
				return session.WriteMemory(ctx)
			}
			return nil
		})

	case "unbind":
		fs := flag.NewFlagSet(command, flag.ContinueOnError)
		fs.SetOutput(stderr)
		template := fs.String("template", "", "client-SSL template name")
		certificate := fs.String("cert", "", "bound certificate file name")
		noWriteMemory := fs.Bool("no-write-memory", false, "do not persist the running configuration")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		if *template == "" || *certificate == "" {
			return errors.New("unbind requires --template and --cert")
		}
		templateName, err := a10.ParseClientSSLTemplateName(*template)
		if err != nil {
			return err
		}
		certificateName, err := a10.ParseCertificateFileName(*certificate)
		if err != nil {
			return err
		}
		return withCompatibleSession(ctx, client, func(session *a10.Session) error {
			if err := session.UnbindCertificate(ctx, templateName, certificateName); err != nil {
				return err
			}
			if !*noWriteMemory {
				return session.WriteMemory(ctx)
			}
			return nil
		})

	case "delete":
		fs := flag.NewFlagSet(command, flag.ContinueOnError)
		fs.SetOutput(stderr)
		certificate := fs.String("cert", "", "unbound certificate file name")
		key := fs.String("key", "", "unbound key file name")
		chain := fs.String("chain", "", "unbound server certificate-chain file name")
		ca := fs.String("ca", "", "unbound CA trust-store file name")
		noWriteMemory := fs.Bool("no-write-memory", false, "do not persist the running configuration")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		certificateName, err := optionalCertificateFileName(*certificate)
		if err != nil {
			return err
		}
		keyName, err := optionalKeyFileName(*key)
		if err != nil {
			return err
		}
		chainName, err := optionalCertificateFileName(*chain)
		if err != nil {
			return err
		}
		caName, err := optionalCAFileName(*ca)
		if err != nil {
			return err
		}
		return withCompatibleSession(ctx, client, func(session *a10.Session) error {
			material := a10.MaterialNames{Certificate: certificateName, Key: keyName, CA: caName}
			if material != (a10.MaterialNames{}) {
				if err := session.DeleteMaterial(ctx, material); err != nil {
					return err
				}
			}
			if chainName != "" {
				if err := session.DeleteMaterial(ctx, a10.MaterialNames{Certificate: chainName}); err != nil {
					return err
				}
			}
			if material == (a10.MaterialNames{}) && *chain == "" {
				return errors.New("delete requires at least one of --cert, --key, --chain, or --ca")
			}
			if !*noWriteMemory {
				return session.WriteMemory(ctx)
			}
			return nil
		})

	case "write-memory":
		return withCompatibleSession(ctx, client, func(session *a10.Session) error {
			if err := session.WriteMemory(ctx); err != nil {
				return err
			}
			_, err := fmt.Fprintln(stdout, "saved")
			return err
		})

	default:
		usage(stderr)
		return fmt.Errorf("unknown command %q", command)
	}
}

func optionalCertificateFileName(value string) (a10.CertificateFileName, error) {
	if value == "" {
		return "", nil
	}
	return a10.ParseCertificateFileName(value)
}

func parseTarget(template, current string) (a10.CertificateTarget, error) {
	if strings.TrimSpace(template) == "" {
		return a10.CertificateTarget{}, errors.New("template name is required")
	}
	templateName, err := a10.ParseClientSSLTemplateName(template)
	if err != nil {
		return a10.CertificateTarget{}, err
	}
	if current == "" {
		return a10.ForClientSSLTemplate(templateName), nil
	}
	currentName, err := a10.ParseCertificateFileName(current)
	if err != nil {
		return a10.CertificateTarget{}, err
	}
	return a10.ForCertificateBinding(templateName, currentName), nil
}

func optionalKeyFileName(value string) (a10.KeyFileName, error) {
	if value == "" {
		return "", nil
	}
	return a10.ParseKeyFileName(value)
}

func optionalCAFileName(value string) (a10.CAFileName, error) {
	if value == "" {
		return "", nil
	}
	return a10.ParseCAFileName(value)
}

func parseGlobals(args []string, stderr io.Writer) (globalOptions, string, []string, error) {
	options := globalOptions{
		host: os.Getenv("A10_HOST"), username: os.Getenv("A10_USERNAME"),
		password: os.Getenv("A10_PASSWORD"), partition: os.Getenv("A10_PARTITION"),
		trustedCertificate: os.Getenv("A10_TRUSTED_CERTIFICATE"), timeout: 30 * time.Second,
	}
	if insecure := strings.ToLower(os.Getenv("A10_INSECURE_SKIP_VERIFY")); insecure == "1" || insecure == "true" || insecure == "yes" {
		options.insecure = true
	}
	if insecureHTTP := strings.ToLower(os.Getenv("A10_ALLOW_INSECURE_HTTP")); insecureHTTP == "1" || insecureHTTP == "true" || insecureHTTP == "yes" {
		options.allowInsecureHTTP = true
	}
	fs := flag.NewFlagSet("a10-certctl", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&options.host, "host", options.host, "A10 management host or URL; env A10_HOST")
	fs.StringVar(&options.username, "username", options.username, "A10 username; env A10_USERNAME")
	fs.StringVar(&options.password, "password", options.password, "A10 password; env A10_PASSWORD")
	fs.StringVar(&options.partition, "partition", options.partition, "optional ACOS partition; env A10_PARTITION")
	fs.BoolVar(&options.insecure, "insecure-skip-verify", options.insecure, "disable management TLS verification")
	fs.BoolVar(&options.allowInsecureHTTP, "allow-insecure-http", options.allowInsecureHTTP, "allow unencrypted HTTP management traffic")
	fs.StringVar(&options.trustedCertificate, "trusted-certificate", options.trustedCertificate, "management CA PEM file; env A10_TRUSTED_CERTIFICATE")
	fs.DurationVar(&options.timeout, "timeout", options.timeout, "HTTP timeout")
	if err := fs.Parse(args); err != nil {
		return options, "", nil, err
	}
	remaining := fs.Args()
	if len(remaining) == 0 {
		return options, "", nil, nil
	}
	return options, remaining[0], remaining[1:], nil
}

func newClient(options globalOptions) (*a10.Client, error) {
	return a10.New(a10.Config{
		Address: options.host, Username: options.username, Password: options.password,
		Partition: options.partition, Timeout: options.timeout,
		InsecureSkipVerify: options.insecure, AllowInsecureHTTP: options.allowInsecureHTTP,
		TrustedCertificate: options.trustedCertificate,
	})
}

func withSession(ctx context.Context, client *a10.Client, operation func(*a10.Session) error) (err error) {
	session, err := client.StartSession(ctx)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, session.Close(ctx)) }()
	return operation(session)
}

func withCompatibleSession(ctx context.Context, client *a10.Client, operation func(*a10.Session) error) error {
	return withSession(ctx, client, func(session *a10.Session) error {
		if _, err := session.VerifyCompatibility(ctx); err != nil {
			return err
		}
		return operation(session)
	})
}

func readBundle(certificateFile, keyFile string, chainFiles []string, passphrase string) (a10.CertificateBundle, error) {
	certificatePEM, err := os.ReadFile(certificateFile)
	if err != nil {
		return a10.CertificateBundle{}, fmt.Errorf("read certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return a10.CertificateBundle{}, fmt.Errorf("read private key: %w", err)
	}
	input := a10.CertificateBundleInput{
		CertificatePEM: certificatePEM, PrivateKeyPEM: keyPEM,
		PrivateKeyPassphrase: []byte(passphrase),
	}
	for _, filename := range chainFiles {
		chainPEM, err := os.ReadFile(filename)
		if err != nil {
			return a10.CertificateBundle{}, fmt.Errorf("read CA chain %q: %w", filename, err)
		}
		input.CertificateChainPEM = append(input.CertificateChainPEM, chainPEM)
	}
	return a10.ParseCertificateBundle(input)
}

func domainMatches(domain, commonName string) bool {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	commonName = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(commonName)), ".")
	if domain == commonName {
		return true
	}
	if !strings.HasPrefix(commonName, "*.") || net.ParseIP(domain) != nil {
		return false
	}
	suffix := strings.TrimPrefix(commonName, "*")
	return strings.HasSuffix(domain, suffix) && strings.Count(domain, ".") == strings.Count(commonName, ".")
}

func printJSON(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func usage(writer io.Writer) {
	_, _ = fmt.Fprintln(writer, `Usage:
  a10-certctl [global options] <command> [command options]

Global options:
  --host URL                    A10 management address (A10_HOST)
  --username USER               aXAPI username (A10_USERNAME)
  --password PASSWORD           aXAPI password (A10_PASSWORD)
  --partition NAME              optional ACOS partition (A10_PARTITION)
  --insecure-skip-verify        allow a self-signed lab management certificate
  --allow-insecure-http         allow unencrypted HTTP management traffic
  --trusted-certificate FILE    trust a management CA PEM file
  --timeout DURATION            HTTP timeout (default 30s)

Commands:
  build-info                    show a10-certctl build version
	  version                       show ACOS/aXAPI version
	  preflight                     verify the ACOS 6.x.y compatibility contract
  list                          list operational certificate metadata
	  templates                     list client-SSL templates and bindings
	  vip --address IP              resolve client-SSL templates served by a VIP
  status --template NAME [--current-cert NAME]
                                read one logical slot and its revision
  find-domain --domain NAME     match certificate common names
  sync --template NAME --cert FILE --key FILE [--chain FILE]
                                safely rotate a template certificate pair
  import --name NAME --cert FILE --key FILE [--chain FILE]
                                import a validated pair without binding it
  bind --template NAME --cert NAME --key NAME [--chain NAME]
  unbind --template NAME --cert NAME
		delete [--cert NAME] [--key NAME] [--chain NAME] [--ca NAME]
  write-memory                  persist the running configuration

Use environment variables for passwords in automation. Private-key PEM and
passphrases are never printed by this CLI.`)
}
