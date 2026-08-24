package a10

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// version is replaced by the release build. Development builds report "dev".
var version = "dev"

// BuildVersion returns the semantic release version embedded at build time.
func BuildVersion() string { return version }

func defaultUserAgent() string { return "a10-certctl/" + BuildVersion() }

// Config contains ACOS aXAPI connection and authentication settings.
type Config struct {
	// Address is the ACOS management hostname or URL.
	Address string `json:"address"`
	// Username is the aXAPI account name.
	Username string `json:"username"`
	// Password is the aXAPI password and is excluded from JSON.
	Password string `json:"-"`
	// Partition selects an optional ACOS partition after login.
	Partition string `json:"partition,omitempty"`
	// Timeout limits a complete HTTP request; zero uses 30 seconds.
	Timeout time.Duration `json:"timeout,omitempty"`
	// InsecureSkipVerify disables management TLS verification for labs.
	InsecureSkipVerify bool `json:"insecureSkipVerify,omitempty"`
	// AllowInsecureHTTP explicitly permits a plain HTTP management URL.
	AllowInsecureHTTP bool `json:"allowInsecureHTTP,omitempty"`
	// TrustedCertificate is management CA PEM text or a PEM file path.
	TrustedCertificate string `json:"trustedCertificate,omitempty"`
	// HTTPClient replaces the default client and is excluded from JSON.
	HTTPClient *http.Client `json:"-"`
	// UserAgent overrides the versioned default User-Agent.
	UserAgent string `json:"userAgent,omitempty"`
}

// Client is an authenticated-session factory. It is safe for concurrent use;
// each operation can create an independent aXAPI signature with StartSession.
type Client struct {
	baseURL   *url.URL
	username  string
	password  string
	partition string
	http      *http.Client
	userAgent string
	managedMu sync.Mutex
}

// New creates an ACOS aXAPI client from Config.
func New(config Config) (*Client, error) {
	if strings.TrimSpace(config.Username) == "" {
		return nil, errors.New("missing A10 username")
	}
	if config.Password == "" {
		return nil, errors.New("missing A10 password")
	}
	baseURL, err := configuredAddress(config.Address, config.AllowInsecureHTTP || config.HTTPClient != nil)
	if err != nil {
		return nil, err
	}
	httpClient, err := configuredHTTPClient(config)
	if err != nil {
		return nil, err
	}
	userAgent := strings.TrimSpace(config.UserAgent)
	if userAgent == "" {
		userAgent = defaultUserAgent()
	}
	return &Client{
		baseURL:   baseURL,
		username:  config.Username,
		password:  config.Password,
		partition: strings.TrimSpace(config.Partition),
		http:      httpClient,
		userAgent: userAgent,
	}, nil
}

func configuredAddress(address string, allowInsecureHTTP bool) (*url.URL, error) {
	raw := strings.TrimSpace(address)
	if raw == "" {
		return nil, errors.New("missing A10 address")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return nil, errors.New("invalid A10 address")
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return nil, errors.New("A10 address scheme must be http or https")
	}
	if parsed.Scheme == "http" && !allowInsecureHTTP {
		return nil, errors.New("A10 address must use https; plain HTTP is allowed only with an explicitly supplied HTTPClient")
	}
	if parsed.User != nil {
		return nil, errors.New("A10 address must not contain credentials")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("A10 address must not contain a query or fragment")
	}
	cleaned := strings.TrimSuffix(parsed.Path, "/")
	if !strings.HasSuffix(cleaned, "/axapi/v3") {
		cleaned += "/axapi/v3"
	}
	parsed.Path = cleaned
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed, nil
}

func configuredHTTPClient(config Config) (*http.Client, error) {
	if config.InsecureSkipVerify && config.TrustedCertificate != "" {
		return nil, errors.New("insecure TLS verification cannot be combined with a trusted certificate")
	}
	if config.Timeout < 0 {
		return nil, errors.New("A10 HTTP timeout must not be negative")
	}
	if config.HTTPClient != nil {
		if config.InsecureSkipVerify || config.TrustedCertificate != "" || config.Timeout > 0 {
			return nil, errors.New("HTTPClient cannot be combined with timeout or TLS transport options")
		}
		return config.HTTPClient, nil
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if config.InsecureSkipVerify {
		// The option is explicit and is intended for self-signed lab appliances.
		tlsConfig.InsecureSkipVerify = true //nolint:gosec
	}
	if config.TrustedCertificate != "" {
		certificatePEM, err := os.ReadFile(config.TrustedCertificate)
		if err != nil {
			return nil, fmt.Errorf("read trusted certificate: %w", err)
		}
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(certificatePEM) {
			return nil, errors.New("trusted certificate file contains no valid PEM certificates")
		}
		tlsConfig.RootCAs = roots
	}
	timeout := config.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			TLSClientConfig:       tlsConfig,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          20,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: time.Second,
		},
	}, nil
}

// Session owns one aXAPI authentication signature. lifecycle prevents logoff
// from racing an in-flight request; it is not an appliance configuration lock
// or transaction. Multiple read requests may execute concurrently.
type Session struct {
	client    *Client
	token     string
	lifecycle sync.RWMutex
	managedMu sync.Mutex
	closed    bool
}

type authRequest struct {
	Credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	} `json:"credentials"`
}

type authResponse struct {
	AuthResponse struct {
		Signature string `json:"signature"`
	} `json:"authresponse"`
}

type activePartitionDocument struct {
	Partition struct {
		Name string `json:"curr_part_name"`
	} `json:"active-partition"`
}

// StartSession authenticates and optionally selects a configured partition.
func (c *Client) StartSession(ctx context.Context) (*Session, error) {
	if ctx == nil {
		return nil, errors.New("context must not be nil")
	}
	var request authRequest
	request.Credentials.Username = c.username
	request.Credentials.Password = c.password
	var response authResponse
	if err := c.doJSON(ctx, "", http.MethodPost, "/auth", request, &response, http.StatusOK); err != nil {
		return nil, fmt.Errorf("authenticate to A10: %w", err)
	}
	if strings.TrimSpace(response.AuthResponse.Signature) == "" {
		return nil, errors.New("A10 authentication response did not contain a signature")
	}
	session := &Session{client: c, token: response.AuthResponse.Signature}
	if c.partition != "" {
		body := activePartitionDocument{}
		body.Partition.Name = c.partition
		if err := session.doJSON(ctx, http.MethodPost, "/active-partition", body, nil, http.StatusOK, http.StatusCreated, http.StatusNoContent); err != nil {
			_ = session.Close(context.Background())
			return nil, fmt.Errorf("select A10 partition %q: %w", c.partition, err)
		}
	}
	return session, nil
}

// Close invalidates the aXAPI signature. It is safe to call more than once.
func (s *Session) Close(ctx context.Context) error {
	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()
	if s.closed {
		return nil
	}
	if ctx == nil || ctx.Err() != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
	}
	err := s.client.doJSON(ctx, s.token, http.MethodPost, "/logoff", struct{}{}, nil, http.StatusOK, http.StatusNoContent)
	s.closed = true
	s.token = ""
	return err
}

// Raw returns the explicitly scoped escape hatch for aXAPI resources outside
// the typed certificate API. Prefer the typed Session methods when available.
func (s *Session) Raw() RawSession { return RawSession{session: s} }

// RawSession performs authenticated, untyped aXAPI operations. It cannot be
// constructed independently from an authenticated Session.
type RawSession struct{ session *Session }

// DoJSON performs an authenticated JSON aXAPI request.
func (raw RawSession) DoJSON(ctx context.Context, method, endpoint string, request, response any, acceptedStatus ...int) error {
	if raw.session == nil {
		return errors.New("A10 raw session is nil")
	}
	return raw.session.doJSON(ctx, method, endpoint, request, response, acceptedStatus...)
}

func (s *Session) doJSON(ctx context.Context, method, endpoint string, request, response any, acceptedStatus ...int) error {
	if ctx == nil {
		return errors.New("context must not be nil")
	}
	s.lifecycle.RLock()
	defer s.lifecycle.RUnlock()
	if s.closed {
		return errors.New("A10 session is closed")
	}
	return s.client.doJSON(ctx, s.token, method, endpoint, request, response, acceptedStatus...)
}

func (c *Client) doJSON(ctx context.Context, token, method, endpoint string, request, response any, acceptedStatus ...int) error {
	if ctx == nil {
		return errors.New("context must not be nil")
	}
	var body io.Reader
	if request != nil {
		encoded, err := json.Marshal(request)
		if err != nil {
			return fmt.Errorf("encode aXAPI request: %w", err)
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.endpoint(endpoint), body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	if token != "" {
		req.Header.Set("Authorization", "A10 "+token)
	}
	return c.execute(req, response, acceptedStatus...)
}

func (s *Session) doMultipart(ctx context.Context, endpoint string, metadata any, filename string, content []byte, acceptedStatus ...int) error {
	if ctx == nil {
		return errors.New("context must not be nil")
	}
	if err := validateFileName(filename); err != nil {
		return err
	}
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("encode multipart metadata: %w", err)
	}
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	jsonPart, err := writer.CreateFormFile("json", "blob")
	if err != nil {
		return err
	}
	if _, err := jsonPart.Write(metadataJSON); err != nil {
		return err
	}
	filePart, err := writer.CreateFormFile("file", filename)
	if err != nil {
		return err
	}
	if _, err := filePart.Write(content); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	s.lifecycle.RLock()
	defer s.lifecycle.RUnlock()
	if s.closed {
		return errors.New("A10 session is closed")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.client.endpoint(endpoint), &body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "A10 "+s.token)
	req.Header.Set("User-Agent", s.client.userAgent)
	return s.client.execute(req, nil, acceptedStatus...)
}

func (c *Client) execute(request *http.Request, response any, acceptedStatus ...int) error {
	result, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("%s %s: %w", request.Method, request.URL.Path, err)
	}
	defer result.Body.Close()
	body, err := io.ReadAll(io.LimitReader(result.Body, 32<<20))
	if err != nil {
		return fmt.Errorf("read aXAPI response: %w", err)
	}
	if !containsStatus(acceptedStatus, result.StatusCode) {
		return newAPIError(request.Method, request.URL.Path, result.StatusCode, body)
	}
	if response != nil && len(bytes.TrimSpace(body)) != 0 {
		if err := json.Unmarshal(body, response); err != nil {
			return fmt.Errorf("decode %s %s response: %w", request.Method, request.URL.Path, err)
		}
	}
	return nil
}

func containsStatus(values []int, value int) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func (c *Client) endpoint(relative string) string {
	copyURL := *c.baseURL
	requestPath, rawQuery, _ := strings.Cut(relative, "?")
	copyURL.Path = strings.TrimSuffix(c.baseURL.Path, "/") + "/" + strings.TrimPrefix(requestPath, "/")
	copyURL.RawQuery = rawQuery
	return copyURL.String()
}

// APIError contains the structured error returned by ACOS.
type APIError struct {
	Method   string
	Path     string
	Status   int
	Code     int64
	Message  string
	Location string
}

func (e *APIError) Error() string {
	// Appliance messages can reflect request values (including passphrases).
	// Keep Message available for explicit inspection, but never include it in
	// the ordinary error string used by logs and CLI output.
	detail := http.StatusText(e.Status)
	if detail == "" {
		detail = "aXAPI request failed"
	}
	if e.Code != 0 {
		detail += fmt.Sprintf(" (aXAPI code %d)", e.Code)
	}
	return fmt.Sprintf("%s %s: HTTP %d: %s", e.Method, e.Path, e.Status, detail)
}

// Is maps HTTP status codes to the package's stable error categories.
func (e *APIError) Is(target error) bool {
	switch target {
	case ErrAuthentication:
		return e.Status == http.StatusUnauthorized || e.Status == http.StatusForbidden
	case ErrNotFound:
		return e.Status == http.StatusNotFound
	case ErrConflict:
		return e.Status == http.StatusConflict
	default:
		return false
	}
}

func newAPIError(method, requestPath string, status int, body []byte) error {
	var document struct {
		Response struct {
			Error struct {
				Code     int64  `json:"code"`
				Message  string `json:"msg"`
				Location string `json:"location"`
			} `json:"err"`
			Message string `json:"msg"`
		} `json:"response"`
	}
	_ = json.Unmarshal(body, &document)
	message := document.Response.Error.Message
	if message == "" {
		message = document.Response.Message
	}
	return &APIError{
		Method: method, Path: requestPath, Status: status,
		Code: document.Response.Error.Code, Message: message, Location: document.Response.Error.Location,
	}
}
