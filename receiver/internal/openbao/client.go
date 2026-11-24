package openbao

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// ErrInvalidToken means OpenBao explicitly reported that the token is invalid, expired, or missing.
// Any other error (permission denied, timeout, 5xx, sealed server) leaves the token's state
// unconfirmed, and callers must verify before treating it as revoked.
var ErrInvalidToken = errors.New("OpenBao rejected the token as invalid or expired")

// ErrPermissionDenied means OpenBao answered HTTP 403 without explicitly identifying the token as
// bad/expired. A live token whose policy lacks `auth/token/revoke-self` also produces HTTP 403
// "permission denied", so callers must NOT treat ErrPermissionDenied alone as a confirmed revocation.
var ErrPermissionDenied = errors.New("OpenBao denied permission for this operation")

// TokenInfo represents verified metadata returned by `/v1/auth/token/lookup-self`.
type TokenInfo struct {
	TTLSeconds                int                 `json:"ttl"`
	Policies                  []string            `json:"policies"`
	IdentityPolicies          []string            `json:"identity_policies"`
	ExternalNamespacePolicies map[string][]string `json:"external_namespace_policies"`
	DisplayName               string              `json:"display_name"`
	Orphan                    bool                `json:"orphan"`
	Renewable                 bool                `json:"renewable"`
	Type                      string              `json:"type"`
	ExpireTime                string              `json:"expire_time"`
	Meta                      map[string]string   `json:"meta"`
}

// Client is a minimal, stdlib-only OpenBao / HashiCorp Vault HTTP client.
type Client struct {
	baseURL    string
	namespace  string
	httpClient *http.Client
}

// NewClient creates a Client. When caCertPath is set, the certificates in it replace the system
// roots: the server must chain to one of them (a self-signed server certificate can be listed
// directly), and the hostname is still verified.
func NewClient(baseURL, namespace, caCertPath string, timeout time.Duration) (*Client, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if strings.TrimSpace(caCertPath) != "" {
		pemBytes, err := os.ReadFile(caCertPath)
		if err != nil {
			return nil, fmt.Errorf("read ca_cert_path %s: %w", caCertPath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("no PEM certificate found in %s", caCertPath)
		}
		tlsCfg.RootCAs = pool
	}

	transport := &http.Transport{
		TLSClientConfig:     tlsCfg,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        4,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 8 * time.Second,
	}

	return &Client{
		baseURL:   strings.TrimRight(baseURL, "/"),
		namespace: strings.TrimSpace(namespace),
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   timeout,
			// Go forwards X-Vault-Token on redirects (it strips only Authorization and Cookie),
			// so a redirect from a standby node or proxy could send the grant elsewhere.
			// Never follow one.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// CheckHealth queries `/v1/sys/health` at root to verify network and TLS trust.
func (c *Client) CheckHealth(ctx context.Context) (version string, sealed bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/sys/health", nil)
	if err != nil {
		return "", false, errors.New("invalid OpenBao health request")
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", false, requestError(err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusTooManyRequests, 473:
		return "", false, fmt.Errorf("OpenBao is on standby (HTTP %d)", resp.StatusCode)
	case http.StatusNotImplemented:
		return "", false, errors.New("OpenBao is uninitialized (HTTP 501)")
	case http.StatusServiceUnavailable:
		return "", false, errors.New("OpenBao is sealed or unavailable (HTTP 503)")
	default:
		return "", false, fmt.Errorf("OpenBao health check returned HTTP %d", resp.StatusCode)
	}
	body, err := readResponseBody(resp.Body)
	if err != nil {
		return "", false, err
	}
	var health struct {
		Version     string `json:"version"`
		Initialized *bool  `json:"initialized"`
		Sealed      *bool  `json:"sealed"`
		Standby     *bool  `json:"standby"`
	}
	if json.Unmarshal(body, &health) != nil || strings.TrimSpace(health.Version) == "" ||
		health.Initialized == nil || health.Sealed == nil || health.Standby == nil {
		return "", false, errors.New("invalid or incomplete OpenBao health response")
	}
	if !*health.Initialized {
		return "", false, errors.New("OpenBao is uninitialized")
	}
	if *health.Standby && !*health.Sealed {
		return "", false, errors.New("OpenBao is on standby")
	}
	return health.Version, *health.Sealed, nil
}

// LookupSelf validates a token against OpenBao and returns its authoritative TTL, policies, and metadata.
func (c *Client) LookupSelf(ctx context.Context, token string) (TokenInfo, error) {
	resp, body, err := c.do(ctx, http.MethodGet, "/v1/auth/token/lookup-self", token, nil)
	if err != nil {
		return TokenInfo{}, err
	}
	if err := statusError("lookup-self", resp.StatusCode, body); err != nil {
		return TokenInfo{}, err
	}
	var envelope struct {
		Data *struct {
			TTLSeconds                *int                `json:"ttl"`
			Policies                  []string            `json:"policies"`
			IdentityPolicies          []string            `json:"identity_policies"`
			ExternalNamespacePolicies map[string][]string `json:"external_namespace_policies"`
			DisplayName               string              `json:"display_name"`
			Orphan                    bool                `json:"orphan"`
			Renewable                 bool                `json:"renewable"`
			Type                      string              `json:"type"`
			ExpireTime                string              `json:"expire_time"`
			Meta                      map[string]string   `json:"meta"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return TokenInfo{}, fmt.Errorf("decode lookup-self: %w", err)
	}
	if envelope.Data == nil || envelope.Data.TTLSeconds == nil {
		return TokenInfo{}, fmt.Errorf("decode lookup-self: response missing required data or ttl field")
	}
	if *envelope.Data.TTLSeconds < 0 {
		return TokenInfo{}, fmt.Errorf("decode lookup-self: invalid negative ttl %d", *envelope.Data.TTLSeconds)
	}
	return TokenInfo{
		TTLSeconds:                *envelope.Data.TTLSeconds,
		Policies:                  envelope.Data.Policies,
		IdentityPolicies:          envelope.Data.IdentityPolicies,
		ExternalNamespacePolicies: envelope.Data.ExternalNamespacePolicies,
		DisplayName:               envelope.Data.DisplayName,
		Orphan:                    envelope.Data.Orphan,
		Renewable:                 envelope.Data.Renewable,
		Type:                      envelope.Data.Type,
		ExpireTime:                envelope.Data.ExpireTime,
		Meta:                      envelope.Data.Meta,
	}, nil
}

// RevokeSelf asks OpenBao to revoke the provided token. A token OpenBao already considers
// invalid returns ErrInvalidToken, which callers can treat as "already revoked".
func (c *Client) RevokeSelf(ctx context.Context, token string) error {
	resp, body, err := c.do(ctx, http.MethodPost, "/v1/auth/token/revoke-self", token, []byte("{}"))
	if err != nil {
		return err
	}
	return statusError("revoke-self", resp.StatusCode, body)
}

func (c *Client) do(ctx context.Context, method, path, token string, payload []byte) (*http.Response, []byte, error) {
	var reader io.Reader
	if payload != nil {
		reader = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return nil, nil, errors.New("invalid OpenBao request URL")
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-Vault-Token", token)
	if c.namespace != "" {
		req.Header.Set("X-Vault-Namespace", c.namespace)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, requestError(err)
	}
	defer resp.Body.Close()
	body, err := readResponseBody(resp.Body)
	return resp, body, err
}

func readResponseBody(body io.Reader) ([]byte, error) {
	const limit = 64 * 1024
	data, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil || len(data) > limit {
		return nil, errors.New("could not read a complete OpenBao response within 64 KiB")
	}
	return data, nil
}

// Transport errors can include the full URL, including a private proxy path.
func requestError(err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	default:
		return errors.New("OpenBao request failed; check connectivity and TLS settings")
	}
}

// statusError maps a response status to an error. Bodies are summarized, never echoed whole.
func statusError(op string, status int, body []byte) error {
	if status >= 200 && status < 300 {
		return nil
	}
	if isInvalidTokenResponse(status, body) {
		return fmt.Errorf("%s: %w", op, ErrInvalidToken)
	}
	if status == http.StatusForbidden {
		return fmt.Errorf("%s: %w (%s)", op, ErrPermissionDenied, summarize(body))
	}
	if status >= 300 && status < 400 {
		return fmt.Errorf("%s: OpenBao answered with a redirect (HTTP %d), which isn't followed; point openbao_addr at the active node", op, status)
	}
	return fmt.Errorf("%s: HTTP %d: %s", op, status, summarize(body))
}

func isInvalidTokenResponse(status int, body []byte) bool {
	if status != http.StatusBadRequest && status != http.StatusForbidden {
		return false
	}
	var parsed struct {
		Errors []string `json:"errors"`
	}
	if json.Unmarshal(body, &parsed) != nil || len(parsed.Errors) == 0 {
		return false
	}
	for _, raw := range parsed.Errors {
		for _, line := range strings.Split(raw, "\n") {
			entry := strings.ToLower(strings.TrimSpace(line))
			entry = strings.TrimSpace(strings.TrimPrefix(entry, "*"))
			switch entry {
			case "bad token", "invalid token", "token is expired", "expired token", "token not found":
				return true
			}
		}
	}
	return false
}

func summarize(body []byte) string {
	var parsed struct {
		Errors []string `json:"errors"`
	}
	if json.Unmarshal(body, &parsed) == nil && len(parsed.Errors) > 0 {
		msg := strings.Join(parsed.Errors, "; ")
		if len(msg) > 200 {
			msg = msg[:200] + "…"
		}
		return msg
	}
	return "unexpected response"
}
