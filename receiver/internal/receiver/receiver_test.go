package receiver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/northcutted/baobuddy/receiver/internal/config"
	"github.com/northcutted/baobuddy/receiver/internal/openbao"
	"github.com/northcutted/baobuddy/receiver/internal/otel"
)

type fakeOpenBao struct {
	mu      sync.Mutex
	tokens  map[string]openbao.TokenInfo
	revoked []string
}

func (f *fakeOpenBao) CheckHealth(ctx context.Context) (string, bool, error) {
	return "2.7.2", false, nil
}

func (f *fakeOpenBao) LookupSelf(ctx context.Context, token string) (openbao.TokenInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	info, ok := f.tokens[token]
	if !ok {
		return openbao.TokenInfo{}, openbao.ErrInvalidToken
	}
	return info, nil
}

func (f *fakeOpenBao) RevokeSelf(ctx context.Context, token string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.tokens, token)
	f.revoked = append(f.revoked, token)
	return nil
}

func TestInstallStatusRevokeAndOTLP(t *testing.T) {
	tmp := t.TempDir()
	var otlpPaths []string
	var otlpMu sync.Mutex
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		otlpMu.Lock()
		otlpPaths = append(otlpPaths, r.URL.Path)
		otlpMu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := config.Config{
		OpenBaoAddr:     "https://vault.example:8200",
		Namespace:       "admin/prod",
		StateDir:        filepath.Join(tmp, "state"),
		OTLPEndpoint:    ts.URL,
		AuditLogPath:    filepath.Join(tmp, "audit.jsonl"),
		MetricsFilePath: filepath.Join(tmp, "baobuddy.prom"),
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config validate: %v", err)
	}

	fake := &fakeOpenBao{
		tokens: map[string]openbao.TokenInfo{
			"s.validtoken123": {
				TTLSeconds: 3600,
				Policies:   []string{"default", "db-readonly"},
				Orphan:     true,
				Renewable:  false,
				Meta:       map[string]string{"by": "alice", "via": "mac", "why": "CHG-100"},
			},
		},
	}

	exp := otel.NewExporter(cfg.OTLPEndpoint, nil, cfg.ServiceName, cfg.AuditLogPath, cfg.MetricsFilePath)
	rcv := New(cfg, fake, exp)
	rcv.Now = func() time.Time { return time.Unix(1_800_000_000, 0).UTC() }

	msg, err := rcv.Install(context.Background(), strings.NewReader("s.validtoken123\n\n\n"))
	if err != nil {
		t.Fatalf("install failed: %v", err)
	}
	if !strings.HasPrefix(msg, "Granted until ") || !strings.Contains(msg, "db-readonly") {
		t.Fatalf("unexpected install message: %q", msg)
	}

	status, err := rcv.Status(context.Background())
	if err != nil {
		t.Fatalf("status failed: %v", err)
	}
	if !strings.Contains(status, "Secrets: active") || !strings.Contains(status, "CHG-100") {
		t.Fatalf("unexpected status: %q", status)
	}

	prom, err := os.ReadFile(cfg.MetricsFilePath)
	if err != nil {
		t.Fatalf("read prom metrics: %v", err)
	}
	if !strings.Contains(string(prom), "baobuddy_receiver_grant_active 1") {
		t.Fatalf("unexpected prom output: %s", string(prom))
	}

	// Revoke must revoke in OpenBao and remove local files.
	revMsg, err := rcv.Revoke(context.Background())
	if err != nil {
		t.Fatalf("revoke failed: %v", err)
	}
	if !strings.Contains(revMsg, "Revoked") {
		t.Fatalf("unexpected revoke message: %q", revMsg)
	}
	if _, err := os.Stat(cfg.TokenPath); !os.IsNotExist(err) {
		t.Fatalf("expected token file deleted after revoke")
	}

	// Verify OTLP logs and metrics were emitted.
	otlpMu.Lock()
	gotPaths := append([]string(nil), otlpPaths...)
	otlpMu.Unlock()
	if len(gotPaths) < 4 {
		t.Fatalf("expected OTLP logs + metrics for install and revoke, got %v", gotPaths)
	}

	// Verify JSONL audit log has valid JSON lines and never records the raw token.
	auditRaw, err := os.ReadFile(cfg.AuditLogPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if strings.Contains(string(auditRaw), "s.validtoken123") {
		t.Fatalf("audit log leaked raw token!")
	}
	for _, line := range strings.Split(strings.TrimSpace(string(auditRaw)), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("invalid audit JSON line %q: %v", line, err)
		}
	}
}

func TestInstallRejectsRenewableOrNonOrphanToken(t *testing.T) {
	cfg := config.Config{
		OpenBaoAddr: "https://vault.example:8200",
		StateDir:    t.TempDir(),
	}
	cfg.ApplyDefaults()

	fake := &fakeOpenBao{
		tokens: map[string]openbao.TokenInfo{
			"s.renewable": {TTLSeconds: 600, Policies: []string{"read"}, Orphan: true, Renewable: true},
			"s.child":     {TTLSeconds: 600, Policies: []string{"read"}, Orphan: false, Renewable: false},
		},
	}
	rcv := New(cfg, fake, nil)

	if _, err := rcv.Install(context.Background(), strings.NewReader("s.renewable\n\n\n")); err == nil {
		t.Fatalf("expected renewable token to be rejected")
	}
	if _, err := rcv.Install(context.Background(), strings.NewReader("s.child\n\n\n")); err == nil {
		t.Fatalf("expected non-orphan token to be rejected")
	}
}

func TestInstallV2JSONArtifactsAndPathTraversalRejection(t *testing.T) {
	cfg := config.Config{
		OpenBaoAddr: "https://vault.example:8200",
		StateDir:    t.TempDir(),
	}
	cfg.ApplyDefaults()

	fake := &fakeOpenBao{
		tokens: map[string]openbao.TokenInfo{
			"s.v2token": {TTLSeconds: 1800, Policies: []string{"deploy"}, Orphan: true, Renewable: false},
		},
	}
	rcv := New(cfg, fake, nil)

	// Path traversal in artifact filename must be rejected.
	badPayload := `{"version":2,"token":"s.v2token","artifacts":[{"name":"../escape","content":"nope"}]}`
	if _, err := rcv.Install(context.Background(), strings.NewReader(badPayload)); err == nil {
		t.Fatalf("expected unsafe artifact filename to be rejected")
	}

	// Valid v2 JSON envelope writes named artifacts and cleans them up on revoke.
	goodPayload := `{"version":2,"token":"s.v2token","artifacts":[{"name":"aws-creds.json","content":"{\"access_key\":\"ASIA123\"}"}]}`
	msg, err := rcv.Install(context.Background(), strings.NewReader(goodPayload))
	if err != nil {
		t.Fatalf("v2 install failed: %v", err)
	}
	if !strings.HasPrefix(msg, "Granted until ") {
		t.Fatalf("unexpected v2 install output: %q", msg)
	}

	artifactPath := filepath.Join(cfg.StateDir, "artifacts", "aws-creds.json")
	got, err := os.ReadFile(artifactPath)
	if err != nil {
		t.Fatalf("expected artifact written at %s: %v", artifactPath, err)
	}
	if !strings.Contains(string(got), "ASIA123") {
		t.Fatalf("unexpected artifact content: %s", string(got))
	}

	if _, err := rcv.Revoke(context.Background()); err != nil {
		t.Fatalf("revoke failed: %v", err)
	}
	if _, err := os.Stat(artifactPath); !os.IsNotExist(err) {
		t.Fatalf("expected artifact deleted on revoke")
	}
}

type flakyOpenBao struct {
	fakeOpenBao
	down bool
}

func (f *flakyOpenBao) LookupSelf(ctx context.Context, token string) (openbao.TokenInfo, error) {
	if f.down {
		return openbao.TokenInfo{}, errors.New("dial tcp: connection refused")
	}
	return f.fakeOpenBao.LookupSelf(ctx, token)
}

func (f *flakyOpenBao) RevokeSelf(ctx context.Context, token string) error {
	if f.down {
		return errors.New("dial tcp: connection refused")
	}
	return f.fakeOpenBao.RevokeSelf(ctx, token)
}

func newTestReceiver(t *testing.T, client OpenBaoClient, mutate func(*config.Config)) (*Receiver, config.Config) {
	t.Helper()
	cfg := config.Config{OpenBaoAddr: "https://vault.example:8200", StateDir: t.TempDir()}
	if mutate != nil {
		mutate(&cfg)
	}
	cfg.ApplyDefaults()
	return New(cfg, client, nil), cfg
}

func goodToken() openbao.TokenInfo {
	return openbao.TokenInfo{TTLSeconds: 600, Policies: []string{"read"}, Orphan: true, Type: "service", Meta: map[string]string{"on": "remote"}}
}

func TestOutageNeitherDeletesNorFakesRevocation(t *testing.T) {
	fake := &flakyOpenBao{fakeOpenBao: fakeOpenBao{tokens: map[string]openbao.TokenInfo{"s.live": goodToken()}}}
	rcv, cfg := newTestReceiver(t, fake, nil)
	if _, err := rcv.Install(context.Background(), strings.NewReader("s.live\n\n\n")); err != nil {
		t.Fatal(err)
	}
	fake.down = true
	status, err := rcv.Status(context.Background())
	if err != nil || !strings.Contains(status, "Secrets: unknown") {
		t.Fatalf("status during outage: %q %v", status, err)
	}
	if _, err := os.Stat(cfg.TokenPath); err != nil {
		t.Fatal("status during an outage must not delete the token")
	}
	if _, err := rcv.Revoke(context.Background()); err == nil || !strings.Contains(err.Error(), "NOT revoked") {
		t.Fatalf("revoke during outage must fail loudly, got %v", err)
	}
	if _, err := os.Stat(cfg.TokenPath); err != nil {
		t.Fatal("failed revoke must keep the token file for a retry")
	}
	fake.down = false
	if _, err := rcv.Revoke(context.Background()); err != nil {
		t.Fatalf("retry revoke: %v", err)
	}
	if _, err := os.Stat(cfg.TokenPath); !os.IsNotExist(err) {
		t.Fatal("token file should be gone after a confirmed revoke")
	}
}

func TestExpiredArtifactsAreSwept(t *testing.T) {
	fake := &fakeOpenBao{tokens: map[string]openbao.TokenInfo{"s.t": goodToken()}}
	rcv, cfg := newTestReceiver(t, fake, nil)
	now := time.Unix(1_800_000_000, 0)
	rcv.Now = func() time.Time { return now }
	payload := `{"version":2,"token":"s.t","artifacts":[{"name":"short","content":"x","expires_at":1800000060},{"name":"long","content":"y"}]}`
	if _, err := rcv.Install(context.Background(), strings.NewReader(payload)); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	if err := rcv.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(cfg.StateDir, "artifacts", "short")); !os.IsNotExist(err) {
		t.Fatal("expired artifact should be removed")
	}
	if _, err := os.Stat(filepath.Join(cfg.StateDir, "artifacts", "long")); err != nil {
		t.Fatal("unexpired artifact should stay")
	}
	// Once the token is revoked elsewhere, everything that came with it goes too.
	delete(fake.tokens, "s.t")
	if err := rcv.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(cfg.StateDir, "artifacts")); !os.IsNotExist(err) {
		t.Fatal("artifacts should be removed with the token")
	}
}

func TestInstallRejectsMalformedOrUnwantedTokens(t *testing.T) {
	batch := goodToken()
	batch.Type = "batch"
	wrongPolicy := goodToken()
	wrongPolicy.Policies = []string{"admin"}
	local := goodToken()
	local.Meta = map[string]string{"on": "local"}
	fake := &fakeOpenBao{tokens: map[string]openbao.TokenInfo{"s.ok": goodToken(), "s.batch": batch, "s.admin": wrongPolicy, "s.local": local}}
	rcv, _ := newTestReceiver(t, fake, func(c *config.Config) {
		c.AllowedPolicies = []string{"read"}
		c.RequiredMeta = map[string]string{"on": "remote"}
	})
	cases := map[string]string{
		"batch token":        "s.batch\n\n\n",
		"disallowed policy":  "s.admin\n\n\n",
		"wrong metadata":     "s.local\n\n\n",
		"push with newline":  `{"version":2,"token":"s.ok","push_token":"123\nghp_x"}`,
		"unknown version":    `{"version":99,"token":"s.ok"}`,
		"unknown field":      `{"version":2,"token":"s.ok","extra":1}`,
		"duplicate artifact": `{"version":2,"token":"s.ok","artifacts":[{"name":"a","content":"1"},{"name":"a","content":"2"}]}`,
		"oversized payload":  strings.Repeat("a", maxPayloadBytes+10),
	}
	for name, payload := range cases {
		if _, err := rcv.Install(context.Background(), strings.NewReader(payload)); err == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}
	if _, err := rcv.Install(context.Background(), strings.NewReader("s.ok\n\n\n")); err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
}

type deniedRevokeOpenBao struct {
	fakeOpenBao
	denyRevoke bool
	denyLookup bool
}

func (d *deniedRevokeOpenBao) LookupSelf(ctx context.Context, token string) (openbao.TokenInfo, error) {
	if d.denyLookup {
		return openbao.TokenInfo{}, openbao.ErrPermissionDenied
	}
	return d.fakeOpenBao.LookupSelf(ctx, token)
}

func (d *deniedRevokeOpenBao) RevokeSelf(ctx context.Context, token string) error {
	if d.denyRevoke {
		return openbao.ErrPermissionDenied
	}
	return d.fakeOpenBao.RevokeSelf(ctx, token)
}

func TestRevokeFailsClosedOn403PermissionDeniedWhileTokenIsLive(t *testing.T) {
	fake := &deniedRevokeOpenBao{
		fakeOpenBao: fakeOpenBao{tokens: map[string]openbao.TokenInfo{"s.norevoke": goodToken()}},
		denyRevoke:  true,
	}
	rcv, cfg := newTestReceiver(t, fake, nil)
	if _, err := rcv.Install(context.Background(), strings.NewReader("s.norevoke\n\n\n")); err != nil {
		t.Fatal(err)
	}

	// Case 1: RevokeSelf returns 403 permission denied while LookupSelf confirms the token is still active.
	if _, err := rcv.Revoke(context.Background()); err == nil || !strings.Contains(err.Error(), "still active") {
		t.Fatalf("expected revoke to fail while token is still live, got %v", err)
	}
	if _, err := os.Stat(cfg.TokenPath); err != nil {
		t.Fatal("token file must be kept when revoke-self is denied on a live token")
	}

	// Case 2: Both RevokeSelf and LookupSelf return 403 permission denied before expiry -> still fail closed.
	fake.denyLookup = true
	if _, err := rcv.Revoke(context.Background()); err == nil || !strings.Contains(err.Error(), "NOT revoked") {
		t.Fatalf("expected revoke to fail when neither revoke-self nor lookup-self confirms invalidity, got %v", err)
	}
	if _, err := os.Stat(cfg.TokenPath); err != nil {
		t.Fatal("token file must be kept when OpenBao cannot confirm token invalidity")
	}

	// Case 3: Token is revoked out-of-band and LookupSelf confirms ErrInvalidToken -> succeeds and cleans up.
	fake.denyLookup = false
	delete(fake.tokens, "s.norevoke")
	if _, err := rcv.Revoke(context.Background()); err != nil {
		t.Fatalf("expected revoke to succeed once LookupSelf confirms token is invalid: %v", err)
	}
	if _, err := os.Stat(cfg.TokenPath); !os.IsNotExist(err) {
		t.Fatal("token file should be deleted once token invalidity is confirmed")
	}
}

func TestHTTPAmbiguousErrorsAndMalformedLookupPreserveStateAcrossRevokeStatusCleanup(t *testing.T) {
	var mu sync.Mutex
	lookupStatus := http.StatusOK
	lookupBody := `{"data":{"ttl":600,"policies":["read"],"orphan":true,"renewable":false,"type":"service"}}`
	revokeStatus := http.StatusForbidden
	revokeBody := `{"errors":["permission denied"]}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/v1/auth/token/lookup-self":
			w.WriteHeader(lookupStatus)
			_, _ = w.Write([]byte(lookupBody))
		case "/v1/auth/token/revoke-self":
			w.WriteHeader(revokeStatus)
			_, _ = w.Write([]byte(revokeBody))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client, err := openbao.NewClient(srv.URL, "", "", 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	rcv, cfg := newTestReceiver(t, client, func(c *config.Config) {
		c.OpenBaoAddr = srv.URL
	})
	rcv.Now = func() time.Time { return now }

	statePath := filepath.Join(cfg.StateDir, stateFileName)
	artifactPath := filepath.Join(cfg.StateDir, artifactsDirName, "creds.json")
	payload := `{"version":2,"token":"s.httplive","artifacts":[{"name":"creds.json","content":"{}"}]}`
	if _, err := rcv.Install(context.Background(), strings.NewReader(payload)); err != nil {
		t.Fatalf("install: %v", err)
	}

	// 1. Status & Cleanup must preserve token, artifacts, and .grant.json on missing client token,
	//    generic 403 permission denied, prose containing "bad token", and malformed HTTP 200 lookup.
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"400 missing client token", http.StatusBadRequest, `{"errors":["missing client token"]}`},
		{"403 permission denied", http.StatusForbidden, `{"errors":["permission denied"]}`},
		{"403 prose with bad token", http.StatusForbidden, `{"errors":["acl error: bad token config"]}`},
		{"200 empty object", http.StatusOK, `{}`},
		{"200 missing ttl", http.StatusOK, `{"data":{"policies":["read"]}}`},
		{"200 ambiguous zero ttl", http.StatusOK, `{"data":{"ttl":0,"policies":["read"]}}`},
	} {
		mu.Lock()
		lookupStatus, lookupBody = tc.status, tc.body
		mu.Unlock()

		status, err := rcv.Status(context.Background())
		if err != nil || !strings.Contains(status, "Secrets: unknown") {
			t.Fatalf("%s: Status should report unknown, got %q err=%v", tc.name, status, err)
		}
		if err := rcv.Cleanup(context.Background()); err != nil {
			t.Fatalf("%s: Cleanup err=%v", tc.name, err)
		}
		if _, err := os.Stat(cfg.TokenPath); err != nil {
			t.Fatalf("%s: token file must be preserved", tc.name)
		}
		if _, err := os.Stat(artifactPath); err != nil {
			t.Fatalf("%s: artifact file must be preserved while state is unknown", tc.name)
		}
		if _, err := os.Stat(statePath); err != nil {
			t.Fatalf("%s: .grant.json metadata must be preserved", tc.name)
		}
	}

	// 2. Revoke after 403 permission denied + malformed HTTP 200 lookup (missing data/ttl or ttl:0)
	//    or missing client token MUST fail closed and preserve BOTH TokenPath AND .grant.json.
	for _, tc := range []struct {
		name         string
		revokeStatus int
		revokeBody   string
		lookupStatus int
		lookupBody   string
	}{
		{"revoke 403 + lookup 200 empty object", http.StatusForbidden, `{"errors":["permission denied"]}`, http.StatusOK, `{}`},
		{"revoke 403 + lookup 200 missing ttl", http.StatusForbidden, `{"errors":["permission denied"]}`, http.StatusOK, `{"data":{"policies":["read"]}}`},
		{"revoke 403 + lookup 200 zero ttl", http.StatusForbidden, `{"errors":["permission denied"]}`, http.StatusOK, `{"data":{"ttl":0}}`},
		{"revoke 400 missing client token", http.StatusBadRequest, `{"errors":["missing client token"]}`, http.StatusOK, `{"data":{"ttl":600}}`},
		{"revoke 403 prose with bad token", http.StatusForbidden, `{"errors":["policy failed: bad token config"]}`, http.StatusOK, `{"data":{"ttl":600}}`},
		{"revoke 403 + lookup 403 before expiry", http.StatusForbidden, `{"errors":["permission denied"]}`, http.StatusForbidden, `{"errors":["permission denied"]}`},
	} {
		mu.Lock()
		revokeStatus, revokeBody = tc.revokeStatus, tc.revokeBody
		lookupStatus, lookupBody = tc.lookupStatus, tc.lookupBody
		mu.Unlock()

		if _, err := rcv.Revoke(context.Background()); err == nil || !strings.Contains(err.Error(), "NOT revoked") {
			t.Fatalf("%s: Revoke must fail closed, got err=%v", tc.name, err)
		}
		if _, err := os.Stat(cfg.TokenPath); err != nil {
			t.Fatalf("%s: Revoke must keep token file on unconfirmed revocation", tc.name)
		}
		if _, err := os.Stat(statePath); err != nil {
			t.Fatalf("%s: Revoke must preserve .grant.json expiry metadata on unconfirmed revocation", tc.name)
		}
	}

	// 3. Because .grant.json was preserved across the failed revocations above, advancing past
	//    TokenExpiresAt allows Revoke to confirm expiry and clean up both TokenPath and .grant.json.
	now = now.Add(15 * time.Minute)
	mu.Lock()
	revokeStatus, revokeBody = http.StatusForbidden, `{"errors":["permission denied"]}`
	lookupStatus, lookupBody = http.StatusForbidden, `{"errors":["permission denied"]}`
	mu.Unlock()

	if _, err := rcv.Revoke(context.Background()); err != nil {
		t.Fatalf("Revoke after preserved TokenExpiresAt passed should succeed: %v", err)
	}
	if _, err := os.Stat(cfg.TokenPath); !os.IsNotExist(err) {
		t.Fatal("token file should be deleted once preserved TokenExpiresAt has elapsed")
	}
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatal(".grant.json should be deleted once revocation/expiry is confirmed")
	}
}
