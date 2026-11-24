package openbao

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRedirectIsNotFollowedAndTokenNotForwarded(t *testing.T) {
	leaked := make(chan string, 1)
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked <- r.Header.Get("X-Vault-Token")
	}))
	defer attacker.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, attacker.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer origin.Close()

	c, err := NewClient(origin.URL, "", "", 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.LookupSelf(context.Background(), "hvs.SECRET"); err == nil {
		t.Fatal("expected an error for a redirect")
	}
	if err := c.RevokeSelf(context.Background(), "hvs.SECRET"); err == nil {
		t.Fatal("expected an error for a redirect")
	}
	select {
	case got := <-leaked:
		t.Fatalf("redirect target received a request with token %q", got)
	default:
	}
}

func TestStatusMapping(t *testing.T) {
	status := http.StatusForbidden
	body := `{"errors":["permission denied"]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	c, _ := NewClient(srv.URL, "ns1", "", 2*time.Second)

	if _, err := c.LookupSelf(context.Background(), "hvs.x"); !errors.Is(err, ErrPermissionDenied) || errors.Is(err, ErrInvalidToken) {
		t.Fatalf("403 permission denied must map to ErrPermissionDenied (not ErrInvalidToken), got %v", err)
	}
	status, body = http.StatusForbidden, `{"errors":["bad token"]}`
	if err := c.RevokeSelf(context.Background(), "hvs.x"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("403 bad token should map to ErrInvalidToken, got %v", err)
	}
	status, body = http.StatusBadRequest, `{"errors":["bad token"]}`
	if err := c.RevokeSelf(context.Background(), "hvs.x"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("400 bad token should map to ErrInvalidToken, got %v", err)
	}
	status, body = http.StatusForbidden, `{"errors":["1 error occurred:\n\t* token is expired\n"]}`
	if err := c.RevokeSelf(context.Background(), "hvs.x"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("403 multi-line token is expired should map to ErrInvalidToken, got %v", err)
	}
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"400 missing client token", http.StatusBadRequest, `{"errors":["missing client token"]}`},
		{"403 missing client token", http.StatusForbidden, `{"errors":["missing client token"]}`},
		{"403 prose containing bad token", http.StatusForbidden, `{"errors":["policy evaluation failed: bad token config"]}`},
		{"403 non-json bad token", http.StatusForbidden, `bad token`},
		{"400 empty errors", http.StatusBadRequest, `{"errors":[]}`},
	} {
		status, body = tc.status, tc.body
		if err := c.RevokeSelf(context.Background(), "hvs.x"); err == nil || errors.Is(err, ErrInvalidToken) {
			t.Fatalf("%s must NOT map to ErrInvalidToken, got %v", tc.name, err)
		}
		if _, err := c.LookupSelf(context.Background(), "hvs.x"); err == nil || errors.Is(err, ErrInvalidToken) {
			t.Fatalf("%s on lookup-self must NOT map to ErrInvalidToken, got %v", tc.name, err)
		}
	}
	status, body = http.StatusServiceUnavailable, `{"errors":["Vault is sealed"]}`
	if _, err := c.LookupSelf(context.Background(), "hvs.x"); err == nil || errors.Is(err, ErrInvalidToken) || errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("503 must not look like an invalid token or permission denial, got %v", err)
	}
}

func TestLookupSelfRejectsMalformedEnvelopeOrMissingTTL(t *testing.T) {
	body := `{"data":{"ttl":3600,"policies":["read"],"orphan":true}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	c, err := NewClient(srv.URL, "", "", 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	info, err := c.LookupSelf(context.Background(), "hvs.ok")
	if err != nil || info.TTLSeconds != 3600 {
		t.Fatalf("expected valid lookup-self, got info=%+v err=%v", info, err)
	}

	for _, tc := range []struct {
		name string
		body string
	}{
		{"empty object", `{}`},
		{"null data", `{"data":null}`},
		{"empty data missing ttl", `{"data":{}}`},
		{"missing ttl with policies", `{"data":{"policies":["read"],"orphan":true}}`},
		{"null ttl", `{"data":{"ttl":null,"policies":["read"]}}`},
		{"negative ttl", `{"data":{"ttl":-1,"policies":["read"]}}`},
	} {
		body = tc.body
		if _, err := c.LookupSelf(context.Background(), "hvs.x"); err == nil || errors.Is(err, ErrInvalidToken) {
			t.Fatalf("%s: expected non-ErrInvalidToken decode error, got %v", tc.name, err)
		}
	}
}

func TestHealthRequiresActiveIssuer(t *testing.T) {
	const active = `{"version":"2.7.2","initialized":true,"sealed":false,"standby":false}`
	for _, tc := range []struct {
		name  string
		code  int
		body  string
		ready bool
	}{
		{"active", 200, active, true},
		{"proxy error", 502, active, false},
		{"missing fields", 200, `{"version":"2.7.2"}`, false},
		{"missing version", 200, `{"initialized":true,"sealed":false,"standby":false}`, false},
		{"uninitialized", 200, strings.Replace(active, `"initialized":true`, `"initialized":false`, 1), false},
		{"standby", 429, active, false},
		{"standby body", 200, strings.Replace(active, `"standby":false`, `"standby":true`, 1), false},
		{"sealed", 503, active, false},
		{"sealed body", 200, strings.Replace(active, `"sealed":false`, `"sealed":true`, 1), false},
		{"oversized", 200, active + strings.Repeat(" ", 65536), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.code)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer srv.Close()
			c, err := NewClient(srv.URL, "", "", time.Second)
			if err != nil {
				t.Fatal(err)
			}
			_, sealed, err := c.CheckHealth(context.Background())
			if (err == nil && !sealed) != tc.ready {
				t.Fatalf("ready=%v, sealed=%v, err=%v", tc.ready, sealed, err)
			}
		})
	}
}

func TestTransportErrorsOmitPrivateEndpointPath(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close()
	c, err := NewClient(srv.URL+"/private-marker", "", "", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, _, healthErr := c.CheckHealth(context.Background())
	_, lookupErr := c.LookupSelf(context.Background(), "s.fixture")
	revokeErr := c.RevokeSelf(context.Background(), "s.fixture")
	for _, err := range []error{healthErr, lookupErr, revokeErr} {
		if err == nil || strings.Contains(err.Error(), "private-marker") {
			t.Fatalf("unexpected transport error: %v", err)
		}
	}
}
