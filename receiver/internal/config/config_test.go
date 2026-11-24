package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRequireHTTPSRejectsLookalikeLoopback(t *testing.T) {
	for _, addr := range []string{"http://localhost.evil.example", "http://127.0.0.1.nip.io:8200", "http://10.0.0.1:8200", "ftp://x"} {
		c := Config{OpenBaoAddr: addr}
		c.ApplyDefaults()
		if err := c.Validate(); err == nil {
			t.Errorf("%s should be rejected", addr)
		}
	}
	for _, addr := range []string{"https://vault.example", "http://127.0.0.1:8200", "http://[::1]:8200", "http://localhost:8200"} {
		c := Config{OpenBaoAddr: addr}
		c.ApplyDefaults()
		if err := c.Validate(); err != nil {
			t.Errorf("%s should be allowed: %v", addr, err)
		}
	}
	c := Config{OpenBaoAddr: "https://vault.example", OTLPEndpoint: "http://collector.example:4318"}
	c.ApplyDefaults()
	if err := c.Validate(); err == nil {
		t.Error("plain-http OTLP endpoint should be rejected")
	}
}

func TestLoadFileModeAndUnknownKeys(t *testing.T) {
	dir := t.TempDir()
	write := func(body string) string {
		p := filepath.Join(dir, "c.json")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cfg, err := Load(write(`{"openbao_addr":"https://v.example","file_mode":"0640"}`))
	if err != nil || cfg.FileMode != 0o640 {
		t.Fatalf("octal string: %v %o", err, cfg.FileMode)
	}
	if _, err := Load(write(`{"openbao_addr":"https://v.example","file_mode":600}`)); err == nil {
		t.Fatal("decimal 600 (0o1130) must be rejected")
	}
	if _, err := Load(write(`{"openbao_addr":"https://v.example","file_mode":"0644"}`)); err == nil {
		t.Fatal("world-readable mode must be rejected")
	}
	for _, mode := range []string{`"0620"`, `"0660"`, "400", "432"} {
		if _, err := Load(write(`{"openbao_addr":"https://v.example","file_mode":` + mode + `}`)); err == nil {
			t.Errorf("accepted group-writable mode %s", mode)
		}
	}
	if _, err := Load(write(`{"openbao_addr":"https://v.example","max_ttl":60}`)); err == nil {
		t.Fatal("unknown key must be rejected")
	}
}

func TestEndpointDiagnosticsOmitPrivateComponents(t *testing.T) {
	for _, raw := range []string{"https://user:private-marker@issuer.example", "https://issuer.example/?key=private-marker", "https://issuer.example/#private-marker", "https://%zz/private-marker"} {
		for _, field := range []string{"openbao_addr", "otlp_endpoint"} {
			if err := requireHTTPS(field, raw); err == nil || strings.Contains(err.Error(), "private-marker") {
				t.Errorf("%s should reject the URL without echoing its value", field)
			}
		}
	}
	if got := EndpointOrigin("https://issuer.example:8200/private-marker"); got != "https://issuer.example:8200" {
		t.Errorf("diagnostic origin = %q", got)
	}
}
