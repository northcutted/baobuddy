package receiver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/northcutted/baobuddy/receiver/internal/config"
	"github.com/northcutted/baobuddy/receiver/internal/openbao"
)

func TestFirstInstallPolicyBoundary(t *testing.T) {
	cfg, err := config.Load(filepath.Join("..", "..", "deploy", "config.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name             string
		direct, identity []string
		external         map[string][]string
		accepted         bool
	}{
		{"expected", []string{"app-read", "default"}, nil, nil, true},
		{"missing policy evidence", nil, nil, nil, false},
		{"additional direct", []string{"app-read", "extra"}, nil, nil, false},
		{"allowed identity", []string{"default"}, []string{"app-read"}, nil, true},
		{"additional identity", []string{"app-read"}, []string{"extra"}, nil, false},
		{"other namespace", []string{"app-read"}, nil, map[string][]string{"other": {"app-read"}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"ttl": 600, "orphan": true, "type": "service", "meta": map[string]string{"on": "remote"}, "policies": tc.direct, "identity_policies": tc.identity, "external_namespace_policies": tc.external}})
			}))
			defer srv.Close()
			client, err := openbao.NewClient(srv.URL, "", "", time.Second)
			if err != nil {
				t.Fatal(err)
			}
			local := cfg
			local.StateDir = t.TempDir()
			local.TokenPath = ""
			local.PushTokenPath = ""
			local.SSHCertPath = ""
			local.ApplyDefaults()
			r := New(local, client, nil)
			_, err = r.Install(context.Background(), strings.NewReader("s.example\n\n\n"))
			if (err == nil) != tc.accepted {
				t.Fatalf("accepted=%v, err=%v", tc.accepted, err)
			}
			if !tc.accepted {
				assertPathAbsent(t, local.TokenPath)
			}
		})
	}
}
