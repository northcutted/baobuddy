package receiver

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallRejectsWritableDeliveryDirectories(t *testing.T) {
	for _, role := range []string{"state", "external token", "artifacts"} {
		t.Run(role, func(t *testing.T) {
			r, client := installedReceiver(t)
			dir := r.Cfg.StateDir
			switch role {
			case "external token":
				// Set up the grant at the custom location before changing its mode.
				r, client = emptyReceiver(t)
				dir = t.TempDir()
				r.Cfg.TokenPath = filepath.Join(dir, "token")
				if _, err := r.Install(context.Background(), strings.NewReader(originalPayload)); err != nil {
					t.Fatal(err)
				}
			case "artifacts":
				dir = filepath.Join(dir, artifactsDirName)
			}
			before := readGrantFiles(t, r)
			if err := os.Chmod(dir, 0770); err != nil {
				t.Fatal(err)
			}
			if _, err := r.Install(context.Background(), strings.NewReader(originalPayload)); err == nil {
				t.Fatal("published into a group-writable directory")
			}
			assertOriginalGrant(t, r, before)
			if len(client.revoked) != 0 {
				t.Fatal("revoked original grant during rejected installation")
			}
		})
	}
}

func TestLegacyGroupWritableCredentialEvidence(t *testing.T) {
	for _, name := range []string{"token", stateFileName} {
		t.Run(name, func(t *testing.T) {
			r, _ := installedReceiver(t)
			path := filepath.Join(r.Cfg.StateDir, name)
			if name == stateFileName {
				if err := os.WriteFile(path, []byte(`{"token_expires_at":1}`), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Chmod(path, 0660); err != nil {
				t.Fatal(err)
			}
			before := readGrantFiles(t, r)
			if _, err := r.Status(context.Background()); err == nil {
				t.Fatal("status trusted group-writable grant evidence")
			}
			assertOriginalGrant(t, r, before)
		})
	}
}
