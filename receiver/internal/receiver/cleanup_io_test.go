package receiver

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/northcutted/baobuddy/receiver/internal/config"
	"github.com/northcutted/baobuddy/receiver/internal/openbao"
)

const testSSHCert = "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29t test@host"

func requireNonRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("skipping permission-enforcement test when running as root")
	}
}

func assertPathExists(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("expected %s to exist, got %v", path, err)
	}
}

func assertPathAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("expected %s to be absent (ENOENT), got err=%v", path, err)
	}
}

func installFullGrant(t *testing.T, rcv *Receiver, token string, pushEpoch int64, artifactExpiry int64) {
	t.Helper()
	p := InstallPayloadV2{
		Version:   2,
		Token:     token,
		SSHCert:   testSSHCert,
		PushToken: strconv.FormatInt(pushEpoch, 10) + " ghs_testpushtoken123",
		Artifacts: []Artifact{
			{Name: "creds.json", Content: `{"ok":true}`, ExpiresAt: artifactExpiry},
		},
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal install payload: %v", err)
	}
	if _, err := rcv.Install(context.Background(), strings.NewReader(string(raw))); err != nil {
		t.Fatalf("install fixture: %v", err)
	}
}

func TestUnreadableTokenDoesNotDeleteSecondariesOrExpiredPush(t *testing.T) {
	requireNonRoot(t)
	fake := &fakeOpenBao{tokens: map[string]openbao.TokenInfo{"s.live": goodToken()}}
	now := time.Unix(1_800_000_000, 0).UTC()
	rcv, cfg := newTestReceiver(t, fake, nil)
	rcv.Now = func() time.Time { return now }

	// Install with a push token that will already be expired when Status runs.
	installFullGrant(t, rcv, "s.live", now.Unix()+60, now.Unix()+600)
	now = now.Add(2 * time.Minute)

	if err := os.Chmod(cfg.TokenPath, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(cfg.TokenPath, 0o600) })

	statePath := filepath.Join(cfg.StateDir, stateFileName)
	artifactPath := filepath.Join(cfg.StateDir, artifactsDirName, "creds.json")

	status, err := rcv.Status(context.Background())
	if err == nil || !strings.Contains(status, "Secrets: unknown") {
		t.Fatalf("Status on unreadable token must fail honestly, got status=%q err=%v", status, err)
	}
	if !strings.Contains(status, "Push: expired (retained") {
		t.Fatalf("Status must retain expired push token when token is unreadable, got %q", status)
	}
	if err := rcv.Cleanup(context.Background()); err == nil {
		t.Fatal("Cleanup on unreadable token must fail")
	}
	if _, err := rcv.Revoke(context.Background()); err == nil {
		t.Fatal("Revoke on unreadable token must fail")
	}

	// Nothing may have been deleted or revoked upstream.
	assertPathExists(t, cfg.TokenPath)
	assertPathExists(t, cfg.SSHCertPath)
	assertPathExists(t, cfg.PushTokenPath)
	assertPathExists(t, artifactPath)
	assertPathExists(t, statePath)
	if len(fake.revoked) != 0 {
		t.Fatalf("unreadable token must not trigger upstream revoke, got %v", fake.revoked)
	}
}

func TestUnreadableOrMalformedStateRetainsExpiredPushToken(t *testing.T) {
	fake := &fakeOpenBao{tokens: map[string]openbao.TokenInfo{"s.live": goodToken()}}
	now := time.Unix(1_800_000_000, 0).UTC()
	rcv, cfg := newTestReceiver(t, fake, nil)
	rcv.Now = func() time.Time { return now }

	installFullGrant(t, rcv, "s.live", now.Unix()+60, now.Unix()+600)
	now = now.Add(2 * time.Minute)

	statePath := filepath.Join(cfg.StateDir, stateFileName)
	if err := os.WriteFile(statePath, []byte("{corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}

	status, err := rcv.Status(context.Background())
	if err == nil {
		t.Fatalf("Status must fail on malformed state, got %q", status)
	}
	if !strings.Contains(status, "Push: expired (retained") {
		t.Fatalf("Status must retain expired push token when state is malformed, got %q", status)
	}
	assertPathExists(t, cfg.PushTokenPath)
	assertPathExists(t, statePath)
}

func TestEmptyMalformedDirectoryOrSymlinkTokenDoesNotAuthorizeCleanup(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, cfg config.Config)
	}{
		{
			name: "empty token file",
			setup: func(t *testing.T, cfg config.Config) {
				if err := os.WriteFile(cfg.TokenPath, []byte("   \n"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "malformed token content",
			setup: func(t *testing.T, cfg config.Config) {
				if err := os.WriteFile(cfg.TokenPath, []byte("not a valid token!\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "directory as token path",
			setup: func(t *testing.T, cfg config.Config) {
				if err := os.Remove(cfg.TokenPath); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(cfg.TokenPath, 0o700); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "symlink as token path",
			setup: func(t *testing.T, cfg config.Config) {
				target := filepath.Join(t.TempDir(), "elsewhere")
				if err := os.WriteFile(target, []byte("s.other\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(cfg.TokenPath); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, cfg.TokenPath); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeOpenBao{tokens: map[string]openbao.TokenInfo{"s.live": goodToken()}}
			now := time.Unix(1_800_000_000, 0).UTC()
			rcv, cfg := newTestReceiver(t, fake, nil)
			rcv.Now = func() time.Time { return now }

			installFullGrant(t, rcv, "s.live", now.Unix()+600, now.Unix()+600)
			tc.setup(t, cfg)

			statePath := filepath.Join(cfg.StateDir, stateFileName)
			artifactPath := filepath.Join(cfg.StateDir, artifactsDirName, "creds.json")

			if _, err := rcv.Status(context.Background()); err == nil {
				t.Fatalf("%s: Status must return error", tc.name)
			}
			if err := rcv.Cleanup(context.Background()); err == nil {
				t.Fatalf("%s: Cleanup must return error", tc.name)
			}
			if _, err := rcv.Revoke(context.Background()); err == nil {
				t.Fatalf("%s: Revoke must return error", tc.name)
			}

			assertPathExists(t, cfg.TokenPath)
			assertPathExists(t, cfg.SSHCertPath)
			assertPathExists(t, cfg.PushTokenPath)
			assertPathExists(t, artifactPath)
			assertPathExists(t, statePath)
			if len(fake.revoked) != 0 {
				t.Fatalf("%s: must not revoke upstream, got %v", tc.name, fake.revoked)
			}
		})
	}
}

func TestMalformedEmptyAndDirectorySecondaryFilesAreNotDeleted(t *testing.T) {
	t.Run("malformed push token and ssh cert preserved by Status and Cleanup", func(t *testing.T) {
		fake := &fakeOpenBao{tokens: map[string]openbao.TokenInfo{"s.live": goodToken()}}
		now := time.Unix(1_800_000_000, 0).UTC()
		rcv, cfg := newTestReceiver(t, fake, nil)
		rcv.Now = func() time.Time { return now }

		installFullGrant(t, rcv, "s.live", now.Unix()+600, now.Unix()+600)

		if err := os.WriteFile(cfg.PushTokenPath, []byte("corrupt-not-epoch\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(cfg.SSHCertPath, []byte("   \n"), 0o600); err != nil {
			t.Fatal(err)
		}

		status, err := rcv.Status(context.Background())
		if err == nil {
			t.Fatalf("Status must fail on malformed push/ssh files, got status=%q", status)
		}
		if !strings.Contains(status, "SSH: unknown") || !strings.Contains(status, "Push: unknown") {
			t.Fatalf("expected unknown SSH and Push lines, got %q", status)
		}
		if err := rcv.Cleanup(context.Background()); err == nil {
			t.Fatal("Cleanup must fail on malformed push/ssh files")
		}
		assertPathExists(t, cfg.PushTokenPath)
		assertPathExists(t, cfg.SSHCertPath)
	})

	t.Run("empty directory at secondary paths is never removed by Revoke or Cleanup", func(t *testing.T) {
		fake := &fakeOpenBao{tokens: map[string]openbao.TokenInfo{"s.live": goodToken()}}
		now := time.Unix(1_800_000_000, 0).UTC()
		rcv, cfg := newTestReceiver(t, fake, nil)
		rcv.Now = func() time.Time { return now }

		installFullGrant(t, rcv, "s.live", now.Unix()+600, now.Unix()+600)

		// Replace SSHCertPath and PushTokenPath with EMPTY directories (os.Remove would rmdir these!).
		if err := os.Remove(cfg.SSHCertPath); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(cfg.SSHCertPath, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(cfg.PushTokenPath); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(cfg.PushTokenPath, 0o700); err != nil {
			t.Fatal(err)
		}

		_, err := rcv.Revoke(context.Background())
		if err == nil {
			t.Fatal("Revoke must report local cleanup error when secondary paths are directories")
		}
		if !strings.Contains(err.Error(), "upstream: revoked at OpenBao") || !strings.Contains(err.Error(), "local cleanup failed") {
			t.Fatalf("expected separate upstream outcome and local cleanup error, got: %v", err)
		}

		// Directories must NOT be deleted; token was revoked & removed; retry state (.grant.json) retained in mode 0600.
		assertPathAbsent(t, cfg.TokenPath)
		assertPathExists(t, cfg.SSHCertPath)
		assertPathExists(t, cfg.PushTokenPath)
		statePath := filepath.Join(cfg.StateDir, stateFileName)
		fi, err := os.Lstat(statePath)
		if err != nil {
			t.Fatalf("expected retained .grant.json: %v", err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("expected private mode 0600 on retained .grant.json, got %#o", fi.Mode().Perm())
		}

		// Fix the bogus directories and retry Revoke: finishes cleaning up `.grant.json` cleanly.
		if err := os.Remove(cfg.SSHCertPath); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(cfg.PushTokenPath); err != nil {
			t.Fatal(err)
		}
		msg, err := rcv.Revoke(context.Background())
		if err != nil {
			t.Fatalf("retry Revoke after fixing directory paths should succeed: %v", err)
		}
		if !strings.Contains(msg, "Revoked") {
			t.Fatalf("unexpected retry message: %q", msg)
		}
		assertPathAbsent(t, statePath)
	})

	t.Run("directory at expired artifact entry is never removed as plain file", func(t *testing.T) {
		fake := &fakeOpenBao{tokens: map[string]openbao.TokenInfo{"s.live": goodToken()}}
		now := time.Unix(1_800_000_000, 0).UTC()
		rcv, cfg := newTestReceiver(t, fake, nil)
		rcv.Now = func() time.Time { return now }

		installFullGrant(t, rcv, "s.live", now.Unix()+600, now.Unix()+60)
		artPath := filepath.Join(cfg.StateDir, artifactsDirName, "creds.json")
		if err := os.Remove(artPath); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(artPath, 0o700); err != nil {
			t.Fatal(err)
		}

		now = now.Add(2 * time.Minute)
		if err := rcv.Cleanup(context.Background()); err == nil {
			t.Fatal("Cleanup must fail when expired artifact path is a directory")
		}
		assertPathExists(t, artPath)
	})
}

func TestMalformedOrDirectoryStateFileDoesNotAuthorizeCleanup(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, statePath string)
	}{
		{
			name: "empty grant.json",
			setup: func(t *testing.T, statePath string) {
				if err := os.WriteFile(statePath, []byte(" \n"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "malformed json",
			setup: func(t *testing.T, statePath string) {
				if err := os.WriteFile(statePath, []byte("{bad"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "empty json object",
			setup: func(t *testing.T, statePath string) {
				if err := os.WriteFile(statePath, []byte("{}"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "directory as grant.json",
			setup: func(t *testing.T, statePath string) {
				if err := os.Remove(statePath); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(statePath, 0o700); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeOpenBao{tokens: map[string]openbao.TokenInfo{"s.live": goodToken()}}
			now := time.Unix(1_800_000_000, 0).UTC()
			rcv, cfg := newTestReceiver(t, fake, nil)
			rcv.Now = func() time.Time { return now }

			installFullGrant(t, rcv, "s.live", now.Unix()+600, now.Unix()+600)
			statePath := filepath.Join(cfg.StateDir, stateFileName)
			tc.setup(t, statePath)

			// Remove token genuinely (ENOENT): malformed/directory .grant.json must still block destructive cleanup.
			if err := os.Remove(cfg.TokenPath); err != nil {
				t.Fatal(err)
			}

			if _, err := rcv.Status(context.Background()); err == nil {
				t.Fatalf("%s: Status must fail on invalid .grant.json", tc.name)
			}
			if err := rcv.Cleanup(context.Background()); err == nil {
				t.Fatalf("%s: Cleanup must fail on invalid .grant.json", tc.name)
			}
			if _, err := rcv.Revoke(context.Background()); err == nil {
				t.Fatalf("%s: Revoke must fail on invalid .grant.json", tc.name)
			}

			assertPathExists(t, statePath)
			assertPathExists(t, cfg.SSHCertPath)
			assertPathExists(t, cfg.PushTokenPath)
			assertPathExists(t, filepath.Join(cfg.StateDir, artifactsDirName, "creds.json"))
		})
	}
}

func TestUntrustedMarkerInGroupWritableStateRejectedAndLegacyGroupReadableAccepted(t *testing.T) {
	t.Run("group-writable .grant.json with marker is rejected", func(t *testing.T) {
		fake := &flakyOpenBao{
			fakeOpenBao: fakeOpenBao{tokens: map[string]openbao.TokenInfo{"s.live": goodToken()}},
			down:        true,
		}
		now := time.Unix(1_800_000_000, 0).UTC()
		rcv, cfg := newTestReceiver(t, fake, func(c *config.Config) {
			c.FileMode = 0o640
		})
		rcv.Now = func() time.Time { return now }

		if err := os.WriteFile(cfg.TokenPath, []byte("s.live\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		statePath := filepath.Join(cfg.StateDir, stateFileName)
		st := grantState{
			TokenExpiresAt:     now.Unix() + 600,
			RevokedTokenSHA256: tokenDigest("s.live"),
		}
		raw, _ := json.Marshal(st)
		if err := os.WriteFile(statePath, raw, 0o660); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(statePath, 0o660); err != nil {
			t.Fatal(err)
		}

		if _, err := rcv.Status(context.Background()); err == nil || !strings.Contains(err.Error(), "untrusted grant state") {
			t.Fatalf("Status must reject untrusted group-writable marker, got %v", err)
		}
		if _, err := rcv.Revoke(context.Background()); err == nil || !strings.Contains(err.Error(), "untrusted grant state") {
			t.Fatalf("Revoke must reject untrusted group-writable marker, got %v", err)
		}
		assertPathExists(t, cfg.TokenPath)
		assertPathExists(t, statePath)
	})

	t.Run("legacy group-readable 0640 .grant.json without marker still works", func(t *testing.T) {
		fake := &fakeOpenBao{tokens: map[string]openbao.TokenInfo{"s.legacy": goodToken()}}
		now := time.Unix(1_800_000_000, 0).UTC()
		rcv, cfg := newTestReceiver(t, fake, func(c *config.Config) {
			c.FileMode = 0o640
		})
		rcv.Now = func() time.Time { return now }

		if err := os.WriteFile(cfg.TokenPath, []byte("s.legacy\n"), 0o640); err != nil {
			t.Fatal(err)
		}
		statePath := filepath.Join(cfg.StateDir, stateFileName)
		raw, _ := json.Marshal(grantState{TokenExpiresAt: now.Unix() + 600})
		if err := os.WriteFile(statePath, raw, 0o640); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(statePath, 0o640); err != nil {
			t.Fatal(err)
		}

		status, err := rcv.Status(context.Background())
		if err != nil || !strings.Contains(status, "Secrets: active") {
			t.Fatalf("legacy 0640 state without marker should work, got status=%q err=%v", status, err)
		}
	})
}

func TestLocalExpiryAloneNeverWritesMarkerOrClaimsOpenBaoConfirmed(t *testing.T) {
	requireNonRoot(t)

	tokenDir := filepath.Join(t.TempDir(), "tokdir")
	if err := os.MkdirAll(tokenDir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(tokenDir, 0o700) })

	fake := &deniedRevokeOpenBao{
		fakeOpenBao: fakeOpenBao{tokens: map[string]openbao.TokenInfo{"s.exp": goodToken()}},
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	rcv, cfg := newTestReceiver(t, fake, func(c *config.Config) {
		c.TokenPath = filepath.Join(tokenDir, "token")
	})
	rcv.Now = func() time.Time { return now }

	installFullGrant(t, rcv, "s.exp", now.Unix()+600, now.Unix()+600)

	// Advance past local TokenExpiresAt while OpenBao denies both revoke-self and lookup-self.
	fake.denyRevoke = true
	fake.denyLookup = true
	now = now.Add(15 * time.Minute)
	if err := os.Chmod(tokenDir, 0o500); err != nil {
		t.Fatal(err)
	}

	// 1. Cleanup/Status failing deletion on local expiry must NOT write RevokedTokenSHA256.
	_, err := rcv.Status(context.Background())
	if err == nil {
		t.Fatal("Status must fail when token unlink fails after local expiry")
	}
	if strings.Contains(err.Error(), "OpenBao confirmed") {
		t.Fatalf("local expiry error must not claim OpenBao confirmed revocation: %v", err)
	}
	statePath := filepath.Join(cfg.StateDir, stateFileName)
	raw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	var st grantState
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatalf("unmarshal state: %v", err)
	}
	if st.RevokedTokenSHA256 != "" {
		t.Fatalf("local expiry alone must not write RevokedTokenSHA256 marker, got %q", st.RevokedTokenSHA256)
	}

	// 2. Revoke failing deletion on local expiry must NOT write RevokedTokenSHA256 either.
	_, err = rcv.Revoke(context.Background())
	if err == nil {
		t.Fatal("Revoke must fail when token unlink fails after local expiry")
	}
	if strings.Contains(err.Error(), "upstream: revoked at OpenBao") || strings.Contains(err.Error(), "OpenBao confirmed") {
		t.Fatalf("local expiry Revoke error must not claim OpenBao confirmed revocation: %v", err)
	}
	raw, err = os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read state after revoke: %v", err)
	}
	st = grantState{}
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatalf("unmarshal state after revoke: %v", err)
	}
	if st.RevokedTokenSHA256 != "" {
		t.Fatalf("local expiry Revoke must not write RevokedTokenSHA256 marker, got %q", st.RevokedTokenSHA256)
	}

	// 3. Restoring permissions and succeeding on local expiry must distinguish the message from OpenBao confirmation.
	if err := os.Chmod(tokenDir, 0o700); err != nil {
		t.Fatal(err)
	}
	msg, err := rcv.Revoke(context.Background())
	if err != nil {
		t.Fatalf("Revoke retry after local expiry should succeed: %v", err)
	}
	if strings.Contains(msg, "Revoked the grant at OpenBao") {
		t.Fatalf("local expiry success message must not claim OpenBao confirmed revocation, got %q", msg)
	}
	if !strings.Contains(msg, "expired locally") {
		t.Fatalf("expected message to state local expiry, got %q", msg)
	}
	assertPathAbsent(t, cfg.TokenPath)
	assertPathAbsent(t, statePath)
}

func TestSameGrantRetryAfterRemoteRevokeAndLocalDeletionFailure(t *testing.T) {
	requireNonRoot(t)

	// Place TokenPath in its own directory so we can make only token deletion fail while StateDir stays writable.
	tokenDir := filepath.Join(t.TempDir(), "tokdir")
	if err := os.MkdirAll(tokenDir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(tokenDir, 0o700) })

	fake := &flakyOpenBao{fakeOpenBao: fakeOpenBao{tokens: map[string]openbao.TokenInfo{"s.retry1": goodToken()}}}
	now := time.Unix(1_800_000_000, 0).UTC()
	rcv, cfg := newTestReceiver(t, fake, func(c *config.Config) {
		c.TokenPath = filepath.Join(tokenDir, "token")
		c.FileMode = 0o640 // Marker must STILL be written 0600 via writePrivateAtomic!
	})
	rcv.Now = func() time.Time { return now }

	installFullGrant(t, rcv, "s.retry1", now.Unix()+600, now.Unix()+600)

	// Lock down tokenDir so reading TokenPath succeeds, but unlinking TokenPath fails with EACCES.
	if err := os.Chmod(tokenDir, 0o500); err != nil {
		t.Fatal(err)
	}

	_, err := rcv.Revoke(context.Background())
	if err == nil {
		t.Fatal("Revoke must fail when TokenPath unlink fails")
	}
	if !strings.Contains(err.Error(), "upstream: revoked at OpenBao") || !strings.Contains(err.Error(), "local cleanup failed") || !strings.Contains(err.Error(), "retry state was kept") {
		t.Fatalf("expected separate upstream confirmation, local cleanup error, and retry state kept, got: %v", err)
	}
	if len(fake.revoked) != 1 || fake.revoked[0] != "s.retry1" {
		t.Fatalf("expected upstream revoke of s.retry1, got %v", fake.revoked)
	}
	assertPathExists(t, cfg.TokenPath)
	statePath := filepath.Join(cfg.StateDir, stateFileName)
	fi, err := os.Lstat(statePath)
	if err != nil {
		t.Fatalf("stat retained state: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("recordRemoteConfirmation must write .grant.json in mode 0600 even when cfg.FileMode=0640, got %#o", fi.Mode().Perm())
	}

	rawState, readErr := os.ReadFile(statePath)
	if readErr != nil {
		t.Fatalf("read retained state: %v", readErr)
	}
	if strings.Contains(string(rawState), "s.retry1") {
		t.Fatal("retained retry state must never store raw token")
	}
	var persisted grantState
	if err := json.Unmarshal(rawState, &persisted); err != nil {
		t.Fatalf("unmarshal retained state: %v", err)
	}
	if persisted.RevokedTokenSHA256 != tokenDigest("s.retry1") {
		t.Fatalf("expected RevokedTokenSHA256 for s.retry1, got %q", persisted.RevokedTokenSHA256)
	}

	// Simulate OpenBao now being completely offline during the retry.
	fake.down = true

	// While tokenDir is still read-only, a retry still fails honestly and retains retry state.
	if _, err := rcv.Revoke(context.Background()); err == nil || !strings.Contains(err.Error(), "already confirmed revoked") {
		t.Fatalf("expected retry with still-failing unlink to report prior upstream confirmation + local error, got: %v", err)
	}
	assertPathExists(t, cfg.TokenPath)
	assertPathExists(t, statePath)

	// Restore tokenDir permissions: same-grant retry MUST complete cleanly even while OpenBao is offline.
	if err := os.Chmod(tokenDir, 0o700); err != nil {
		t.Fatal(err)
	}
	msg, err := rcv.Revoke(context.Background())
	if err != nil {
		t.Fatalf("same-grant retry after fixing permissions should succeed even offline: %v", err)
	}
	if !strings.Contains(msg, "Revoked") {
		t.Fatalf("unexpected retry message: %q", msg)
	}
	assertPathAbsent(t, cfg.TokenPath)
	assertPathAbsent(t, statePath)
}

func TestRemoteConfirmationDoesNotApplyToDifferentGrant(t *testing.T) {
	fake := &flakyOpenBao{
		fakeOpenBao: fakeOpenBao{tokens: map[string]openbao.TokenInfo{"s.grant2": goodToken()}},
		down:        true,
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	rcv, cfg := newTestReceiver(t, fake, nil)
	rcv.Now = func() time.Time { return now }

	// Manually place token s.grant2 alongside a private 0600 .grant.json confirming revocation of a
	// DIFFERENT token (s.grant1) with an elapsed expiry, while OpenBao is down.
	if err := os.WriteFile(cfg.TokenPath, []byte("s.grant2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	st := grantState{
		TokenExpiresAt:     now.Unix() - 10,
		RevokedTokenSHA256: tokenDigest("s.grant1"),
	}
	raw, _ := json.Marshal(st)
	if err := os.WriteFile(filepath.Join(cfg.StateDir, stateFileName), raw, 0o600); err != nil {
		t.Fatal(err)
	}

	status, err := rcv.Status(context.Background())
	if err != nil {
		t.Fatalf("Status during outage for different grant should report unknown without deleting: %v", err)
	}
	if !strings.Contains(status, "Secrets: unknown") {
		t.Fatalf("expected Secrets: unknown, got %q", status)
	}
	assertPathExists(t, cfg.TokenPath)

	if _, err := rcv.Revoke(context.Background()); err == nil || !strings.Contains(err.Error(), "NOT revoked") {
		t.Fatalf("Revoke must fail closed for a different grant during outage, got %v", err)
	}
	assertPathExists(t, cfg.TokenPath)
}

func TestStatusCleanupRetryAfterRemoteInvalidAndLocalDeletionFailure(t *testing.T) {
	requireNonRoot(t)

	tokenDir := filepath.Join(t.TempDir(), "tokdir")
	if err := os.MkdirAll(tokenDir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(tokenDir, 0o700) })

	fake := &flakyOpenBao{fakeOpenBao: fakeOpenBao{tokens: map[string]openbao.TokenInfo{"s.dead": goodToken()}}}
	now := time.Unix(1_800_000_000, 0).UTC()
	rcv, cfg := newTestReceiver(t, fake, func(c *config.Config) {
		c.TokenPath = filepath.Join(tokenDir, "token")
	})
	rcv.Now = func() time.Time { return now }

	installFullGrant(t, rcv, "s.dead", now.Unix()+600, now.Unix()+600)

	// Revoke out-of-band on OpenBao and block deletion of TokenPath.
	delete(fake.tokens, "s.dead")
	if err := os.Chmod(tokenDir, 0o500); err != nil {
		t.Fatal(err)
	}

	status, err := rcv.Status(context.Background())
	if err == nil {
		t.Fatal("Status must return error when local token deletion fails after OpenBao rejects token")
	}
	if !strings.Contains(err.Error(), "upstream: OpenBao confirmed token is invalid or revoked") || !strings.Contains(err.Error(), "local cleanup failed") {
		t.Fatalf("expected separate upstream and local errors, got: %v (status=%q)", err, status)
	}
	assertPathExists(t, cfg.TokenPath)
	assertPathExists(t, filepath.Join(cfg.StateDir, stateFileName))

	// Even if OpenBao goes offline before retry, fixing tokenDir allows Cleanup/Status to finish cleanly.
	fake.down = true
	if err := os.Chmod(tokenDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := rcv.Cleanup(context.Background()); err != nil {
		t.Fatalf("Cleanup retry after fixing permissions should succeed offline: %v", err)
	}
	assertPathAbsent(t, cfg.TokenPath)
	assertPathAbsent(t, filepath.Join(cfg.StateDir, stateFileName))
}

func TestReadOnlyStateDirReportsPersistFailureWithoutPromisingRetryStateKept(t *testing.T) {
	requireNonRoot(t)

	fake := &fakeOpenBao{tokens: map[string]openbao.TokenInfo{"s.ro": goodToken()}}
	now := time.Unix(1_800_000_000, 0).UTC()
	rcv, cfg := newTestReceiver(t, fake, nil)
	rcv.Now = func() time.Time { return now }

	installFullGrant(t, rcv, "s.ro", now.Unix()+600, now.Unix()+600)

	// Make StateDir read-only: .lock (0600) still opens O_RDWR, reading token/.grant.json succeeds,
	// unlinking any file and rewriting .grant.json fail with EACCES.
	if err := os.Chmod(cfg.StateDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(cfg.StateDir, 0o750) })

	_, err := rcv.Revoke(context.Background())
	if err == nil {
		t.Fatal("Revoke on read-only StateDir must return error")
	}
	if !strings.Contains(err.Error(), "upstream: revoked at OpenBao") || !strings.Contains(err.Error(), "local cleanup failed") {
		t.Fatalf("expected upstream outcome + local cleanup error, got: %v", err)
	}
	if strings.Contains(err.Error(), "retry state was kept") {
		t.Fatalf("must not promise retry state was kept when marker persistence failed, got: %v", err)
	}
	if !strings.Contains(err.Error(), "retry state could not be updated") {
		t.Fatalf("expected explicit notice that retry state could not be updated, got: %v", err)
	}
	assertPathExists(t, cfg.TokenPath)
	assertPathExists(t, filepath.Join(cfg.StateDir, stateFileName))

	// Restore permissions and retry: OpenBao returns ErrInvalidToken (already revoked), cleanup finishes cleanly.
	if err := os.Chmod(cfg.StateDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := rcv.Revoke(context.Background()); err != nil {
		t.Fatalf("retry Revoke after restoring StateDir permissions should succeed: %v", err)
	}
	assertPathAbsent(t, cfg.TokenPath)
	assertPathAbsent(t, cfg.SSHCertPath)
	assertPathAbsent(t, cfg.PushTokenPath)
	assertPathAbsent(t, filepath.Join(cfg.StateDir, stateFileName))
}

func TestGenuineENOENTStillCleansUpLeftoverSecondaries(t *testing.T) {
	fake := &fakeOpenBao{tokens: map[string]openbao.TokenInfo{"s.live": goodToken()}}
	now := time.Unix(1_800_000_000, 0).UTC()
	rcv, cfg := newTestReceiver(t, fake, nil)
	rcv.Now = func() time.Time { return now }

	installFullGrant(t, rcv, "s.live", now.Unix()+600, now.Unix()+600)
	if err := os.Remove(cfg.TokenPath); err != nil {
		t.Fatal(err)
	}

	status, err := rcv.Status(context.Background())
	if err != nil {
		t.Fatalf("Status with genuine ENOENT token should succeed: %v", err)
	}
	if !strings.Contains(status, "Secrets: no grant") || !strings.Contains(status, "SSH: no certificate") || !strings.Contains(status, "Push: no token") {
		t.Fatalf("unexpected status: %q", status)
	}
	assertPathAbsent(t, cfg.SSHCertPath)
	assertPathAbsent(t, cfg.PushTokenPath)
	assertPathAbsent(t, filepath.Join(cfg.StateDir, artifactsDirName))
	assertPathAbsent(t, filepath.Join(cfg.StateDir, stateFileName))
}
