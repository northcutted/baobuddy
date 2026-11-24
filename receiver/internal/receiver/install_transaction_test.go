package receiver

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/northcutted/baobuddy/receiver/internal/openbao"
)

const originalPayload = `{"version":2,"token":"s.original","push_token":"1900000000 ghp_original","ssh_cert":"ssh-ed25519-cert-v01@openssh.com original","artifacts":[{"name":"db","content":"original","expires_at":1700000000}]}`

func readGrantFiles(t *testing.T, r *Receiver) map[string]string {
	t.Helper()
	files := make(map[string]string)
	for _, p := range append(r.installPaths()[1:], filepath.Join(r.Cfg.StateDir, artifactsDirName, "db")) {
		data, err := os.ReadFile(p)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		files[p] = string(data)
	}
	return files
}

func assertOriginalGrant(t *testing.T, r *Receiver, want map[string]string) {
	t.Helper()
	got := readGrantFiles(t, r)
	if len(got) != len(want) {
		t.Fatalf("restored %d files, want %d", len(got), len(want))
	}
	for p, content := range want {
		if got[p] != content {
			t.Errorf("%s was not restored", p)
		}
	}
	entries, err := os.ReadDir(r.Cfg.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), "install-") {
			t.Errorf("left transaction entry %s", e.Name())
		}
	}
}

func emptyReceiver(t *testing.T) (*Receiver, *fakeOpenBao) {
	t.Helper()
	bao := &fakeOpenBao{tokens: map[string]openbao.TokenInfo{"s.original": goodToken(), "s.next": goodToken()}}
	r, _ := newTestReceiver(t, bao, nil)
	return r, bao
}

func installedReceiver(t *testing.T) (*Receiver, *fakeOpenBao) {
	t.Helper()
	r, bao := emptyReceiver(t)
	if _, err := r.Install(context.Background(), strings.NewReader(originalPayload)); err != nil {
		t.Fatal(err)
	}
	return r, bao
}

func TestInstallStagingFailurePreservesLiveGrant(t *testing.T) {
	r, bao := emptyReceiver(t)
	r.Cfg.PushTokenPath = filepath.Join(t.TempDir(), "missing-parent", "push-token")
	withoutPush := strings.Replace(originalPayload, `"push_token":"1900000000 ghp_original",`, "", 1)
	if _, err := r.Install(context.Background(), strings.NewReader(withoutPush)); err != nil {
		t.Fatal(err)
	}
	before := readGrantFiles(t, r)
	_, err := r.Install(context.Background(), strings.NewReader("s.next\n\n1900000000 ghp_abc\n"))
	if err == nil || !strings.Contains(err.Error(), "install did not commit") {
		t.Fatalf("expected a storage failure, got %v", err)
	}
	assertOriginalGrant(t, r, before)
	if len(bao.revoked) != 0 {
		t.Fatal("revoked the working token on failed installation")
	}
	if _, err := r.Install(context.Background(), strings.NewReader("s.next\n\n\n")); err != nil {
		t.Fatal(err)
	}
	if len(bao.revoked) != 1 || bao.revoked[0] != "s.original" {
		t.Fatal("successful replacement did not retire the prior token")
	}
}

func TestInstallRecoveryAtPublicationBoundaries(t *testing.T) {
	for count := 0; count <= 5; count++ {
		t.Run(fmt.Sprintf("after_%d_outputs", count), func(t *testing.T) {
			r, _ := installedReceiver(t)
			before := readGrantFiles(t, r)
			// Simulate the on-disk state on process exit at each publication
			// boundary. The next normal command must recover before inspecting it.
			j, outputs, err := r.prepareInstall([]bool{true, false, true, true, true})
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(j)
			if err := os.WriteFile(filepath.Join(r.Cfg.StateDir, installPending), raw, 0600); err != nil {
				t.Fatal(err)
			}
			if err = r.stageGrant(outputs, "s.next", "", "1900000000 ghp_abc", []Artifact{{Name: "db", Content: "next"}}, 1900000000); err != nil {
				t.Fatal(err)
			}
			for _, out := range outputs[:count] {
				if err = out.publish(); err != nil {
					t.Fatal(err)
				}
			}
			// The sample artifact has a historical expiry; a matching replay
			// of the clock keeps the test about transaction recovery.
			r.Now = func() time.Time { return time.Unix(1600000000, 0) }
			if _, err = r.Status(context.Background()); err != nil {
				t.Fatal(err)
			}
			assertOriginalGrant(t, r, before)
		})
	}
}

func TestInstallPublishFailureRestoresOriginalGrant(t *testing.T) {
	r, _ := installedReceiver(t)
	before := readGrantFiles(t, r)
	j, outputs, err := r.prepareInstall([]bool{false, false, false, true, true})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.stageGrant(outputs, "s.next", "", "", nil, 1900000000); err != nil {
		t.Fatal(err)
	}
	// Force the final filesystem publication to fail after the preceding four
	// outputs have already changed. Exercise the same rollback as Install.
	last := outputs[len(outputs)-1]
	if err := os.Remove(filepath.Join(last.stage, "new")); err != nil {
		t.Fatal(err)
	}
	record := filepath.Join(r.Cfg.StateDir, installPending)
	raw, _ := json.Marshal(j)
	if err := os.WriteFile(record, raw, 0600); err != nil {
		t.Fatal(err)
	}
	for _, out := range outputs[:len(outputs)-1] {
		if err := out.publish(); err != nil {
			t.Fatal(err)
		}
	}
	if err := last.publish(); err == nil {
		t.Fatal("published a missing staged token")
	}
	if err := r.finishInstall(record, outputs, false); err != nil {
		t.Fatal(err)
	}
	assertOriginalGrant(t, r, before)
}

func TestInstallRecoveryWhileRetiringArtifactDirectory(t *testing.T) {
	r, _ := installedReceiver(t)
	before := readGrantFiles(t, r)
	j, outs, err := r.prepareInstall([]bool{false, false, false, true, true})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(j)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.Cfg.StateDir, installPending), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := r.stageGrant(outs, "s.next", "", "", nil, 1900000000); err != nil {
		t.Fatal(err)
	}
	// The process exited after retiring an omitted artifact directory.
	if err := os.Rename(outs[0].path, filepath.Join(outs[0].stage, "old")); err != nil {
		t.Fatal(err)
	}
	if err := r.recoverInstall(); err != nil {
		t.Fatal(err)
	}
	assertOriginalGrant(t, r, before)
	if _, err := os.Stat(filepath.Join(outs[0].path, "new-file")); !os.IsNotExist(err) {
		t.Fatal("part of the staged replacement is visible after rollback")
	}
}

func TestUnavailableMountKeepsRollbackEvidence(t *testing.T) {
	r, _ := installedReceiver(t)
	mount := filepath.Join(t.TempDir(), "workload")
	if err := os.Mkdir(mount, 0700); err != nil {
		t.Fatal(err)
	}
	r.Cfg.SSHCertPath = filepath.Join(mount, "certificate")
	if err := os.WriteFile(r.Cfg.SSHCertPath, []byte("previous"), 0600); err != nil {
		t.Fatal(err)
	}
	before := readGrantFiles(t, r)
	j, outs, err := r.prepareInstall([]bool{false, true, false, true, true})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(j)
	if err := os.WriteFile(filepath.Join(r.Cfg.StateDir, installPending), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := r.stageGrant(outs, "s.next", "replacement", "", nil, 1900000000); err != nil {
		t.Fatal(err)
	}
	if err := outs[1].publish(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(mount, mount+".offline"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(mount, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Status(context.Background()); err == nil {
		t.Fatal("forgot the unavailable mount")
	}
	if err := os.Remove(mount); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(mount+".offline", mount); err != nil {
		t.Fatal(err)
	}
	if err := r.recoverInstall(); err != nil {
		t.Fatal(err)
	}
	assertOriginalGrant(t, r, before)
}

func TestOverlappingGrantPathsRejected(t *testing.T) {
	r, _ := installedReceiver(t)
	before := readGrantFiles(t, r)
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(r.Cfg.StateDir, alias); err != nil {
		t.Fatal(err)
	}
	original := r.Cfg.PushTokenPath
	r.Cfg.PushTokenPath = filepath.Join(alias, "token")
	if _, err := r.Install(context.Background(), strings.NewReader("s.next\n\n\n")); err == nil {
		t.Fatal("accepted colliding token and push token paths")
	}
	r.Cfg.PushTokenPath = original
	assertOriginalGrant(t, r, before)
}

func TestInstallKeepsCommittedGrantOnBackupCleanupFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires a user subject to filesystem permission checks")
	}
	r, bao := installedReceiver(t)
	artifacts := filepath.Join(r.Cfg.StateDir, artifactsDirName)
	protected := filepath.Join(artifacts, "protected")
	if err := os.Mkdir(protected, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(protected, "old"), []byte("example"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(protected, 0500); err != nil {
		t.Fatal(err)
	}
	msg, err := r.Install(context.Background(), strings.NewReader("s.next\n\n\n"))
	if err != nil || !strings.Contains(msg, "cleanup requires retry") {
		t.Fatalf("committed grant should return a cleanup warning: %q, %v", msg, err)
	}
	if token, _, err := r.readTokenFile(); err != nil || token != "s.next" {
		t.Fatal("cleanup failure lost the committed token")
	}
	if len(bao.revoked) != 1 || bao.revoked[0] != "s.original" {
		t.Fatal("failed to retire the replaced token after commit")
	}
	backups, err := filepath.Glob(filepath.Join(r.Cfg.StateDir, ".baobuddy-install-*", "old"))
	if err != nil || len(backups) != 1 {
		t.Fatalf("expected a retained artifact backup: %v, %v", backups, err)
	}
	if _, err := r.Revoke(context.Background()); err == nil || !strings.Contains(err.Error(), "local cleanup failed") {
		t.Fatalf("revoke must report the outstanding backup: %v", err)
	}
	if len(bao.revoked) != 2 || bao.revoked[1] != "s.next" {
		t.Fatal("the backup cleanup failure prevented remote revocation")
	}
	if err := os.Chmod(filepath.Join(backups[0], "protected"), 0700); err != nil {
		t.Fatal(err)
	}
	if msg, err := r.Revoke(context.Background()); err != nil || !strings.Contains(msg, "at OpenBao") {
		t.Fatalf("revoke retry failed: %q %v", msg, err)
	}
	if _, err := os.Stat(filepath.Join(r.Cfg.StateDir, installCommitted)); !os.IsNotExist(err) {
		t.Fatalf("cleanup journal still present: %v", err)
	}
}

func TestInstallPreservesArtifactDirectoryMode(t *testing.T) {
	r, _ := installedReceiver(t)
	dir := filepath.Join(r.Cfg.StateDir, artifactsDirName)
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	r.Cfg.FileMode = 0640
	if _, err := r.Install(context.Background(), strings.NewReader(originalPayload)); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(dir)
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("replacement lost the artifact directory identity or access controls: %v", err)
	}
	for path, want := range map[string]os.FileMode{dir: 0700, filepath.Join(r.Cfg.StateDir, stateFileName): 0600, r.Cfg.TokenPath: 0640} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != want {
			t.Errorf("%s has mode %o, want %o", path, info.Mode().Perm(), want)
		}
	}
}

func TestInstallRejectsInvalidDeliveryParentWithoutPoisoningRetry(t *testing.T) {
	r, _ := installedReceiver(t)
	before := readGrantFiles(t, r)
	parent := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(parent, []byte("unrelated"), 0600); err != nil {
		t.Fatal(err)
	}
	saved := r.Cfg.PushTokenPath
	r.Cfg.PushTokenPath = filepath.Join(parent, "push")
	if _, err := r.Install(context.Background(), strings.NewReader("s.next\n\n1900000000 ghp_abc\n")); err == nil {
		t.Fatal("accepted a non-directory parent")
	}
	r.Cfg.PushTokenPath = saved
	assertOriginalGrant(t, r, before)
	if _, err := r.Install(context.Background(), strings.NewReader("s.next\n\n\n")); err != nil {
		t.Fatal(err)
	}
}

func TestOfflineSecondaryMountBlocksReplacementAndRequiresRevokeRetry(t *testing.T) {
	r, client := emptyReceiver(t)
	mount := filepath.Join(t.TempDir(), "credentials")
	if err := os.Mkdir(mount, 0700); err != nil {
		t.Fatal(err)
	}
	r.Cfg.SSHCertPath = filepath.Join(mount, "cert")
	if _, err := r.Install(context.Background(), strings.NewReader(originalPayload)); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(mount, mount+".offline"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(mount, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(r.Cfg.SSHCertPath, []byte("another directory"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Install(context.Background(), strings.NewReader("s.next\n\n\n")); err == nil || len(client.revoked) != 0 {
		t.Fatalf("replacement overlooked an unavailable SSH credential: %v", err)
	}
	if _, err := r.Revoke(context.Background()); err == nil || len(client.revoked) != 1 {
		t.Fatalf("expected upstream revocation and local cleanup error: %v", err)
	}
	if b, err := os.ReadFile(r.Cfg.SSHCertPath); err != nil || string(b) != "another directory" {
		t.Fatal("modified a file on the wrong mount")
	}
	if err := os.Rename(mount, mount+".other"); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(mount+".offline", mount); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Revoke(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertPathAbsent(t, r.Cfg.SSHCertPath)
}

func TestOfflineTokenMountPreservesOtherCredentials(t *testing.T) {
	r, client := emptyReceiver(t)
	dir := filepath.Join(t.TempDir(), "token-dir")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	r.Cfg.TokenPath = filepath.Join(dir, "token")
	if _, err := r.Install(context.Background(), strings.NewReader(originalPayload)); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(dir, dir+".offline"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Status(context.Background()); err == nil {
		t.Fatal("status should report unavailable token mount")
	}
	if _, err := r.Revoke(context.Background()); err == nil || len(client.revoked) != 0 {
		t.Fatal("revoke should fail while the token mount is unavailable")
	}
	assertPathExists(t, r.Cfg.SSHCertPath)
	assertPathExists(t, r.Cfg.PushTokenPath)
	assertPathExists(t, filepath.Join(r.Cfg.StateDir, stateFileName))
}

func TestRecoverPartiallyUpdatedArtifactDirectory(t *testing.T) {
	r, _ := installedReceiver(t)
	before := readGrantFiles(t, r)
	j, outs, err := r.prepareInstall([]bool{true, false, false, true, true})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(j)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.Cfg.StateDir, installPending), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := r.stageGrant(outs, "s.next", "", "", []Artifact{{Name: "added", Content: "new"}, {Name: "db", Content: "changed"}}, 1900000000); err != nil {
		t.Fatal(err)
	}
	added := grantOutput{path: filepath.Join(outs[0].path, "added"), stage: filepath.Join(outs[0].stage, "items", "added"), present: true}
	if err := added.publishEntry(); err != nil {
		t.Fatal(err)
	}
	if err := r.recoverInstall(); err != nil {
		t.Fatal(err)
	}
	assertOriginalGrant(t, r, before)
	assertPathAbsent(t, added.path)
}
