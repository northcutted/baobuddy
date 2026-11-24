// Grant files can have different parent directories and live on different mounts.
// Stage each output next to its destination, and keep its original in that
// private directory until the token and the rest of the grant have committed.
package receiver

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const installPending = ".install-pending"
const installCommitted = ".install-cleanup"

// Directory identities distinguish a missing entry from a different mount or
// service namespace. Recovery may delete only staging directories we created.
type fileID struct {
	Device uint64
	Inode  uint64
}

func identity(info os.FileInfo) fileID {
	st := info.Sys().(*syscall.Stat_t)
	return fileID{uint64(st.Dev), uint64(st.Ino)}
}

type stageRecord struct {
	Name          string
	Parent        fileID
	Directory     fileID
	LiveDirectory *fileID `json:",omitempty"`
}
type installJournal struct {
	PathHash string
	Stages   []*stageRecord
}
type grantOutput struct {
	path    string
	stage   string
	record  *stageRecord
	present bool
}

// The control record and token are published last. The same order is used for recovery.
func (r *Receiver) installPaths() []string {
	return []string{filepath.Join(r.Cfg.StateDir, artifactsDirName), r.Cfg.SSHCertPath,
		r.Cfg.PushTokenPath, filepath.Join(r.Cfg.StateDir, stateFileName), r.Cfg.TokenPath}
}

func installPathHash(paths []string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join(paths, "\x00"))))
}

func (r *Receiver) outputs(j installJournal) ([]grantOutput, error) {
	paths := r.installPaths()
	if j.PathHash != installPathHash(paths) || len(j.Stages) != len(paths) {
		return nil, errors.New("invalid install journal or changed grant paths; restore the original configuration before recovery")
	}
	outputs := make([]grantOutput, len(paths))
	for i, p := range paths {
		out := grantOutput{path: p, record: j.Stages[i]}
		if rec := out.record; rec != nil {
			if !strings.HasPrefix(rec.Name, ".baobuddy-install-") || filepath.Base(rec.Name) != rec.Name {
				return nil, errors.New("invalid staging directory in grant journal")
			}
			out.stage = filepath.Join(filepath.Dir(p), rec.Name)
		}
		outputs[i] = out
	}
	return outputs, nil
}

func (r *Receiver) prepareInstall(present []bool) (installJournal, []grantOutput, error) {
	paths := r.installPaths()
	j := installJournal{PathHash: installPathHash(paths), Stages: make([]*stageRecord, len(paths))}
	outputs, err := r.outputs(j)
	if err != nil {
		return j, nil, err
	}
	for i := range outputs {
		out := &outputs[i]
		out.present = present[i]
		info, err := os.Lstat(out.path)
		if err == nil && ((i == 0 && !info.IsDir()) || (i != 0 && !info.Mode().IsRegular())) {
			return j, outputs, fmt.Errorf("unexpected file type at grant destination %q", out.path)
		}
		if errors.Is(err, os.ErrNotExist) && !out.present {
			continue
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return j, outputs, err
		}
		parent := filepath.Dir(out.path)
		parentInfo, err := os.Stat(parent)
		if err != nil {
			return j, outputs, err
		}
		if err := verifyControlFileOwner(parentInfo); err != nil {
			return j, outputs, fmt.Errorf("untrusted grant delivery directory %q: %w", parent, err)
		}
		if i == 0 && info != nil && out.present {
			if err := verifyControlFileOwner(info); err != nil {
				return j, outputs, fmt.Errorf("untrusted artifact directory: %w", err)
			}
		}
		// Before the journal is durable these private directories are empty.
		dir, err := os.MkdirTemp(parent, ".baobuddy-install-")
		if err != nil {
			return j, outputs, err
		}
		fi, err := os.Lstat(dir)
		if err != nil {
			return j, outputs, errors.Join(err, os.Remove(dir))
		}
		rec := &stageRecord{Name: filepath.Base(dir), Parent: identity(parentInfo), Directory: identity(fi)}
		if i == 0 && info != nil && out.present {
			liveID := identity(info)
			rec.LiveDirectory = &liveID
		}
		j.Stages[i] = rec
		out.record = rec
		out.stage = dir
	}
	return j, outputs, nil
}

func (out grantOutput) checkStage(allowRemoved bool) error {
	if out.record == nil {
		return nil
	}
	parent, err := os.Stat(filepath.Dir(out.path))
	if err != nil {
		return err
	}
	if identity(parent) != out.record.Parent {
		return fmt.Errorf("grant destination parent changed: %s", out.path)
	}
	info, err := os.Lstat(out.stage)
	if allowRemoved && errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || identity(info) != out.record.Directory {
		return fmt.Errorf("grant staging directory changed: %s", out.stage)
	}
	return nil
}

func discardStages(outputs []grantOutput) error {
	var result error
	for _, out := range outputs {
		if out.record == nil {
			continue
		}
		err := out.checkStage(true)
		if err == nil {
			err = os.RemoveAll(out.stage)
		}
		result = errors.Join(result, err)
	}
	return result
}

// Resolve an existing parent (including a symlinked mount). Missing optional
// or inaccessible parents still get a lexical path for collision checking.
// Each credential operation separately reports errors opening its own parent.
func canonicalDirectory(path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err == nil {
		return resolved, nil
	}
	if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, os.ErrPermission) && !errors.Is(err, syscall.ENOTDIR) {
		return "", err
	}
	parent := filepath.Dir(path)
	if parent == path {
		return "", err
	}
	resolved, err = canonicalDirectory(parent)
	if err != nil {
		return "", err
	}
	return filepath.Join(resolved, filepath.Base(path)), nil
}

func (r *Receiver) checkGrantPaths() error {
	if r.Cfg.TokenPath == filepath.Join(r.Cfg.StateDir, "token") && r.Cfg.SSHCertPath == filepath.Join(r.Cfg.StateDir, "ssh-cert.pub") && r.Cfg.PushTokenPath == filepath.Join(r.Cfg.StateDir, "push-token") {
		return nil
	}
	paths := append(r.installPaths(), filepath.Join(r.Cfg.StateDir, lockFileName), filepath.Join(r.Cfg.StateDir, installPending), filepath.Join(r.Cfg.StateDir, installCommitted))
	var seen []string
	for _, p := range paths {
		abs, err := filepath.Abs(p)
		if err != nil {
			return err
		}
		parent, err := canonicalDirectory(filepath.Dir(abs))
		if err != nil {
			return err
		}
		// Store outputs must be distinguishable on case-insensitive volumes too.
		key := strings.ToLower(filepath.Join(parent, filepath.Base(abs)))
		for _, other := range seen {
			if key == "/" || other == "/" || key == other || strings.HasPrefix(key, other+"/") || strings.HasPrefix(other, key+"/") {
				return fmt.Errorf("overlapping receiver paths at %q", p)
			}
		}
		seen = append(seen, key)
	}
	return nil
}

// Returns separate cleanup and installation errors. Once the journal is committed,
// a failure deleting backups must never tell the approving device to revoke the new grant.
func (r *Receiver) writeGrantFiles(token, sshCert, pushToken string, artifacts []Artifact, expiry int64) (cleanupErr, installErr error) {
	j, outputs, err := r.prepareInstall([]bool{len(artifacts) > 0, sshCert != "", pushToken != "", true, true})
	if err != nil {
		return nil, errors.Join(err, discardStages(outputs))
	}
	pending := filepath.Join(r.Cfg.StateDir, installPending)
	committed := filepath.Join(r.Cfg.StateDir, installCommitted)
	// Publish complete journal metadata before creating any credential backup.
	tmp, err := os.CreateTemp(r.Cfg.StateDir, ".install-record-*")
	if err != nil {
		return nil, errors.Join(err, discardStages(outputs))
	}
	defer os.Remove(tmp.Name())
	err = json.NewEncoder(tmp).Encode(j)
	if err == nil {
		err = tmp.Sync()
	}
	err = errors.Join(err, tmp.Close())
	if err != nil {
		return nil, errors.Join(err, discardStages(outputs))
	}
	if err = os.Rename(tmp.Name(), pending); err != nil {
		return nil, errors.Join(err, discardStages(outputs))
	}

	err = r.stageGrant(outputs, token, sshCert, pushToken, artifacts, expiry)
	if err == nil {
		for _, out := range outputs {
			if err = out.publish(); err != nil {
				break
			}
		}
	}
	if err == nil {
		err = os.Rename(pending, committed)
	}
	if err != nil {
		return nil, errors.Join(err, r.finishInstall(pending, outputs, false))
	}
	return r.finishInstall(committed, outputs, true), nil
}

func (r *Receiver) stageGrant(outputs []grantOutput, token, cert, push string, artifacts []Artifact, expiry int64) error {
	state := grantState{TokenExpiresAt: expiry, Parents: deliveryParents{
		Token: outputs[4].deliveryParent(r.Cfg.StateDir),
		SSH:   outputs[1].deliveryParent(r.Cfg.StateDir),
		Push:  outputs[2].deliveryParent(r.Cfg.StateDir),
	}}
	if len(artifacts) > 0 {
		out := outputs[0]
		dir := filepath.Join(out.stage, "new")
		keepDirectory := out.record.LiveDirectory != nil
		if keepDirectory {
			dir = filepath.Join(out.stage, "items")
		}
		if err := os.Mkdir(dir, 0700); err != nil {
			return err
		}
		if keepDirectory {
			entries, err := os.ReadDir(out.path)
			if err != nil {
				return err
			}
			for _, entry := range entries {
				if err := os.Mkdir(filepath.Join(dir, entry.Name()), 0700); err != nil {
					return err
				}
			}
		} else {
			if gid := r.Cfg.FileOwnerGID; gid > 0 {
				if err := os.Chown(dir, -1, gid); err != nil {
					return err
				}
			}
			if err := os.Chmod(dir, 0750); err != nil {
				return err
			}
		}
		for _, a := range artifacts {
			dest := filepath.Join(dir, a.Name)
			if keepDirectory {
				if err := os.MkdirAll(dest, 0700); err != nil {
					return err
				}
				dest = filepath.Join(dest, "new")
			}
			if err := r.writeAtomic(dest, a.Content); err != nil {
				return err
			}
			if a.ExpiresAt > 0 {
				if state.ArtifactExpiresAt == nil {
					state.ArtifactExpiresAt = make(map[string]int64)
				}
				state.ArtifactExpiresAt[a.Name] = min(expiry, a.ExpiresAt)
			}
		}
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if err := r.writePrivateAtomic(filepath.Join(outputs[3].stage, "new"), string(raw)+"\n"); err != nil {
		return err
	}
	for i, content := range []string{cert, push, "", token} {
		if content != "" {
			if err := r.writeAtomic(filepath.Join(outputs[i+1].stage, "new"), content+"\n"); err != nil {
				return err
			}
		}
	}
	return nil
}

// 'old' and 'absent' are undo records. Rename within the destination filesystem
// preserves the original bytes, ownership and mode, including for directories.
func (out grantOutput) publish() error {
	if out.record == nil {
		return nil
	}
	if out.record.LiveDirectory != nil {
		return out.updateArtifactEntries(false)
	}
	return out.publishEntry()
}

// An existing artifacts directory may carry workload-specific ownership or ACLs.
// Leave its inode in place and journal the immediate children individually.
func (out grantOutput) updateArtifactEntries(rollback bool) error {
	live, err := os.Lstat(out.path)
	if err != nil {
		return err
	}
	if !live.IsDir() || identity(live) != *out.record.LiveDirectory {
		return fmt.Errorf("artifact directory changed during installation: %s", out.path)
	}
	items := filepath.Join(out.stage, "items")
	entries, err := os.ReadDir(items)
	if rollback && errors.Is(err, os.ErrNotExist) {
		return nil // interrupted before staging started
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			return fmt.Errorf("invalid staged artifact entry %q", entry.Name())
		}
		child := grantOutput{path: filepath.Join(out.path, entry.Name()), stage: filepath.Join(items, entry.Name())}
		if rollback {
			err = child.undoEntry()
		} else {
			child.present, err = exists(filepath.Join(child.stage, "new"))
			if err == nil {
				err = child.publishEntry()
			}
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (out grantOutput) publishEntry() error {
	next := filepath.Join(out.stage, "new")
	old := filepath.Join(out.stage, "old")
	info, err := os.Lstat(out.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		err = os.Mkdir(filepath.Join(out.stage, "absent"), 0700)
	case err != nil:
		return err
	case out.present && info.Mode().IsRegular():
		// Preserve the original inode without creating a gap in the public path.
		err = os.Link(out.path, old)
	default:
		err = os.Rename(out.path, old)
	}
	if err != nil || !out.present {
		return err
	}
	return os.Rename(next, out.path)
}

func exists(path string) (bool, error) {
	_, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

func (out grantOutput) undo() error {
	if out.record.LiveDirectory != nil {
		return out.updateArtifactEntries(true)
	}
	return out.undoEntry()
}

func (out grantOutput) undoEntry() error {
	old := filepath.Join(out.stage, "old")
	original, err := os.Lstat(old)
	hadOld := err == nil
	if errors.Is(err, os.ErrNotExist) {
		err = nil
	}
	if err != nil {
		return err
	}
	if !hadOld {
		absent, err := exists(filepath.Join(out.stage, "absent"))
		if err != nil || !absent {
			return err
		}
	}
	// If a new entry reached the live path, move it aside before restoring the
	// original. Recovery can repeat after either rename without losing the backup.
	live, err := os.Lstat(out.path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err == nil {
		if hadOld && original.Mode().IsRegular() && live.Mode().IsRegular() {
			if os.SameFile(original, live) {
				return nil
			}
			return os.Rename(old, out.path)
		}
		next := filepath.Join(out.stage, "new")
		staged, err := exists(next)
		if err != nil {
			return err
		}
		if staged {
			return fmt.Errorf("grant destination changed during rollback: %s", out.path)
		}
		if err := os.Rename(out.path, next); err != nil {
			return err
		}
	}
	if hadOld {
		return os.Rename(old, out.path)
	}
	return nil
}

func (r *Receiver) finishInstall(record string, outputs []grantOutput, committed bool) error {
	if !committed {
		for _, out := range outputs {
			if err := out.checkStage(false); err != nil {
				return err
			}
		}
		var rollback error
		for i := len(outputs) - 1; i >= 0; i-- {
			if outputs[i].record != nil {
				rollback = errors.Join(rollback, outputs[i].undo())
			}
		}
		if rollback != nil {
			return fmt.Errorf("rollback incomplete; retained install journal: %w", rollback)
		}
		// Rollback is complete. A crash during backup disposal must resume only
		// disposal; the backups may no longer all exist.
		cleanup := filepath.Join(r.Cfg.StateDir, installCommitted)
		if err := os.Rename(record, cleanup); err != nil {
			return err
		}
		record = cleanup
	}
	if err := discardStages(outputs); err != nil {
		return err
	}
	return os.Remove(record)
}

// An already committed journal contains only backup disposal work. Let status
// and revoke use the committed grant while still reporting that cleanup failed.
type backupCleanupError struct{ error }

// Called with the exclusive receiver lock, before anyone observes or modifies state.
func (r *Receiver) recoverInstall() error {
	for _, name := range []string{installPending, installCommitted} {
		path := filepath.Join(r.Cfg.StateDir, name)
		raw, fi, found, err := readRegularFileInfo(path, 16384)
		if err != nil {
			return err
		}
		if !found {
			continue
		}
		if err := verifyControlFileOwner(fi); err != nil {
			return err
		}
		if name == installPending {
			extra, err := exists(filepath.Join(r.Cfg.StateDir, installCommitted))
			if err != nil {
				return err
			}
			if extra {
				return errors.New("conflicting install journals; inspect the state directory before recovery")
			}
		}
		var j installJournal
		if err = json.Unmarshal(raw, &j); err != nil {
			return err
		}
		outputs, err := r.outputs(j)
		if err != nil {
			return err
		}
		if err := r.finishInstall(path, outputs, name == installCommitted); err != nil {
			if name == installCommitted {
				return &backupCleanupError{fmt.Errorf("remove previous install backups: %w", err)}
			}
			return err
		}
	}
	return nil
}
