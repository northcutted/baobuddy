package receiver

import (
	"fmt"
	"os"
	"path/filepath"
)

// A grant can deliver files outside the receiver's state directory. Keep track
// of the mounted directory that actually received each file. An empty directory
// at the same path while the mount is away must not count as successful cleanup.
type deliveryParent struct {
	Path string `json:"path"`
	ID   fileID `json:"id"`
}

type deliveryParents struct {
	Token *deliveryParent `json:"token,omitempty"`
	SSH   *deliveryParent `json:"ssh,omitempty"`
	Push  *deliveryParent `json:"push,omitempty"`
}

func (out grantOutput) deliveryParent(stateDir string) *deliveryParent {
	if !out.present {
		return nil
	}
	d := &deliveryParent{Path: out.path}
	if filepath.Clean(filepath.Dir(out.path)) != filepath.Clean(stateDir) {
		d.ID = out.record.Parent
	}
	return d
}

func (d *deliveryParent) check(path string) error {
	if d == nil {
		return nil
	}
	if d.Path != path {
		return fmt.Errorf("grant delivery path changed from %q to %q", d.Path, path)
	}
	if d.ID == (fileID{}) {
		return nil // delivery and control record share their parent
	}
	fi, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return err
	}
	if identity(fi) != d.ID {
		return fmt.Errorf("restore the original grant delivery directory for %s before retrying", path)
	}
	return nil
}

func (d *deliveryParent) remove(path string) error {
	if err := d.check(path); err != nil {
		return err
	}
	return removeRegularFile(path)
}

func (d *deliveryParent) readSecondary(path string) (string, bool, error) {
	if err := d.check(path); err != nil {
		return "", true, err
	}
	return readOptionalRegularTrimmedFile(path, maxSecondaryFileBytes)
}

type grantFiles struct {
	*Receiver
	parents   deliveryParents
	backupErr error
}

func (f grantFiles) token() (string, bool, error) {
	if err := f.parents.Token.check(f.Cfg.TokenPath); err != nil {
		return "", true, err
	}
	return f.readTokenFile()
}
