package receiver

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// The SSH client accepts at most 64 KiB including the CLI newline.
const maxTaskOutput = 64 * 1024
const tasksUnavailable = "! task check unavailable"

func (r *Receiver) Tasks(ctx context.Context) string {
	if len(r.Cfg.TasksCommand) == 0 {
		return ""
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, r.Cfg.TasksCommand[0], r.Cfg.TasksCommand[1:]...)
	cmd.WaitDelay = 250 * time.Millisecond
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	read, write, err := os.Pipe()
	if err != nil {
		return tasksUnavailable
	}
	defer read.Close()
	cmd.Stdout = write
	// Close our read end too, even if a detached descendant still holds stdout.
	cmd.Cancel = func() error {
		read.Close()
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	err = cmd.Start()
	write.Close()
	if err != nil {
		return tasksUnavailable
	}
	out, readErr := io.ReadAll(io.LimitReader(read, maxTaskOutput+1))
	overLimit := len(out) > maxTaskOutput
	if overLimit {
		_ = cmd.Cancel()
		cancel()
	}
	waitErr := cmd.Wait()
	if readErr != nil || overLimit || waitErr != nil || ctx.Err() != nil {
		return tasksUnavailable
	}
	result := strings.TrimSpace(string(out))
	if len(result)+1 > maxTaskOutput {
		return tasksUnavailable
	}
	return result
}
