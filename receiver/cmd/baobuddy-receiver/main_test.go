package main

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/northcutted/baobuddy/receiver/internal/config"
	"github.com/northcutted/baobuddy/receiver/internal/receiver"
)

func TestStalledInstallStopsAtInputDeadline(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close()
	if _, err := write.WriteString("s.partial"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	r := receiver.New(config.Config{StateDir: t.TempDir()}, nil, nil)
	done := make(chan error, 1)
	go func() { _, err := installFromStdin(ctx, r, read); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expected deadline, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("stalled pipe kept the command alive")
	}
}
