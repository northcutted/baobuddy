package otel

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestLocalSinkFailuresAreReported(t *testing.T) {
	dir := t.TempDir()
	audit := filepath.Join(dir, "private-audit-path")
	if err := syscall.Mkfifo(audit, 0600); err != nil {
		t.Fatal(err)
	}
	metrics := filepath.Join(dir, "metrics.prom")
	if err := os.Mkdir(metrics, 0700); err != nil {
		t.Fatal(err)
	}
	e := NewExporter("", nil, "fixture", audit, metrics)
	if err := e.CheckLocalSinks(); err == nil || !strings.Contains(err.Error(), "audit_log_path") || !strings.Contains(err.Error(), "metrics_file_path") {
		t.Fatalf("missing sink diagnostics: %v", err)
	}
	result := make(chan error, 1)
	go func() { result <- e.Emit(context.Background(), Event{Action: "install", Outcome: "ok"}) }()
	select {
	case err := <-result:
		if err == nil || !strings.Contains(err.Error(), "audit log") || strings.Contains(err.Error(), audit) {
			t.Fatalf("unsafe or missing audit warning: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("audit FIFO blocked the grant")
	}
	if err := e.WritePrometheusState(true, 60, false, false); err == nil {
		t.Fatal("reported successful metrics publication to a directory")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 2 {
		t.Fatalf("unexpected remnants: %v %v", entries, err)
	}
}
