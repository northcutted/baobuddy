package receiver

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/northcutted/baobuddy/receiver/internal/config"
)

func TestTaskCheckerOutputLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tasks")
	r := New(config.Config{TasksCommand: []string{"cat", path}}, nil, nil)
	for _, n := range []int{16, maxTaskOutput - 1, maxTaskOutput} {
		input := strings.Repeat("a", n)
		if err := os.WriteFile(path, []byte(input+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		want := input
		if n+1 > maxTaskOutput {
			want = tasksUnavailable
		}
		if got := r.Tasks(context.Background()); got != want {
			t.Fatalf("unexpected result for %d bytes", n+1)
		}
	}
}

func TestTaskCheckerDeadlineWithInheritedStdout(t *testing.T) {
	r := New(config.Config{TasksCommand: []string{"sh", "-c", "sleep 4 & exit 0"}}, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if got := r.Tasks(ctx); got != tasksUnavailable {
		t.Errorf("expected unavailable, got %q", got)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("inherited stdout blocked for %s", elapsed)
	}
}
