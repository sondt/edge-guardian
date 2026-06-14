package ingest

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTailer_FollowsAppends(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	if err := os.WriteFile(path, []byte("first\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tailer := New([]string{path})
	lines, err := tailer.Run(ctx)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	time.Sleep(150 * time.Millisecond)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("second\n")
	_ = f.Close()

	got := map[string]bool{}
	timeout := time.After(3 * time.Second)
	for !got["second"] {
		select {
		case ln := <-lines:
			got[ln.Text] = true
			if ln.Source != path {
				t.Fatalf("source=%q want %q", ln.Source, path)
			}
		case <-timeout:
			t.Fatalf("did not receive appended line 'second'; got=%v", got)
		}
	}
}

func TestTailer_ChannelClosesOnCancel(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.log")
	_ = os.WriteFile(path, nil, 0o644)

	ctx, cancel := context.WithCancel(context.Background())
	tailer := New([]string{path})
	lines, err := tailer.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}

	cancel()
	timeout := time.After(3 * time.Second)
	for {
		select {
		case _, ok := <-lines:
			if !ok {
				return // channel closed as expected
			}
		case <-timeout:
			t.Fatal("channel did not close after cancel")
		}
	}
}
