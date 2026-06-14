// Package ingest tails multiple log files (handling log rotation) and pushes each new
// line to a shared channel.
package ingest

import (
	"context"
	"fmt"
	"io"
	"sync"

	"github.com/nxadm/tail"
)

// Line is a log line together with its origin.
type Line struct {
	Source string
	Text   string
}

// Tailer follows a set of log files.
type Tailer struct {
	paths []string
}

// New creates a Tailer for the given paths.
func New(paths []string) *Tailer {
	cp := make([]string, len(paths))
	copy(cp, paths)
	return &Tailer{paths: cp}
}

// Run starts tailing every file, sending new lines into the returned channel until ctx is canceled.
// Each file runs in its own goroutine. The channel is closed when every tailer stops.
func (t *Tailer) Run(ctx context.Context) (<-chan Line, error) {
	out := make(chan Line, 1024)

	tails := make([]*tail.Tail, 0, len(t.paths))
	for _, p := range t.paths {
		tl, err := tail.TailFile(p, tail.Config{
			Follow: true,
			ReOpen: true, // follow rotation
			// Start at the END of the file: only process NEW lines. This avoids the daemon,
			// on startup/restart, rescanning the entire historical log and mass-banning old
			// IPs (each match is timestamped "now" when read). After rotation, the new file
			// is read from the beginning so no lines are missed.
			Location:  &tail.SeekInfo{Offset: 0, Whence: io.SeekEnd},
			MustExist: false,
			Logger:    tail.DiscardingLogger,
		})
		if err != nil {
			for _, opened := range tails {
				_ = opened.Stop()
			}
			return nil, fmt.Errorf("tail %q: %w", p, err)
		}
		tails = append(tails, tl)
	}

	var wg sync.WaitGroup
	for _, tl := range tails {
		wg.Add(1)
		go func(tl *tail.Tail) {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case ln, ok := <-tl.Lines:
					if !ok {
						return
					}
					if ln.Err != nil {
						continue
					}
					select {
					case out <- Line{Source: tl.Filename, Text: ln.Text}:
					case <-ctx.Done():
						return
					}
				}
			}
		}(tl)
	}

	// Cleanup: when ctx is canceled, stop every tailer then close the channel.
	go func() {
		<-ctx.Done()
		for _, tl := range tails {
			_ = tl.Stop()
		}
	}()
	go func() {
		wg.Wait()
		close(out)
	}()

	return out, nil
}
