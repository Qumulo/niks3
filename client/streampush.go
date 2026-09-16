package client

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
)

const (
	DefaultStreamBatchSize = 50
	// DefaultStreamParallel bounds pushes in flight. Each has its own NAR
	// upload pool; a few in parallel keep closure setup of the next batch
	// off the critical path.
	DefaultStreamParallel = 4
	// Single-path retries of a failed batch before the server is blamed.
	streamIsolationProbes = 3

	streamStatusOK    = "ok"
	streamStatusError = "error"
)

type StreamPushFunc func(ctx context.Context, paths []string) ([]string, error)

type StreamResult struct {
	Path    string `json:"path"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

// StreamPusher pushes store paths read line by line from a reader as they
// arrive and writes one JSON StreamResult per input path, so a long-running
// CI driver learns per path when it is cached. While all `parallel` pushes
// are busy, incoming paths accumulate into one batch of up to `batchSize`.
type StreamPusher struct {
	push      StreamPushFunc
	parallel  int
	batchSize int
}

func NewStreamPusher(push StreamPushFunc, parallel, batchSize int) *StreamPusher {
	if parallel < 1 {
		parallel = 1
	}

	if batchSize < 1 {
		batchSize = DefaultStreamBatchSize
	}

	return &StreamPusher{push: push, parallel: parallel, batchSize: batchSize}
}

// Run returns after EOF on `in` once every path was reported on `out`, or
// as soon as ctx ends, with ctx.Err(). In the latter case paths still in
// flight are reported as errors and paths not yet read are left
// unreported; the error tells the driver the run was cut short. A reader
// blocked in `in` cannot be interrupted and is abandoned to process exit.
func (s *StreamPusher) Run(ctx context.Context, in io.Reader, out io.Writer) error {
	lines := make(chan string, s.batchSize*s.parallel)
	readErr := make(chan error, 1)

	go func() {
		defer close(lines)

		sc := bufio.NewScanner(in)
		for sc.Scan() {
			p := strings.TrimSpace(sc.Text())
			if p == "" {
				continue
			}

			select {
			case lines <- p:
			case <-ctx.Done():
				return
			}
		}

		readErr <- sc.Err()
	}()

	var (
		outMu sync.Mutex
		wg    sync.WaitGroup
	)

	enc := json.NewEncoder(out)
	report := func(results []StreamResult) {
		outMu.Lock()
		defer outMu.Unlock()

		for _, r := range results {
			if err := enc.Encode(r); err != nil {
				slog.Error("Failed to write result", "error", err)
			}
		}
	}

	slots := make(chan struct{}, s.parallel)

loop:
	for {
		var (
			first string
			ok    bool
		)

		select {
		case first, ok = <-lines:
			if !ok {
				break loop
			}
		case <-ctx.Done():
			break loop
		}

		batch := append(make([]string, 0, s.batchSize), first)

		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			break loop
		}

	fill:
		for len(batch) < s.batchSize {
			select {
			case p, ok := <-lines:
				if !ok {
					break fill
				}

				batch = append(batch, p)
			default:
				break fill
			}
		}

		wg.Go(func() {
			defer func() { <-slots }()

			report(s.upload(ctx, batch))
		})
	}

	wg.Wait()

	if err := ctx.Err(); err != nil {
		return fmt.Errorf("stopped before stdin ended: %w", err)
	}

	if err := <-readErr; err != nil {
		return fmt.Errorf("reading paths: %w", err)
	}

	return nil
}

// A failed batch is retried path by path so one bad path only costs itself.
func (s *StreamPusher) upload(ctx context.Context, batch []string) []StreamResult {
	results := make([]StreamResult, 0, len(batch))

	_, err := s.push(ctx, batch)
	if err == nil {
		for _, p := range batch {
			results = append(results, StreamResult{Path: p, Status: streamStatusOK})
		}

		return results
	}

	slog.Error("Upload failed", "error", err, "count", len(batch))

	fail := func(paths []string, err error) {
		for _, p := range paths {
			results = append(results, StreamResult{Path: p, Status: streamStatusError, Message: err.Error()})
		}
	}

	if len(batch) == 1 || ctx.Err() != nil {
		fail(batch, err)

		return results
	}

	succeeded, failures := 0, 0

	for i, p := range batch {
		if succeeded == 0 && failures >= streamIsolationProbes {
			slog.Error("Server seems unavailable, giving up on batch", "untried", len(batch)-i)
			fail(batch[i:], err)

			break
		}

		if _, perr := s.push(ctx, []string{p}); perr != nil {
			fail([]string{p}, perr)

			failures++

			continue
		}

		results = append(results, StreamResult{Path: p, Status: streamStatusOK})
		succeeded++
	}

	return results
}
