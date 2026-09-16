package client_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Mic92/niks3/client"
)

type result struct {
	Path    string `json:"path"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

func runStream(t *testing.T, push client.StreamPushFunc, parallel, batch int, feed func(w io.Writer)) []result {
	t.Helper()

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()

	s := client.NewStreamPusher(push, parallel, batch)

	done := make(chan error, 1)

	go func() {
		done <- s.Run(context.Background(), inR, outW)

		_ = outW.Close()
	}()

	go func() {
		feed(inW)

		_ = inW.Close()
	}()

	var results []result

	sc := bufio.NewScanner(outR)
	for sc.Scan() {
		var r result
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatalf("bad output line %q: %v", sc.Text(), err)
		}

		results = append(results, r)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after stdin EOF")
	}

	return results
}

func TestStreamPushReportsEveryPath(t *testing.T) {
	t.Parallel()

	var (
		mu     sync.Mutex
		pushed []string
	)

	push := func(_ context.Context, paths []string) ([]string, error) {
		mu.Lock()
		defer mu.Unlock()

		pushed = append(pushed, paths...)

		return paths, nil
	}

	results := runStream(t, push, 4, 10, func(w io.Writer) {
		_, _ = io.WriteString(w, "/nix/store/a\n\n/nix/store/b\n/nix/store/c\n")
	})

	got := make([]string, 0, len(results))

	for _, r := range results {
		if r.Status != "ok" {
			t.Errorf("path %s: status %s (%s)", r.Path, r.Status, r.Message)
		}

		got = append(got, r.Path)
	}

	slices.Sort(got)
	slices.Sort(pushed)

	want := []string{"/nix/store/a", "/nix/store/b", "/nix/store/c"}
	if !slices.Equal(got, want) {
		t.Errorf("results = %v, want %v", got, want)
	}

	if !slices.Equal(pushed, want) {
		t.Errorf("pushed = %v, want %v", pushed, want)
	}
}

func TestStreamPushBatchesUnderLoad(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})

	var (
		mu      sync.Mutex
		batches [][]string
	)

	push := func(_ context.Context, paths []string) ([]string, error) {
		mu.Lock()

		batches = append(batches, slices.Clone(paths))
		first := len(batches) == 1

		mu.Unlock()

		if first {
			<-release
		}

		return paths, nil
	}

	results := runStream(t, push, 1, 10, func(w io.Writer) {
		_, _ = io.WriteString(w, "/nix/store/first\n")
		time.Sleep(50 * time.Millisecond)

		_, _ = io.WriteString(w, "/nix/store/x\n/nix/store/y\n/nix/store/z\n")

		time.Sleep(50 * time.Millisecond)

		close(release)
	})

	if len(results) != 4 {
		t.Fatalf("got %d results, want 4", len(results))
	}

	mu.Lock()
	defer mu.Unlock()

	if len(batches) != 2 || len(batches[1]) != 3 {
		t.Errorf("batches = %v, want [first] then [x y z]", batches)
	}
}

func TestStreamPushIsolatesFailures(t *testing.T) {
	t.Parallel()

	errBad := errors.New("bad path")

	push := func(_ context.Context, paths []string) ([]string, error) {
		if slices.Contains(paths, "/nix/store/bad") {
			return nil, errBad
		}

		return paths, nil
	}

	results := runStream(t, push, 1, 10, func(w io.Writer) {
		_, _ = io.WriteString(w, "/nix/store/good1\n/nix/store/bad\n/nix/store/good2\n")
	})

	status := map[string]result{}
	for _, r := range results {
		status[r.Path] = r
	}

	for _, p := range []string{"/nix/store/good1", "/nix/store/good2"} {
		if status[p].Status != "ok" {
			t.Errorf("%s: %+v, want ok", p, status[p])
		}
	}

	if bad := status["/nix/store/bad"]; bad.Status != "error" || !strings.Contains(bad.Message, "bad path") {
		t.Errorf("bad: %+v, want error with message", bad)
	}
}

// A driver that keeps stdin open must not keep `niks3 push --stdin` alive
// after SIGTERM; Run has to return with the context's error.
func TestStreamPushStopsWhenCancelled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	inR, inW := io.Pipe() // never closed, like a driver that is still running

	var (
		started sync.Once
		pushing = make(chan struct{})
	)

	push := func(ctx context.Context, _ []string) ([]string, error) { //nolint:unparam // StreamPushFunc signature
		started.Do(func() { close(pushing) })

		<-ctx.Done()

		return nil, ctx.Err()
	}

	var out safeBuffer

	done := make(chan error, 1)

	go func() {
		done <- client.NewStreamPusher(push, 1, 10).Run(ctx, inR, &out)
	}()

	_, _ = io.WriteString(inW, "/nix/store/a\n/nix/store/b\n")

	<-pushing

	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run returned %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}

	var reported []result

	for line := range strings.SplitSeq(strings.TrimSpace(out.String()), "\n") {
		if line == "" {
			continue
		}

		var r result
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("bad output line %q: %v", line, err)
		}

		reported = append(reported, r)
	}

	for _, r := range reported {
		if r.Status != "error" {
			t.Errorf("%s: status %s, want error after cancellation", r.Path, r.Status)
		}
	}
}

type safeBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	n, _ := s.b.Write(p) // strings.Builder never fails

	return n, nil
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.b.String()
}

func TestStreamPushGivesUpOnDeadServer(t *testing.T) {
	t.Parallel()

	errDown := errors.New("connection refused")

	var calls int

	push := func(_ context.Context, _ []string) ([]string, error) {
		calls++

		return nil, errDown
	}

	var sb strings.Builder
	for i := range 20 {
		sb.WriteString("/nix/store/p" + string(rune('a'+i)) + "\n")
	}

	results := runStream(t, push, 1, 50, func(w io.Writer) {
		_, _ = io.WriteString(w, sb.String())
	})

	if len(results) != 20 {
		t.Fatalf("got %d results, want 20", len(results))
	}

	for _, r := range results {
		if r.Status != "error" {
			t.Errorf("%s: status %s, want error", r.Path, r.Status)
		}
	}

	if calls > 1+3 {
		t.Errorf("push called %d times, want <= 4", calls)
	}
}
