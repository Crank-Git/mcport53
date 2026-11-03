package mcp

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Crank-Git/mcport53/internal/codec"
	"github.com/Crank-Git/mcport53/internal/dns"
	"github.com/Crank-Git/mcport53/internal/testresolver"
)

// delayedTool returns text after d (or fails with failMsg) and counts runs.
func delayedTool(name string, d time.Duration, text, failMsg string, runs *atomic.Int64) *Tool {
	return &Tool{Name: name, Call: func(ctx context.Context, _ []byte) (*codec.Envelope, error) {
		if runs != nil {
			runs.Add(1)
		}
		select {
		case <-time.After(d):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if failMsg != "" {
			return nil, errors.New(failMsg)
		}
		re, _ := codec.JSONResult(map[string]string{"text": text})
		return codec.OK(name, re, 0), nil
	}}
}

func jobRegistry(t *testing.T, tools ...*Tool) *Registry {
	t.Helper()
	r := NewRegistry()
	for _, tool := range tools {
		if err := r.Register(tool); err != nil {
			t.Fatal(err)
		}
	}
	return r
}

func TestFastToolAnsweredInline(t *testing.T) {
	srv := NewServer(jobRegistry(t, delayedTool("fast", 0, "hi", "", nil))).WithInlineBudget(time.Second)
	e := srv.Handlers().OnCall(&dns.CallRequest{Tool: "fast"})
	if e.Status != codec.StatusOK || srv.jobs.len() != 0 {
		t.Fatalf("fast tool: %+v, %d jobs", e, srv.jobs.len())
	}
}

// TestJobLifecycle drives queued -> running -> done through the handlers.
func TestJobLifecycle(t *testing.T) {
	srv := NewServer(jobRegistry(t, delayedTool("slow", 300*time.Millisecond, "late", "", nil))).WithInlineBudget(50 * time.Millisecond)
	h := srv.Handlers()
	start := time.Now()
	q := h.OnCall(&dns.CallRequest{Tool: "slow"})
	if q.Status != codec.StatusQueued || q.Job == "" || time.Since(start) > 250*time.Millisecond {
		t.Fatalf("call: %+v after %v, want queued at the 50ms budget", q, time.Since(start))
	}
	if e := h.OnJob(q.Job); e.Status != codec.StatusRunning || e.Job != q.Job || e.Tool != "slow" {
		t.Fatalf("poll while running: %+v", e)
	}
	deadline := time.Now().Add(3 * time.Second)
	var done *codec.Envelope
	for time.Now().Before(deadline) {
		if done = h.OnJob(q.Job); done.Status != codec.StatusRunning {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if done.Status != codec.StatusDone || done.Session == "" || done.Total != 1 {
		t.Fatalf("finished poll: %+v", done)
	}
	chunk := h.OnChunk(&dns.ChunkRequest{Session: done.Session})
	raw, _ := base64.StdEncoding.DecodeString(chunk.Result)
	if !strings.Contains(string(raw), "late") {
		t.Fatalf("job result chunk: %q", raw)
	}
	if e := h.OnJob("nope"); e.Status != codec.StatusError || !strings.Contains(e.Error, "unknown") {
		t.Fatalf("unknown job: %+v", e)
	}
}

// TestJobResultsMatchDirect checks an agent gets the same result through a
// job as from an inline call, for small, chunked and compressed results and
// cursor mode, over a real socket.
func TestJobResultsMatchDirect(t *testing.T) {
	random := make([]byte, 5000)
	_, _ = rand.Read(random)
	texts := map[string]string{
		"small":          "small result",
		"incompressible": base64.StdEncoding.EncodeToString(random),
		"compressible":   strings.Repeat("compress me ", 1500),
	}
	for name, text := range texts {
		for _, compress := range []bool{false, true} {
			for _, cursor := range []bool{false, true} {
				t.Run(name+map[bool]string{true: "/gzip", false: ""}[compress]+map[bool]string{true: "/cursor", false: ""}[cursor], func(t *testing.T) {
					reg := jobRegistry(t, delayedTool("slow", 200*time.Millisecond, text, "", nil))
					agent := startAgentServerConfig(t, reg, func(s *Server) *Server {
						s = s.WithInlineBudget(30 * time.Millisecond)
						if compress {
							s = s.WithCompression()
						}
						if cursor {
							s = s.WithCursorPagination()
						}
						return s
					})
					re, err := agent.Call(context.Background(), "slow", []byte(`{}`))
					if err != nil {
						t.Fatal(err)
					}
					if got := jsonText(t, re); got != text {
						t.Fatalf("job result differs (%d vs %d bytes)", len(got), len(text))
					}
				})
			}
		}
	}
}

func TestJobFailureIsError(t *testing.T) {
	reg := jobRegistry(t, delayedTool("bad", 150*time.Millisecond, "", "disk on fire", nil))
	agent := startAgentServerConfig(t, reg, func(s *Server) *Server { return s.WithInlineBudget(20 * time.Millisecond) })
	if _, err := agent.Call(context.Background(), "bad", []byte(`{}`)); err == nil || !strings.Contains(err.Error(), "disk on fire") {
		t.Fatalf("err = %v, want the tool's failure", err)
	}
}

func TestJobTimeoutIsError(t *testing.T) {
	reg := jobRegistry(t, delayedTool("forever", time.Hour, "", "", nil))
	agent := startAgentServerConfig(t, reg, func(s *Server) *Server {
		return s.WithInlineBudget(20 * time.Millisecond).WithCallTimeout(300 * time.Millisecond)
	})
	if _, err := agent.Call(context.Background(), "forever", []byte(`{}`)); err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("err = %v, want tool timed out", err)
	}
}

// TestAgentContextStopsPolling: the agent gives up when its context ends.
func TestAgentContextStopsPolling(t *testing.T) {
	reg := jobRegistry(t, delayedTool("slow", 10*time.Second, "x", "", nil))
	agent := startAgentServerConfig(t, reg, func(s *Server) *Server { return s.WithInlineBudget(20 * time.Millisecond) })
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := agent.Call(ctx, "slow", []byte(`{}`))
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 2*time.Second {
		t.Fatalf("err = %v after %v, want deadline exceeded promptly", err, time.Since(start))
	}
}

// TestSlowToolOutlivesQueryTimeout is the case from the issue: a tool slower
// than the agent's per-query timeout now completes.
func TestSlowToolOutlivesQueryTimeout(t *testing.T) {
	var runs atomic.Int64
	reg := jobRegistry(t, delayedTool("slow", 1500*time.Millisecond, "worth the wait", "", &runs))
	agent := startAgentServerConfig(t, reg, nil) // default inline budget
	// The query timeout must exceed the inline budget (750ms) so the queued
	// answer can arrive, but is well below the tool's 1.5s run time.
	agent.SetTimeout(time.Second)
	re, err := agent.Call(context.Background(), "slow", []byte(`{}`))
	if err != nil || jsonText(t, re) != "worth the wait" {
		t.Fatalf("slow call: %v", err)
	}
	if runs.Load() != 1 {
		t.Fatalf("tool ran %d times", runs.Load())
	}
}

func TestJobExpiry(t *testing.T) {
	srv := NewServer(jobRegistry(t, delayedTool("slow", 50*time.Millisecond, "x", "", nil))).
		WithInlineBudget(5*time.Millisecond).WithJobLimits(10, time.Minute)
	var offset atomic.Int64
	base := time.Now()
	srv.jobs.now = func() time.Time { return base.Add(time.Duration(offset.Load())) }
	h := srv.Handlers()
	q := h.OnCall(&dns.CallRequest{Tool: "slow"})
	for h.OnJob(q.Job).Status == codec.StatusRunning {
		time.Sleep(10 * time.Millisecond)
	}
	offset.Store(int64(59 * time.Second))
	if e := h.OnJob(q.Job); e.Status != codec.StatusDone {
		t.Fatalf("within TTL: %+v", e)
	}
	offset.Store(int64(61 * time.Second))
	if e := h.OnJob(q.Job); e.Status != codec.StatusError {
		t.Fatalf("after TTL: %+v", e)
	}
}

// TestJobsBounded: with no room for a job, a slow call is answered when it
// finishes rather than queued.
func TestJobsBounded(t *testing.T) {
	srv := NewServer(jobRegistry(t, delayedTool("slow", 200*time.Millisecond, "x", "", nil))).
		WithInlineBudget(20*time.Millisecond).WithJobLimits(1, time.Minute)
	h := srv.Handlers()
	if e := h.OnCall(&dns.CallRequest{Tool: "slow"}); e.Status != codec.StatusQueued {
		t.Fatalf("first: %+v", e)
	}
	if e := h.OnCall(&dns.CallRequest{Tool: "slow"}); e.Status != codec.StatusOK {
		t.Fatalf("second with the job store full: %+v, want ok after the tool finishes", e)
	}
}

// TestJobPollsUseFreshNames: each poll carries a new nonce so no resolver can
// answer it from cache.
func TestJobPollsUseFreshNames(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		n, _ := codec.RandomNonce()
		name := dns.LabelsToName(codec.JobPollName([]string{"example"}, "job1", n))
		if seen[name] {
			t.Fatal("repeated poll name")
		}
		seen[name] = true
		job, _, err := codec.ParseJobName(dns.NameToLabels(name))
		if err != nil || job != "job1" {
			t.Fatalf("poll name %s parses to %q %v", name, job, err)
		}
	}
}

// TestJobThroughResolver: a tool that takes several seconds completes through
// Unbound (0x20 on), and runs once.
func TestJobThroughResolver(t *testing.T) {
	var runs atomic.Int64
	reg := jobRegistry(t, delayedTool("slow", 3*time.Second, "done after 3s", "", &runs))
	a := viaResolver(t, NewServer(reg).WithCompression(), testresolver.Options{CapsForID: true})
	a.SetTimeout(2 * time.Second)
	re, err := a.Call(context.Background(), "slow", []byte(`{}`))
	if err != nil || jsonText(t, re) != "done after 3s" {
		t.Fatalf("slow call through the resolver: %v", err)
	}
	if runs.Load() != 1 {
		t.Fatalf("tool ran %d times", runs.Load())
	}
}
