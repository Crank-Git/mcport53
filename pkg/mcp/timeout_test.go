package mcp

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Crank-Git/mcport53/internal/codec"
	"github.com/Crank-Git/mcport53/internal/dns"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

func toolRegistry(t *testing.T, name string, call func(ctx context.Context, args []byte) (*codec.Envelope, error)) *Registry {
	t.Helper()
	r := NewRegistry()
	if err := r.Register(&Tool{Name: name, Call: call}); err != nil {
		t.Fatal(err)
	}
	return r
}

// TestToolCancelledAtDeadline: a tool that honours its context is cancelled
// at the deadline, and the call returns a timeout error promptly.
func TestToolCancelledAtDeadline(t *testing.T) {
	sawErr := make(chan error, 1)
	r := toolRegistry(t, "slow", func(ctx context.Context, _ []byte) (*codec.Envelope, error) {
		<-ctx.Done()
		sawErr <- ctx.Err()
		return nil, ctx.Err()
	})
	h := NewServer(r).WithCallTimeout(50 * time.Millisecond).Handlers()

	start := time.Now()
	e := h.OnCall(&dns.CallRequest{Tool: "slow"})
	elapsed := time.Since(start)
	if e.Status != codec.StatusError || !strings.Contains(e.Error, "timed out") {
		t.Fatalf("envelope = %+v, want timeout error", e)
	}
	if elapsed < 50*time.Millisecond || elapsed > time.Second {
		t.Fatalf("returned after %v, want ~50ms", elapsed)
	}
	select {
	case err := <-sawErr:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("tool saw ctx.Err() = %v, want DeadlineExceeded", err)
		}
	case <-time.After(time.Second):
		t.Fatal("tool context was never cancelled")
	}
}

// TestToolIgnoringContextStillAnswers: a tool that ignores its context cannot
// hold the DNS handler past the deadline.
func TestToolIgnoringContextStillAnswers(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	r := toolRegistry(t, "stuck", func(context.Context, []byte) (*codec.Envelope, error) {
		<-release
		return codec.OK("stuck", "late", 0), nil
	})
	h := NewServer(r).WithCallTimeout(50 * time.Millisecond).Handlers()
	start := time.Now()
	e := h.OnCall(&dns.CallRequest{Tool: "stuck"})
	if e.Status != codec.StatusError || time.Since(start) > time.Second {
		t.Fatalf("envelope = %+v after %v, want timeout error at the deadline", e, time.Since(start))
	}
}

// TestFastToolUnaffected: a tool that finishes before the deadline returns its
// result unchanged, and its context is still live while it runs.
func TestFastToolUnaffected(t *testing.T) {
	r := toolRegistry(t, "fast", func(ctx context.Context, args []byte) (*codec.Envelope, error) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return codec.OK("fast", string(args), 0), nil
	})
	h := NewServer(r).WithCallTimeout(time.Second).Handlers()
	e := h.OnCall(&dns.CallRequest{Tool: "fast", Args: []byte("abc")})
	if e.Status != codec.StatusOK || e.Result != "abc" {
		t.Fatalf("envelope = %+v", e)
	}
}

// TestToolContextCarriesDeadline: tools (including MCP SDK handlers) receive a
// context with the configured deadline, and the default applies when unset.
func TestToolContextCarriesDeadline(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  time.Duration
		want time.Duration
	}{
		{"configured", 2 * time.Second, 2 * time.Second},
		{"default", 0, DefaultCallTimeout},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var remaining time.Duration
			var hasDeadline bool
			r := NewRegistry()
			_ = r.AddMCPTool(&sdkmcp.Tool{Name: "probe"}, func(ctx context.Context, _ *sdkmcp.CallToolRequest) (*sdkmcp.CallToolResult, error) {
				var dl time.Time
				dl, hasDeadline = ctx.Deadline()
				remaining = time.Until(dl)
				return textResult("ok"), nil
			})
			srv := NewServer(r)
			if tc.set > 0 {
				srv = srv.WithCallTimeout(tc.set)
			}
			if e := srv.Handlers().OnCall(&dns.CallRequest{Tool: "probe", Args: []byte(`{}`)}); e.Status != codec.StatusOK {
				t.Fatalf("envelope = %+v", e)
			}
			if !hasDeadline || remaining <= 0 || remaining > tc.want {
				t.Fatalf("deadline present=%v remaining=%v, want <= %v", hasDeadline, remaining, tc.want)
			}
		})
	}
}

// TestToolPanicIsErrorEnvelope: the tool runs on its own goroutine, which the
// DNS server's recover does not cover, so a panic must be recovered there.
func TestToolPanicIsErrorEnvelope(t *testing.T) {
	r := toolRegistry(t, "boom", func(context.Context, []byte) (*codec.Envelope, error) {
		panic("tool bug")
	})
	e := NewServer(r).Handlers().OnCall(&dns.CallRequest{Tool: "boom"})
	if e.Status != codec.StatusError || !strings.Contains(e.Error, "panicked") {
		t.Fatalf("envelope = %+v, want panic error", e)
	}
}

// TestTimeoutOverDNS drives a slow tool through a real server and Agent: the
// agent gets a timeout error well before its own query timeout, and the server
// answers the next call normally.
func TestTimeoutOverDNS(t *testing.T) {
	r := NewRegistry()
	_ = r.Register(&Tool{Name: "slow", Call: func(ctx context.Context, _ []byte) (*codec.Envelope, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}})
	_ = r.Register(&Tool{Name: "fast", Call: func(context.Context, []byte) (*codec.Envelope, error) {
		re, _ := codec.JSONResult("ok")
		return codec.OK("fast", re, 0), nil
	}})
	agent := startAgentServerConfig(t, r, func(s *Server) *Server { return s.WithCallTimeout(100 * time.Millisecond) })
	agent.SetTimeout(3 * time.Second)

	start := time.Now()
	_, err := agent.Call(context.Background(), "slow", []byte(`{}`))
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("slow call: err = %v, want timed out", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("slow call took %v; the server should answer at its 100ms deadline", time.Since(start))
	}
	if re, err := agent.Call(context.Background(), "fast", []byte(`{}`)); err != nil || re.Kind != codec.KindJSON {
		t.Fatalf("fast call after timeout: %+v err=%v", re, err)
	}
}
