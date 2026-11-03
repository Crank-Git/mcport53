package mcp

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Crank-Git/mcport53/internal/auth"
	"github.com/Crank-Git/mcport53/internal/codec"
	"github.com/Crank-Git/mcport53/internal/testresolver"
)

// slowRegistry has one tool that takes d and counts its runs.
func slowRegistry(t *testing.T, d time.Duration, runs *atomic.Int64) *Registry {
	t.Helper()
	r := NewRegistry()
	_ = r.Register(&Tool{Name: "slow", Call: func(ctx context.Context, _ []byte) (*codec.Envelope, error) {
		runs.Add(1)
		select {
		case <-time.After(d):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		re, _ := codec.JSONResult("done")
		return codec.OK("slow", re, 0), nil
	}})
	return r
}

// TestRetransmittedCallRunsOnce: a tool slower than Unbound's retransmit
// timer makes Unbound re-send the call query. The tool must run once and the
// call must succeed, unsigned and signed (where a re-sent copy used to trip
// replay protection).
func TestRetransmittedCallRunsOnce(t *testing.T) {
	for _, signed := range []bool{false, true} {
		name := "unsigned"
		if signed {
			name = "signed"
		}
		t.Run(name, func(t *testing.T) {
			var runs atomic.Int64
			// A long inline budget keeps the call on the call query itself (no job),
			// so the resolver retransmits it while the tool runs.
			srv := NewServer(slowRegistry(t, 1500*time.Millisecond, &runs)).WithInlineBudget(5 * time.Second)
			keys := auth.NewKeyRegistry([]byte("retransmit-key"))
			if signed {
				srv = srv.WithKeys(keys)
			}
			a := viaResolver(t, srv, testresolver.Options{CapsForID: true})
			a.SetTimeout(8 * time.Second)
			if signed {
				a.WithKeys(keys)
			}
			if _, err := a.Call(context.Background(), "slow", []byte(`{}`)); err != nil {
				t.Fatalf("slow call through the resolver: %v", err)
			}
			if got := runs.Load(); got != 1 {
				t.Fatalf("tool ran %d times for one call, want 1", got)
			}
		})
	}
}
