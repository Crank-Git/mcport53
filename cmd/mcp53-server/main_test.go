package main

import (
	"context"
	"strings"
	"testing"

	"github.com/Crank-Git/mcport53/internal/codec"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestTextResult(t *testing.T) {
	r := textResult("hello")
	if len(r.Content) != 1 {
		t.Fatalf("content len = %d, want 1", len(r.Content))
	}
	tc, ok := r.Content[0].(*sdkmcp.TextContent)
	if !ok {
		t.Fatalf("content[0] type = %T, want *sdkmcp.TextContent", r.Content[0])
	}
	if tc.Text != "hello" {
		t.Errorf("text = %q, want %q", tc.Text, "hello")
	}
}

func TestRegisterDefaultTools(t *testing.T) {
	reg := registerDefaultTools()
	if reg.Len() != 3 {
		t.Fatalf("Len = %d, want 3", reg.Len())
	}
	for _, name := range []string{"add", "echo", "upper"} {
		if _, ok := reg.Tool(name); !ok {
			t.Errorf("tool %q missing from default registry", name)
		}
	}
}

// TestDefaultToolHandlers exercises each built-in tool handler through the
// registry, covering both the success and invalid-argument paths.
func TestDefaultToolHandlers(t *testing.T) {
	reg := registerDefaultTools()
	call := func(name string, args string) (*codec.Envelope, error) {
		t.Helper()
		tool, ok := reg.Tool(name)
		if !ok {
			t.Fatalf("tool %q missing from default registry", name)
		}
		return tool.Call(context.Background(), []byte(args))
	}

	// add: success.
	env, err := call("add", `{"a":2,"b":3}`)
	if err != nil {
		t.Fatalf("add call: %v", err)
	}
	if env.Status != codec.StatusOK || !strings.Contains(env.Result, "5") {
		t.Errorf("add = %+v, want ok containing 5", env)
	}

	// add: invalid arguments.
	env, err = call("add", `not json`)
	if err != nil {
		t.Fatalf("add invalid args should not error: %v", err)
	}
	if env.Status != codec.StatusError {
		t.Errorf("add invalid args status = %q, want error", env.Status)
	}

	// echo: success.
	if env, err := call("echo", `{"text":"hi"}`); err != nil || env.Status != codec.StatusOK {
		t.Fatalf("echo = %+v err=%v", env, err)
	}

	// upper: success.
	if env, err := call("upper", `{"text":"hi"}`); err != nil || !strings.Contains(env.Result, "HI") {
		t.Errorf("upper = %+v err=%v, want HI", env, err)
	}

	// echo: invalid arguments.
	if env, _ := call("echo", `not json`); env.Status != codec.StatusError {
		t.Errorf("echo invalid args status = %q, want error", env.Status)
	}
}
