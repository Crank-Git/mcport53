package main

import (
	"context"
	"reflect"
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
// TestParseDiscover checks the --discover host:port parsing used for the
// discovery SRV record (protocol §2.1), covering success and every error path.
func TestParseDiscover(t *testing.T) {
	tests := []struct {
		name     string
		in       string
		wantHost string
		wantPort uint16
		wantErr  bool
	}{
		{"default", "127.0.0.1:53", "127.0.0.1", 53, false},
		{"public host", "dns.example.com:53", "dns.example.com", 53, false},
		{"custom port", "resolver.example:8053", "resolver.example", 8053, false},
		{"missing port", "127.0.0.1", "", 0, true},
		{"non-numeric port", "127.0.0.1:abc", "", 0, true},
		{"port out of range", "127.0.0.1:70000", "", 0, true},
		{"empty", "", "", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port, err := parseDiscover(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseDiscover(%q) expected error, got host=%q port=%d", tt.in, host, port)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseDiscover(%q) unexpected error: %v", tt.in, err)
			}
			if host != tt.wantHost || port != tt.wantPort {
				t.Errorf("parseDiscover(%q) = (%q, %d), want (%q, %d)", tt.in, host, port, tt.wantHost, tt.wantPort)
			}
		})
	}
}

func TestParseKeys(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    map[string]string
		wantErr bool
	}{
		{"empty", "", nil, false},
		{"single", "echo=secret1", map[string]string{"echo": "secret1"}, false},
		{"multiple", "echo=secret1,upper=secret2", map[string]string{"echo": "secret1", "upper": "secret2"}, false},
		{"lowercases tool", "Echo=secret", map[string]string{"echo": "secret"}, false},
		{"trims spaces", " echo = secret ", map[string]string{"echo": " secret"}, false},
		{"ignores blank", "echo=secret,,upper=secret2", map[string]string{"echo": "secret", "upper": "secret2"}, false},
		{"missing equals", "echo", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseKeys(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseKeys(%q) expected error", tt.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseKeys(%q) unexpected error: %v", tt.in, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseKeys(%q) = %#v, want %#v", tt.in, got, tt.want)
			}
		})
	}
}

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
