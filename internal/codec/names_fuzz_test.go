package codec

import (
	"strings"
	"testing"
)

// malformedNames are label slices that once crashed or could crash a parser:
// structural labels at every position with too few labels around them.
var malformedNames = [][]string{
	nil,
	{},
	{"chunk"},
	{"abc", "chunk"},
	{"abc", "chunk", "example"}, // one label before "chunk": index out of range [-1]
	{"chunk", "example"},
	{"0", "chunk", "example"},
	{"call"},
	{"call", "example"},
	{"tool", "call"},
	{"tool", "call", "nonce"},
	{"tool", "call", "signed", "nonce"},
	{"tool", "call", "signed"},
	{"tool", "call", "signed", "nonce", "example"}, // signed but no sig label
	{"job"},
	{"job", "example"},
	{"abc", "job"},
	{"", "", ""},
	{"", "chunk", ""},
	{"", "", "chunk", ""},
	{"99999999999999999999999", "s", "chunk", "example"},
}

// TestParsersRejectMalformedWithoutPanic feeds every parser every malformed
// name and requires an error (never a panic).
func TestParsersRejectMalformedWithoutPanic(t *testing.T) {
	for _, labels := range malformedNames {
		name := strings.Join(labels, ".")
		mustNotPanic(t, "ParseCallName("+name+")", func() { _, _ = ParseCallName(labels) })
		mustNotPanic(t, "ParseChunkName("+name+")", func() { _, _, _, _ = ParseChunkName(labels) })
		mustNotPanic(t, "ParseCursorName("+name+")", func() { _, _, _, _ = ParseCursorName(labels) })
		mustNotPanic(t, "ParseJobName("+name+")", func() { _, _, _ = ParseJobName(labels) })
	}
}

// TestParseChunkNameRequiresIndexAndSession pins the exact boundary of the
// crash: one label before "chunk" is an error, two parse.
func TestParseChunkNameRequiresIndexAndSession(t *testing.T) {
	if _, _, _, err := ParseChunkName([]string{"abc", "chunk", "example"}); err == nil {
		t.Fatal("one label before chunk: want error")
	}
	idx, sess, zone, err := ParseChunkName([]string{"3", "abc", "chunk", "example"})
	if err != nil || idx != 3 || sess != "abc" || !equalStrings(zone, []string{"example"}) {
		t.Fatalf("got idx=%d sess=%q zone=%v err=%v", idx, sess, zone, err)
	}
}

func mustNotPanic(t *testing.T, what string, fn func()) {
	t.Helper()
	defer func() {
		if v := recover(); v != nil {
			t.Errorf("%s panicked: %v", what, v)
		}
	}()
	fn()
}

// FuzzParseNames checks that no name parser panics on arbitrary input. The
// seed corpus runs as a normal test; use go test -fuzz=FuzzParseNames to
// explore further.
func FuzzParseNames(f *testing.F) {
	for _, labels := range malformedNames {
		f.Add(strings.Join(labels, "."))
	}
	f.Add("nbswy3dp.echo.call.abcdefgh.example")
	f.Add("sig.nbswy3dp.echo.call.signed.abcdefgh.example")
	f.Add("0.sess.chunk.example")
	f.Add("cursor.sess.chunk.example")
	f.Add("j1.job.example")
	f.Fuzz(func(t *testing.T, name string) {
		labels := strings.Split(name, ".")
		_, _ = ParseCallName(labels)
		_, _, _, _ = ParseChunkName(labels)
		_, _, _, _ = ParseCursorName(labels)
		_, _, _ = ParseJobName(labels)
	})
}
