package codec

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// MaxEnvelopeTXT is the target maximum size (bytes) for a single TXT record
// holding an envelope. Kept below the 255-byte TXT character-string limit with
// headroom so most resolvers return it intact.
const MaxEnvelopeTXT = 200

// Status is the outcome of a call as carried in an Envelope.
type Status string

const (
	StatusOK      Status = "ok"      // success; Result holds the serialized outcome
	StatusError   Status = "error"   // tool raised; Error holds a message
	StatusQueued  Status = "queued"  // accepted; Job holds a job id to poll
	StatusRunning Status = "running" // job in progress; poll again
	StatusChunked Status = "chunked" // large result; fetch chunks by session
	StatusDone    Status = "done"    // job finished; Session holds the result
)

// Kind identifies how a tool result's "result" string is serialized.
type Kind string

const (
	KindJSON   Kind = "json"   // structured result (JSON object)
	KindText   Kind = "text"   // text result (base64 in JSON)
	KindBase64 Kind = "base64" // binary result (base64 in JSON)
)

// Envelope is the JSON structure returned in a TXT record for a call, chunk, or
// job-status response.
type Envelope struct {
	V       int    `json:"v"`
	Status  Status `json:"status"`
	Tool    string `json:"tool,omitempty"`
	Result  string `json:"result,omitempty"`
	Error   string `json:"error,omitempty"`
	Session string `json:"session,omitempty"`
	Chunk   int    `json:"chunk,omitempty"`
	Total   int    `json:"total,omitempty"`
	More    bool   `json:"more,omitempty"`
	Job     string `json:"job,omitempty"`
	Ms      int    `json:"ms,omitempty"`
}

// NewEnvelope builds an envelope with the current protocol version.
func NewEnvelope(st Status) *Envelope {
	return &Envelope{V: 1, Status: st}
}

// OK builds a successful envelope. result is the serialized tool outcome.
func OK(tool, result string, ms int) *Envelope {
	e := NewEnvelope(StatusOK)
	e.Tool = tool
	e.Result = result
	e.Ms = ms
	return e
}

// Error builds an error envelope.
func Error(tool, msg string) *Envelope {
	e := NewEnvelope(StatusError)
	e.Tool = tool
	e.Error = msg
	return e
}

// Queued builds a queued envelope for a long-running call.
func Queued(tool, job string) *Envelope {
	e := NewEnvelope(StatusQueued)
	e.Tool = tool
	e.Job = job
	return e
}

// Running builds a running-job envelope.
func Running(tool, job string) *Envelope {
	e := NewEnvelope(StatusRunning)
	e.Tool = tool
	e.Job = job
	return e
}

// Done builds a done-job envelope; the client fetches the result by session.
func Done(tool, job, session string) *Envelope {
	e := NewEnvelope(StatusDone)
	e.Tool = tool
	e.Job = job
	e.Session = session
	return e
}

// Chunked builds a result-chunk envelope. more indicates whether additional
// chunks follow.
func Chunked(tool, session string, chunk, total int, more bool, data string) *Envelope {
	e := NewEnvelope(StatusChunked)
	e.Tool = tool
	e.Session = session
	e.Chunk = chunk
	e.Total = total
	e.More = more
	e.Result = data
	return e
}

// Marshal returns the JSON encoding of the envelope.
func (e *Envelope) Marshal() ([]byte, error) {
	b, err := json.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("codec: marshaling envelope: %w", err)
	}
	return b, nil
}

// ParseEnvelope decodes an envelope from JSON (typically TXT contents).
func ParseEnvelope(b []byte) (*Envelope, error) {
	var e Envelope
	if err := json.Unmarshal(b, &e); err != nil {
		return nil, fmt.Errorf("codec: parsing envelope: %w", err)
	}
	if e.V == 0 {
		e.V = 1
	}
	return &e, nil
}

// ResultEnvelope wraps a tool result with its serialization kind.
type ResultEnvelope struct {
	Kind  Kind   `json:"kind"`
	Mime  string `json:"mime,omitempty"`
	Value string `json:"value"`
}

// JSONResult builds a ResultEnvelope for a structured (JSON) result.
func JSONResult(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("codec: marshaling result: %w", err)
	}
	re := ResultEnvelope{Kind: KindJSON, Value: string(b)}
	out, err := json.Marshal(re)
	if err != nil {
		return "", fmt.Errorf("codec: marshaling result envelope: %w", err)
	}
	return string(out), nil
}

// TextResult builds a ResultEnvelope for a text result (base64-encoded).
func TextResult(mime, s string) string {
	re := ResultEnvelope{Kind: KindText, Mime: mime, Value: base64.StdEncoding.EncodeToString([]byte(s))}
	out, _ := json.Marshal(re)
	return string(out)
}

// BinaryResult builds a ResultEnvelope for a binary result (base64-encoded).
func BinaryResult(mime string, data []byte) string {
	re := ResultEnvelope{Kind: KindBase64, Mime: mime, Value: base64.StdEncoding.EncodeToString(data)}
	out, _ := json.Marshal(re)
	return string(out)
}

// ParseResultEnvelope decodes a ResultEnvelope from its serialized form.
func ParseResultEnvelope(s string) (*ResultEnvelope, error) {
	var re ResultEnvelope
	if err := json.Unmarshal([]byte(s), &re); err != nil {
		return nil, fmt.Errorf("codec: parsing result envelope: %w", err)
	}
	return &re, nil
}
