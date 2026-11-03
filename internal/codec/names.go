package codec

import (
	"errors"
	"fmt"
)

// MaxName is the maximum wire length of a domain name (RFC 1035 §2.3.4).
const MaxName = 255

// ErrNameTooLong is returned when a name exceeds MaxName or a label exceeds
// MaxLabel on the wire.
var ErrNameTooLong = errors.New("codec: name exceeds DNS length limits")

// Reserved structural labels. Tool names must not collide with these.
const (
	LabelCall   = "call"
	LabelSigned = "signed" // marks a signed (HMAC) call name
	LabelSchema = "schema"
	LabelChunk  = "chunk"
	LabelJob    = "job"
)

// CallName is a parsed MCPort53 tool-call query name.
type CallName struct {
	Tool  string   // tool name (single DNS label)
	Args  []byte   // decoded argument bytes
	Nonce string   // uncacheability nonce
	Sig   string   // HMAC signature label ("" if unsigned)
	Zone  []string // zone labels (rightmost, e.g. ["example"])
}

// BuildCallName constructs the label slice for a call query.
//
// Layout (left-to-right, most-significant first):
//
//	signed:   <sig>.<arg-labels...>.<tool>.call.signed.<nonce>.<zone>
//	unsigned: <arg-labels...>.<tool>.call.<nonce>.<zone>
//
// args are base32-encoded and chunked to <= MaxLabel bytes per label.
func BuildCallName(zone []string, tool string, args []byte, nonce string, sig string) []string {
	if zone == nil || len(zone) == 0 {
		panic("codec: zone must be non-empty")
	}
	if tool == "" {
		panic("codec: tool must be non-empty")
	}
	if nonce == "" {
		panic("codec: nonce must be non-empty")
	}

	var labels []string

	argStr := EncodeBase32(args)
	labels = append(labels, ChunkLabels(argStr)...)
	labels = append(labels, tool, LabelCall)
	if sig != "" {
		labels = append(labels, LabelSigned)
	}
	labels = append(labels, nonce)
	labels = append(labels, zone...)

	if sig != "" {
		// Prepend the signature as the leftmost label.
		return append([]string{sig}, labels...)
	}
	return labels
}

// NameWireLength returns the wire-format length of a name made of labels: one
// length byte plus the label for each, and the terminating root byte.
func NameWireLength(labels []string) int {
	n := 1
	for _, l := range labels {
		n += 1 + len(l)
	}
	return n
}

// CheckName reports ErrNameTooLong when labels would not fit in a DNS name.
func CheckName(labels []string) error {
	for _, l := range labels {
		if len(l) > MaxLabel {
			return fmt.Errorf("%w: label of %d bytes (max %d)", ErrNameTooLong, len(l), MaxLabel)
		}
	}
	if n := NameWireLength(labels); n > MaxName {
		return fmt.Errorf("%w: %d bytes (max %d)", ErrNameTooLong, n, MaxName)
	}
	return nil
}

// MaxCallArgs returns the largest argument size, in bytes, for which a call
// name with the given zone, tool, nonce and signature fits in MaxName. It
// returns -1 when even empty arguments do not fit.
func MaxCallArgs(zone []string, tool, nonce, sig string) int {
	fits := func(n int) bool {
		return CheckName(BuildCallName(zone, tool, make([]byte, n), nonce, sig)) == nil
	}
	if !fits(0) {
		return -1
	}
	n := 0
	for fits(n + 1) {
		n++
	}
	return n
}

// ParseCallName parses a label slice produced by BuildCallName (or received from
// a DNS query). It returns an error if the name is malformed.
func ParseCallName(labels []string) (CallName, error) {
	var cn CallName
	i := indexOf(labels, LabelCall)
	if i < 0 {
		return cn, fmt.Errorf("codec: no %q label in call name", LabelCall)
	}
	if i == 0 {
		return cn, fmt.Errorf("codec: tool label missing before %q", LabelCall)
	}
	cn.Tool = labels[i-1]
	argsLabels := labels[:i-1]

	// Structural labels after "call": [signed?] nonce zone...
	rest := labels[i+1:]
	if len(rest) < 2 {
		return cn, fmt.Errorf("codec: nonce/zone labels missing after %q", LabelCall)
	}
	signed := false
	if rest[0] == LabelSigned {
		signed = true
		rest = rest[1:]
	}
	cn.Nonce = rest[0]
	cn.Zone = rest[1:]
	if len(cn.Zone) == 0 {
		return cn, fmt.Errorf("codec: zone missing after nonce")
	}

	if signed {
		if len(argsLabels) == 0 {
			return cn, fmt.Errorf("codec: signed call name missing signature label")
		}
		cn.Sig = argsLabels[0]
		argsLabels = argsLabels[1:]
	}

	if len(argsLabels) > 0 {
		decoded, err := DecodeBase32(UnchunkLabels(argsLabels))
		if err != nil {
			return cn, fmt.Errorf("codec: decoding args: %w", err)
		}
		cn.Args = decoded
	}
	return cn, nil
}

// ChunkName builds the label slice for a result-chunk query:
//
//	<chunk-index>.<session>.chunk.<zone>
func ChunkName(zone []string, session string, chunk int) []string {
	return append([]string{
		fmt.Sprintf("%d", chunk),
		session,
		LabelChunk,
	}, zone...)
}

// ParseChunkName parses a result-chunk query name.
func ParseChunkName(labels []string) (chunk int, session string, zone []string, err error) {
	// Two labels must precede "chunk": the index and the session.
	i := indexOf(labels, LabelChunk)
	if i < 2 {
		return 0, "", nil, fmt.Errorf("codec: malformed chunk name %v", labels)
	}
	if chunk, err = parseIndex(labels[i-2]); err != nil {
		return 0, "", nil, err
	}
	session = labels[i-1]
	zone = labels[i+1:]
	if session == "" || len(zone) == 0 {
		return 0, "", nil, fmt.Errorf("codec: malformed chunk name %v", labels)
	}
	return chunk, session, zone, nil
}

// CursorName builds the label slice for a cursor-paginated result-chunk query
// (protocol §4.4):
//
//	<cursor>.<session>.chunk.<zone>
//
// The cursor replaces the numeric chunk index: it is an opaque token the server
// assigns and the client returns unchanged.
func CursorName(zone []string, session, cursor string) []string {
	return append([]string{
		cursor,
		session,
		LabelChunk,
	}, zone...)
}

// ParseCursorName parses a cursor-paginated result-chunk query name.
func ParseCursorName(labels []string) (cursor, session string, zone []string, err error) {
	i := indexOf(labels, LabelChunk)
	if i < 2 {
		return "", "", nil, fmt.Errorf("codec: malformed cursor chunk name %v", labels)
	}
	cursor = labels[i-2]
	session = labels[i-1]
	zone = labels[i+1:]
	if cursor == "" || session == "" || len(zone) == 0 {
		return "", "", nil, fmt.Errorf("codec: malformed cursor chunk name %v", labels)
	}
	return cursor, session, zone, nil
}

// JobName builds the label slice for a job-status poll:
//
//	<job>.job.<zone>
func JobName(zone []string, job string) []string {
	return append([]string{job, LabelJob}, zone...)
}

// ParseJobName parses a job-status poll name.
func ParseJobName(labels []string) (job string, zone []string, err error) {
	i := indexOf(labels, LabelJob)
	if i < 1 {
		return "", nil, fmt.Errorf("codec: malformed job name %v", labels)
	}
	job = labels[i-1]
	zone = labels[i+1:]
	if job == "" || len(zone) == 0 {
		return "", nil, fmt.Errorf("codec: malformed job name %v", labels)
	}
	return job, zone, nil
}

func indexOf(labels []string, s string) int {
	for i, l := range labels {
		if l == s {
			return i
		}
	}
	return -1
}

func parseIndex(s string) (int, error) {
	if s == "" {
		return 0, fmt.Errorf("codec: empty chunk index")
	}
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("codec: non-numeric chunk index %q", s)
		}
		n = n*10 + int(r-'0')
	}
	return n, nil
}
