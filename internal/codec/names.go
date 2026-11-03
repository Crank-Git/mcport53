package codec

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
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
	LabelUpload = "upload" // one part of an uploaded argument blob
)

// uploadRefPrefix starts the label that makes a call take its arguments from
// an upload: "u-<id>-<parts>". '-' is outside the base32 alphabet, so the label
// can never be inline argument data.
const uploadRefPrefix = "u-"

// CallName is a parsed MCPort53 tool-call query name.
type CallName struct {
	Tool  string   // tool name (single DNS label)
	Args  []byte   // decoded argument bytes
	Nonce string   // uncacheability nonce
	Sig   string   // HMAC signature label ("" if unsigned)
	Zone  []string // zone labels (rightmost, e.g. ["example"])
	// Upload and Parts are set when the arguments were uploaded in parts
	// (protocol §3.1); Args is then empty until the server assembles them.
	Upload string
	Parts  int
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

	if len(argsLabels) == 1 && strings.HasPrefix(argsLabels[0], uploadRefPrefix) {
		id, parts, err := parseUploadRef(argsLabels[0])
		if err != nil {
			return cn, err
		}
		cn.Upload, cn.Parts = id, parts
		return cn, nil
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

// UploadRef returns the call-name label that references an upload of parts
// parts: "u-<id>-<parts>".
func UploadRef(id string, parts int) string {
	return uploadRefPrefix + id + "-" + strconv.Itoa(parts)
}

func parseUploadRef(label string) (id string, parts int, err error) {
	rest := strings.TrimPrefix(label, uploadRefPrefix)
	i := strings.LastIndexByte(rest, '-')
	if i <= 0 {
		return "", 0, fmt.Errorf("codec: malformed upload reference %q", label)
	}
	id = rest[:i]
	if parts, err = parseIndex(rest[i+1:]); err != nil || parts < 1 {
		return "", 0, fmt.Errorf("codec: malformed upload reference %q", label)
	}
	return id, parts, nil
}

// BuildUploadCallName builds a call name whose arguments come from an upload
// (protocol §3.1). It is BuildCallName with the upload reference label in place
// of the argument labels.
func BuildUploadCallName(zone []string, tool, upload string, parts int, nonce, sig string) []string {
	labels := BuildCallName(zone, tool, nil, nonce, sig)
	i := 0
	if sig != "" {
		i = 1
	}
	return append(labels[:i:i], append([]string{UploadRef(upload, parts)}, labels[i:]...)...)
}

// UploadPartName builds the name for one upload part (protocol §3.1):
//
//	<data-labels...>.<index>.<upload-id>.upload.<zone>
func UploadPartName(zone []string, upload string, index int, data []byte) []string {
	labels := ChunkLabels(EncodeBase32(data))
	labels = append(labels, strconv.Itoa(index), upload, LabelUpload)
	return append(labels, zone...)
}

// ParseUploadPart parses the labels of an upload part name with the zone
// already removed. It reads from the right ("upload" is last), so data labels
// that happen to spell a structural label do not confuse it.
func ParseUploadPart(prefix []string) (upload string, index int, data []byte, err error) {
	n := len(prefix)
	if n < 3 || prefix[n-1] != LabelUpload {
		return "", 0, nil, fmt.Errorf("codec: malformed upload part name %v", prefix)
	}
	upload = prefix[n-2]
	if upload == "" {
		return "", 0, nil, fmt.Errorf("codec: empty upload id")
	}
	if index, err = parseIndex(prefix[n-3]); err != nil {
		return "", 0, nil, err
	}
	if data, err = DecodeBase32(UnchunkLabels(prefix[:n-3])); err != nil {
		return "", 0, nil, fmt.Errorf("codec: decoding upload part: %w", err)
	}
	return upload, index, data, nil
}

// MaxUploadPart returns the largest part size, in bytes, whose part name fits
// in MaxName for the given zone and upload id, with a part index of up to
// indexDigits digits.
func MaxUploadPart(zone []string, upload string, indexDigits int) int {
	index := 1
	for i := 1; i < indexDigits; i++ {
		index *= 10
	}
	n := 0
	for CheckName(UploadPartName(zone, upload, index, make([]byte, n+1))) == nil {
		n++
	}
	return n
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

// JobPollName builds a job poll with a fresh nonce, so a resolver never
// answers it from cache (protocol §4.3):
//
//	<nonce>.<job>.job.<zone>
func JobPollName(zone []string, job, nonce string) []string {
	return append([]string{nonce, job, LabelJob}, zone...)
}

// ParseJobName parses a job-status poll name. A nonce label before the job
// id, as JobPollName adds, is ignored.
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
		if n > 1<<30 {
			return 0, fmt.Errorf("codec: chunk index %q out of range", s)
		}
	}
	return n, nil
}
