package dns

import (
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// MaxTXTString is the maximum length (bytes) of a single TXT character-string,
// per RFC 1035 §5.1. A payload longer than this is split across several
// strings of one TXT record.
const MaxTXTString = 255

// NameToLabels splits a fully-qualified domain name into its labels, dropping the
// trailing dot. Labels are returned left-to-right (most-significant first).
func NameToLabels(fqdn string) []string {
	name := strings.TrimSuffix(fqdn, ".")
	if name == "" {
		return nil
	}
	return strings.Split(name, ".")
}

// LabelsToName joins labels into a fully-qualified domain name with a trailing dot.
func LabelsToName(labels []string) string {
	return dns.Fqdn(strings.Join(labels, "."))
}

// reply builds a reply header for r: id, opcode, question, the RD and CD
// flags copied from the query, and QR set. Resolvers discard a "response"
// without QR (RFC 1035 §4.1.1), so every reply must carry it.
func reply(r *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	resp.Id = r.Id
	resp.Response = true
	resp.Opcode = r.Opcode
	resp.RecursionDesired = r.RecursionDesired
	resp.CheckingDisabled = r.CheckingDisabled
	resp.Question = r.Question
	return resp
}

// splitTXT extracts every TXT character-string from a message's answer RRset.
func splitTXT(msg *dns.Msg) []string {
	var out []string
	for _, rr := range msg.Answer {
		if txt, ok := rr.(*dns.TXT); ok {
			out = append(out, txt.Txt...)
		}
	}
	return out
}

// ExtractTXT returns the payload carried by a message's TXT answers: the
// unescaped bytes of every character-string, concatenated (protocol §4). It
// returns an error if there is no TXT answer.
func ExtractTXT(msg *dns.Msg) (string, error) {
	strs := splitTXT(msg)
	if len(strs) == 0 {
		return "", errors.New("dns: no TXT answer")
	}
	var b strings.Builder
	for _, s := range strs {
		raw, err := unescapeTXT(s)
		if err != nil {
			return "", fmt.Errorf("dns: decoding txt: %w", err)
		}
		b.Write(raw)
	}
	return b.String(), nil
}

func extractTXT(msg *dns.Msg) (string, error) { return ExtractTXT(msg) }

// TXTStrings splits payload into TXT character-strings of at most
// MaxTXTString bytes on the wire (RFC 1035 §5.1), escaped for miekg/dns.
//
// miekg/dns holds TXT strings in presentation format: when packing, "\"
// starts an escape ("\\", "\"", "\DDD"), and when unpacking, quotes,
// backslashes and non-printable bytes come back escaped. Escaping every byte
// that needs it here, and unescaping in ExtractTXT, makes the wire carry the
// payload's exact bytes.
func TXTStrings(payload string) []string {
	if payload == "" {
		return []string{""} // a TXT record holds at least one string
	}
	var out []string
	for len(payload) > 0 {
		n := MaxTXTString
		if n > len(payload) {
			n = len(payload)
		}
		out = append(out, escapeTXT(payload[:n]))
		payload = payload[n:]
	}
	return out
}

// escapeTXT escapes raw bytes for a miekg/dns TXT string.
func escapeTXT(raw string) string {
	var b strings.Builder
	b.Grow(len(raw))
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch {
		case c == '\\' || c == '"':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c < 0x20 || c > 0x7e:
			fmt.Fprintf(&b, "\\%03d", c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// unescapeTXT reverses miekg/dns's presentation escaping of a TXT string:
// "\DDD" is the byte with decimal value DDD and "\X" is X.
func unescapeTXT(s string) ([]byte, error) {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' {
			out = append(out, c)
			continue
		}
		if i+1 >= len(s) {
			return nil, errors.New("dangling escape")
		}
		if d := s[i+1]; d >= '0' && d <= '9' {
			if i+4 > len(s) {
				return nil, fmt.Errorf("short \\DDD escape in %q", s)
			}
			v := 0
			for _, x := range []byte(s[i+1 : i+4]) {
				if x < '0' || x > '9' {
					return nil, fmt.Errorf("bad \\DDD escape in %q", s)
				}
				v = v*10 + int(x-'0')
			}
			if v > 255 {
				return nil, fmt.Errorf("\\DDD escape out of range in %q", s)
			}
			out = append(out, byte(v))
			i += 3
			continue
		}
		out = append(out, s[i+1])
		i++
	}
	return out, nil
}

// buildTXTResponse writes a TXT answer carrying txt into resp as an
// authoritative reply to req (protocol §4).
func buildTXTResponse(req, resp *dns.Msg, txt string) {
	*resp = *reply(req)
	resp.Authoritative = true
	name := resp.Question[0].Name
	resp.Answer = append(resp.Answer, &dns.TXT{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0},
		Txt: TXTStrings(txt),
	})
}

// buildEmptyResponse writes an authoritative, empty answer to req.
func buildEmptyResponse(req, resp *dns.Msg) {
	*resp = *reply(req)
	resp.Authoritative = true
}

// buildNXDOMAIN writes an authoritative NXDOMAIN answer to req.
func buildNXDOMAIN(req, resp *dns.Msg) {
	*resp = *reply(req)
	resp.Authoritative = true
	resp.Rcode = dns.RcodeNameError
}
