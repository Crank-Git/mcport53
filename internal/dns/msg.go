package dns

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// MaxTXTString is the maximum length (bytes) of a single TXT character-string,
// per RFC 1035 §5.1. A DNS message may carry several TXT records, but we keep
// responses to a single string for broad resolver compatibility.
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

// reply builds an authoritative reply header for r (id, question, RD flag).
func reply(r *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	resp.Id = r.Id
	resp.RecursionDesired = r.RecursionDesired
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

// extractTXT returns the decoded content of the first TXT answer RRset, or an
// error if none is present. TXT strings are base64-encoded on the wire (see
// buildTXTResponse) because the installed miekg/dns TXT pack/unpack path is not
// a clean inverse for strings containing " or \\ -- base64 keeps the payload in
// the ASCII-safe [A-Za-z0-9+/=] alphabet so it survives the round trip intact.
func extractTXT(msg *dns.Msg) (string, error) {
	strs := splitTXT(msg)
	if len(strs) == 0 {
		return "", errors.New("dns: no TXT answer")
	}
	var b strings.Builder
	for _, s := range strs {
		dec, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return "", fmt.Errorf("dns: decoding txt: %w", err)
		}
		b.Write(dec)
	}
	return b.String(), nil
}

// buildTXTResponse writes a single TXT answer holding txt into resp as an
// authoritative reply to req. txt is base64-encoded before being placed in the
// TXT string so the payload avoids the " and \ characters that the installed
// miekg/dns TXT pack/unpack path mishandles (see extractTXT).
func buildTXTResponse(req, resp *dns.Msg, txt string) {
	*resp = *reply(req)
	resp.Authoritative = true
	name := resp.Question[0].Name
	b64 := base64.StdEncoding.EncodeToString([]byte(txt))
	resp.Answer = append(resp.Answer, &dns.TXT{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0},
		Txt: []string{b64},
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
