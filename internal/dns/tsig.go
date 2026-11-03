package dns

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"

	"github.com/miekg/dns"
)

// CanonicalKey canonicalizes a TSIG key name to the canonical form used on the
// wire (RFC 4034 §6.2): lowercased with a trailing dot. Both peers must agree on
// the canonical name so the provider lookup and the MAC calculation match.
func CanonicalKey(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	return name
}

// TsigKeys is a set of TSIG shared secrets keyed by canonical key name
// (protocol §8). It implements dns.TsigProvider so a Client can sign outgoing
// queries and a Server can verify incoming queries and sign responses. The
// algorithm is HMAC-SHA256 (RFC 4635); the secret is base64-encoded the way
// miekg/dns expects it.
type TsigKeys struct {
	secrets map[string]string // canonical key name -> base64(secret)
	algo    string            // HMAC algorithm name advertised on the wire
	fudge   uint16            // time fudge window accepted for signatures
}

// NewTsigKeys builds an empty TsigKeys set using HMAC-SHA256 with the standard
// 300-second fudge.
func NewTsigKeys() *TsigKeys {
	return &TsigKeys{
		secrets: map[string]string{},
		algo:    dns.HmacSHA256,
		fudge:   300,
	}
}

// With adds (or replaces) the secret for key name and returns the receiver for
// chaining. The name is canonicalized so both peers agree on the lookup key.
func (ks *TsigKeys) With(name string, secret []byte) *TsigKeys {
	if ks.secrets == nil {
		ks.secrets = map[string]string{}
	}
	ks.secrets[CanonicalKey(name)] = base64.StdEncoding.EncodeToString(secret)
	return ks
}

// Len reports how many keys are installed. It is nil-safe.
func (ks *TsigKeys) Len() int {
	if ks == nil {
		return 0
	}
	return len(ks.secrets)
}

// Algorithm returns the HMAC algorithm name advertised on the wire. It is
// nil-safe.
func (ks *TsigKeys) Algorithm() string {
	if ks == nil {
		return dns.HmacSHA256
	}
	return ks.algo
}

// Fudge returns the time fudge window accepted for signatures. It is nil-safe.
func (ks *TsigKeys) Fudge() uint16 {
	if ks == nil {
		return 300
	}
	return ks.fudge
}

// tsigProvider adapts a TsigKeys map to dns.TsigProvider. It mirrors the
// built-in miekg/dns HMAC provider: the MAC is HMAC-SHA256 over the canonical
// message buffer (which the library has already assembled) keyed by the base64
// shared secret. Verify delegates to the exported TsigVerify, which also checks
// the time-fudge window.
type tsigProvider struct {
	secrets map[string]string
}

func (p tsigProvider) Generate(msg []byte, t *dns.TSIG) ([]byte, error) {
	key, ok := p.secrets[t.Hdr.Name]
	if !ok {
		return nil, dns.ErrSecret
	}
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, err
	}
	h := hmac.New(sha256.New, raw)
	_, _ = h.Write(msg)
	return h.Sum(nil), nil
}

func (p tsigProvider) Verify(msg []byte, t *dns.TSIG) error {
	if _, ok := p.secrets[t.Hdr.Name]; !ok {
		return dns.ErrSecret
	}
	// Match miekg's built-in tsigHMACProvider: recompute the HMAC over msg and
	// compare it against the MAC carried in the TSIG RR. Do NOT call
	// dns.TsigVerify here -- it strips the TSIG again from an already-stripped
	// buffer and would always report "no signature found".
	b, err := p.Generate(msg, t)
	if err != nil {
		return err
	}
	mac, err := hex.DecodeString(t.MAC)
	if err != nil {
		return err
	}
	if !hmac.Equal(b, mac) {
		return dns.ErrSig
	}
	return nil
}

// provider returns the dns.TsigProvider backed by these keys. It is nil-safe,
// returning nil (no TSIG) when called on a nil *TsigKeys.
func (ks *TsigKeys) provider() dns.TsigProvider {
	if ks == nil {
		return nil
	}
	return tsigProvider{secrets: ks.secrets}
}
