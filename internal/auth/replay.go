package auth

import (
	"container/list"
	"errors"
	"sync"
	"time"
)

// DefaultReplayMaxEntries is the maximum number of nonces a ReplayGuard
// retains. When it is full of unexpired nonces, new calls are refused rather
// than evicting a live nonce (which would re-open it for replay).
const DefaultReplayMaxEntries = 65536

// DefaultReplayTTL is how long a nonce is remembered once used. A verifier
// that accepts timestamps within +/- window must remember nonces for at least
// 2 x window: a call signed at now+window stays valid until now+2*window.
const DefaultReplayTTL = 10 * time.Minute

// ErrReplay is returned when a nonce has already been used.
var ErrReplay = errors.New("auth: replay detected")

// ErrGuardFull is returned when the guard holds DefaultReplayMaxEntries (or
// the configured maximum) unexpired nonces and cannot record another without
// forgetting a live one.
var ErrGuardFull = errors.New("auth: replay guard full")

// entry is a replay-guard record: the nonce it is stored under and when it
// expires.
type entry struct {
	nonce   string
	expires time.Time
}

// ReplayGuard enforces one-time use of nonces, per protocol §7.2. It is safe
// for concurrent use.
//
// The guard is keyed on the nonce alone. The nonce is covered by the call
// signature, so it identifies one signed call; keying on the source address as
// well would let a captured call be replayed from any other address (UDP
// sources are trivially spoofed, and behind a resolver every client shares the
// resolver's address).
type ReplayGuard struct {
	max   int
	ttl   time.Duration
	mu    sync.Mutex
	seen  map[string]*list.Element
	order *list.List // front = newest, back = oldest (entries share one TTL)
	stop  chan struct{}
}

// NewReplayGuard builds a guard retaining at most max nonces, each expiring
// ttl after first use. A background reaper removes expired entries at half the
// TTL interval. Call Close to stop the reaper.
func NewReplayGuard(max int, ttl time.Duration) *ReplayGuard {
	if max <= 0 {
		max = DefaultReplayMaxEntries
	}
	if ttl <= 0 {
		ttl = DefaultReplayTTL
	}
	g := &ReplayGuard{
		max:   max,
		ttl:   ttl,
		seen:  make(map[string]*list.Element),
		order: list.New(),
		stop:  make(chan struct{}),
	}
	go g.reaper()
	return g
}

// Close stops the background reaper goroutine.
func (g *ReplayGuard) Close() {
	select {
	case <-g.stop:
	default:
		close(g.stop)
	}
}

// Check records nonce as used at now. It returns nil for a fresh nonce,
// ErrReplay if the nonce was already used and has not expired, and
// ErrGuardFull if the guard is at capacity with unexpired nonces.
func (g *ReplayGuard) Check(nonce string, now time.Time) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if el, ok := g.seen[nonce]; ok {
		if now.After(el.Value.(entry).expires) {
			// Expired but not yet reaped: forget it and treat as fresh.
			g.order.Remove(el)
			delete(g.seen, nonce)
		} else {
			return ErrReplay
		}
	}
	if g.order.Len() >= g.max {
		g.evictLocked(now)
		if g.order.Len() >= g.max {
			return ErrGuardFull
		}
	}
	g.seen[nonce] = g.order.PushFront(entry{nonce: nonce, expires: now.Add(g.ttl)})
	return nil
}

// evict removes entries whose expiry is before now. It takes the lock.
func (g *ReplayGuard) evict(now time.Time) {
	g.mu.Lock()
	g.evictLocked(now)
	g.mu.Unlock()
}

// Len returns the number of retained nonces (for tests and observability).
func (g *ReplayGuard) Len() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.order.Len()
}

// reaper periodically expires old entries.
func (g *ReplayGuard) reaper() {
	t := time.NewTicker(g.ttl / 2)
	defer t.Stop()
	for {
		select {
		case <-g.stop:
			return
		case <-t.C:
			g.evict(time.Now())
		}
	}
}

// evictLocked removes all entries whose expiry is before now. Callers must
// hold g.mu. Entries are ordered oldest-first from the back, so iteration stops
// at the first still-live entry.
func (g *ReplayGuard) evictLocked(now time.Time) {
	for e := g.order.Back(); e != nil; {
		next := e.Prev()
		en := e.Value.(entry)
		if !now.After(en.expires) {
			break
		}
		g.order.Remove(e)
		delete(g.seen, en.nonce)
		e = next
	}
}
