package auth

import (
	"container/list"
	"sync"
	"time"
)

// DefaultReplayMaxEntries is the maximum number of (caller, nonce) pairs a
// ReplayGuard retains before evicting the oldest.
const DefaultReplayMaxEntries = 4096

// DefaultReplayTTL is how long a (caller, nonce) pair is considered used before
// it may be reused. It bounds how far in the past a captured call can be
// replayed once its nonce has been evicted.
const DefaultReplayTTL = 5 * time.Minute

// entry is a replay-guard record: the key it is stored under and when it
// expires.
type entry struct {
	key     string
	expires time.Time
}

// ReplayGuard enforces one-time use of nonces per caller, per protocol §7.2.
// It is safe for concurrent use. A caller is any opaque string (typically the
// remote network address); a nonce is the per-call uncacheability nonce.
type ReplayGuard struct {
	max   int
	ttl   time.Duration
	mu    sync.Mutex
	seen  map[string]*list.Element
	order *list.List // front = most recently used, back = oldest
	stop  chan struct{}
}

// NewReplayGuard builds a guard retaining at most max (caller, nonce) pairs,
// each expiring after ttl. A background reaper removes expired entries at half
// the TTL interval. Call Close to stop the reaper.
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

// Check reports whether (caller, nonce) is fresh. On a fresh pair it records
// the pair as used (updating its expiry and recency) and returns true. If the
// pair was already seen it returns false, signalling a replay.
func (g *ReplayGuard) Check(caller, nonce string, now time.Time) bool {
	key := caller + "\x00" + nonce

	g.mu.Lock()
	defer g.mu.Unlock()

	if _, ok := g.seen[key]; ok {
		return false
	}
	elem := g.order.PushFront(entry{key: key, expires: now.Add(g.ttl)})
	g.seen[key] = elem

	// Evict the oldest entry if we have exceeded capacity.
	if g.order.Len() > g.max {
		oldest := g.order.Back()
		g.order.Remove(oldest)
		delete(g.seen, oldest.Value.(entry).key)
	}
	return true
}

// evict removes entries whose expiry is at or before now. It takes the lock.
func (g *ReplayGuard) evict(now time.Time) {
	g.mu.Lock()
	g.evictLocked(now)
	g.mu.Unlock()
}

// Len returns the number of retained pairs (for tests and observability).
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

// evictLocked removes all entries whose expiry is at or before now. Callers
// must hold g.mu. Entries are ordered oldest-first from the back, so iteration
// stops at the first still-live entry.
func (g *ReplayGuard) evictLocked(now time.Time) {
	for e := g.order.Back(); e != nil; {
		next := e.Prev()
		en := e.Value.(entry)
		if !now.After(en.expires) {
			break
		}
		g.order.Remove(e)
		delete(g.seen, en.key)
		e = next
	}
}
