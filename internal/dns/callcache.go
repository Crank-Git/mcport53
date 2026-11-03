package dns

import (
	"container/list"
	"sync"
	"time"
)

// Call-cache defaults. The TTL covers the replay window (2 x 5 minutes plus a
// second), so a retransmitted copy is answered from the cache for as long as
// replay protection would otherwise reject it.
const (
	DefaultCallCacheEntries = 8192
	DefaultCallCacheTTL     = 10*time.Minute + time.Second
)

// callWaitLimit bounds how long a duplicate waits for the first copy (a
// variable so tests can shorten it).
var callWaitLimit = 2 * time.Minute

// callCache deduplicates retransmitted call queries. Resolvers re-send a query
// whose answer is slow, and their 0x20 fallback re-sends the same name. The
// first copy of a call name runs the call; concurrent and later copies wait
// for it and get the same answer, so a tool runs once per call and a copy
// never trips replay protection. Entries are keyed on the lowercased question
// name, which includes the nonce, so distinct calls never share an entry.
type callCache struct {
	max int
	ttl time.Duration
	now func() time.Time

	mu      sync.Mutex
	entries map[string]*list.Element
	order   *list.List // front = newest
}

type callEntry struct {
	key     string
	done    chan struct{} // closed when txt is set (or the leader gave up)
	txt     string        // envelope text; "" if the leader failed
	expires time.Time     // zero while in flight
}

func newCallCache(max int, ttl time.Duration) *callCache {
	if max <= 0 {
		max = DefaultCallCacheEntries
	}
	if ttl <= 0 {
		ttl = DefaultCallCacheTTL
	}
	return &callCache{max: max, ttl: ttl, now: time.Now, entries: make(map[string]*list.Element), order: list.New()}
}

// begin returns the entry for key and whether the caller is its leader (the
// copy that must run the call). It returns nil when the cache is full of
// in-flight calls, in which case the caller runs the call uncached.
func (c *callCache) begin(key string) (e *callEntry, leader bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if el, ok := c.entries[key]; ok {
		e := el.Value.(*callEntry)
		if e.expires.IsZero() || !now.After(e.expires) {
			return e, false
		}
		c.removeLocked(el)
	}
	for c.order.Len() >= c.max {
		if !c.evictOneLocked(now) {
			return nil, true
		}
	}
	e = &callEntry{key: key, done: make(chan struct{})}
	c.entries[key] = c.order.PushFront(e)
	return e, true
}

// finish records the leader's answer and releases waiters.
func (c *callCache) finish(e *callEntry, txt string) {
	c.mu.Lock()
	e.txt = txt
	e.expires = c.now().Add(c.ttl)
	c.mu.Unlock()
	close(e.done)
}

// abort releases waiters without an answer and forgets the entry, so a later
// copy runs the call again.
func (c *callCache) abort(e *callEntry) {
	c.mu.Lock()
	if el, ok := c.entries[e.key]; ok && el.Value == e {
		c.removeLocked(el)
	}
	c.mu.Unlock()
	close(e.done)
}

// wait blocks until e is finished or the wait limit passes, returning the
// answer and whether one is available.
func (c *callCache) wait(e *callEntry) (string, bool) {
	select {
	case <-e.done:
	case <-time.After(callWaitLimit):
		return "", false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return e.txt, e.txt != ""
}

// len reports the number of entries (for tests).
func (c *callCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}

// evictOneLocked removes the oldest finished entry (expired or not). It
// reports false when every entry is still in flight.
func (c *callCache) evictOneLocked(now time.Time) bool {
	for el := c.order.Back(); el != nil; el = el.Prev() {
		if !el.Value.(*callEntry).expires.IsZero() {
			c.removeLocked(el)
			return true
		}
	}
	return false
}

func (c *callCache) removeLocked(el *list.Element) {
	c.order.Remove(el)
	delete(c.entries, el.Value.(*callEntry).key)
}
