package mcp

import (
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"github.com/Crank-Git/mcport53/internal/codec"
)

// Job defaults (protocol §4.3).
const (
	// DefaultInlineBudget is how long a call may run before it is answered
	// "queued" and continues as a job. It is kept well under the upstream
	// timeout of common resolvers (about a second), so a slow tool does not
	// make the resolver give up on the call query.
	DefaultInlineBudget = 750 * time.Millisecond
	DefaultMaxJobs      = 1024
	DefaultJobTTL       = 5 * time.Minute // how long a finished job is kept
)

var errJobsFull = errors.New("mcp: too many jobs in progress")

type job struct {
	tool     string
	done     chan struct{}
	final    *codec.Envelope // the call's answer; set when done is closed
	finished time.Time
}

// jobStore tracks calls that outlived the inline budget. It is safe for
// concurrent use.
type jobStore struct {
	max int
	ttl time.Duration
	now func() time.Time

	mu   sync.Mutex
	jobs map[string]*job
}

func newJobStore(max int, ttl time.Duration) *jobStore {
	if max <= 0 {
		max = DefaultMaxJobs
	}
	if ttl <= 0 {
		ttl = DefaultJobTTL
	}
	return &jobStore{max: max, ttl: ttl, now: time.Now, jobs: make(map[string]*job)}
}

// start registers a job that completes when result delivers the call's
// answer.
func (js *jobStore) start(tool string, result <-chan *codec.Envelope) (string, error) {
	id, err := codec.RandomJob()
	if err != nil {
		return "", err
	}
	js.mu.Lock()
	js.expireLocked()
	if len(js.jobs) >= js.max {
		js.mu.Unlock()
		return "", errJobsFull
	}
	j := &job{tool: tool, done: make(chan struct{})}
	js.jobs[id] = j
	js.mu.Unlock()

	go func() {
		final := <-result
		js.mu.Lock()
		j.final = final
		j.finished = js.now()
		js.mu.Unlock()
		close(j.done)
	}()
	return id, nil
}

// get returns the job, or nil if it is unknown or expired.
func (js *jobStore) get(id string) *job {
	js.mu.Lock()
	defer js.mu.Unlock()
	js.expireLocked()
	return js.jobs[id]
}

func (js *jobStore) len() int {
	js.mu.Lock()
	defer js.mu.Unlock()
	return len(js.jobs)
}

func (js *jobStore) expireLocked() {
	now := js.now()
	for id, j := range js.jobs {
		if !j.finished.IsZero() && now.Sub(j.finished) > js.ttl {
			delete(js.jobs, id)
		}
	}
}

// WithInlineBudget sets how long a call may run before it is answered
// "queued" and continues as a job (default DefaultInlineBudget).
func (s *Server) WithInlineBudget(d time.Duration) *Server {
	s.inlineBudget = d
	return s
}

// WithJobLimits bounds the job store: at most max jobs (running or finished)
// at once, and finished jobs are kept for ttl.
func (s *Server) WithJobLimits(max int, ttl time.Duration) *Server {
	s.jobs = newJobStore(max, ttl)
	return s
}

// onJob answers a job poll (protocol §4.3): "running" while the call runs; when
// it has finished, "done" with the session, chunk count and compression of the
// stored result, or the call's "error" envelope.
func (s *Server) onJob(id string) *codec.Envelope {
	j := s.jobs.get(id)
	if j == nil {
		return codec.Error("", "mcp: unknown or expired job")
	}
	select {
	case <-j.done:
	default:
		return codec.Running(j.tool, id)
	}
	final := j.final
	switch final.Status {
	case codec.StatusChunked:
		// The result is already stored under its session.
		d := codec.Done(j.tool, id, final.Session)
		d.Total, d.Compression, d.Ms = final.Total, final.Compression, final.Ms
		return d
	case codec.StatusOK:
		payload := []byte(final.Result)
		if final.Compression != "" {
			raw, err := base64.StdEncoding.DecodeString(final.Result)
			if err != nil {
				return codec.Error(j.tool, "mcp: corrupt job result")
			}
			payload = raw
		}
		session, err := s.results.Put(payload)
		if err != nil {
			return codec.Error(j.tool, err.Error())
		}
		d := codec.Done(j.tool, id, session)
		d.Total = len(codec.ChunkPayload(payload, codec.ChunkSize))
		d.Compression, d.Ms = final.Compression, final.Ms
		return d
	default:
		e := *final
		e.Job = id
		return &e
	}
}
