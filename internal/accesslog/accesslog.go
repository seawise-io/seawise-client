// Package accesslog keeps the agent's local record of forwarded
// connections: one JSON line per connection with addresses, byte counts,
// duration and result. It never holds payloads, headers or visitor
// identity. Files live in the v2 store directory, are readable only by the
// agent's user, rotate daily or by size, and are deleted after the
// retention period or when the set exceeds its size cap.
package accesslog

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/seawise/client/internal/store"
)

const (
	DefaultRetention     = 30 * 24 * time.Hour
	DefaultMaxFileBytes  = 4 << 20
	DefaultMaxTotalBytes = 32 << 20
	DefaultQueueSize     = 1024
	RotateAfter          = 24 * time.Hour
	DefaultPage          = 50
	MaxPage              = 200
	MaxLine              = 4 << 10
	pruneEvery           = time.Hour
	chunkSize            = 64 << 10
	maxField             = 128
)

const (
	ResultOK          = "ok"
	ResultRefused     = "refused"
	ResultUnreachable = "unreachable"
	ResultBusy        = "busy"
)

var knownResult = map[string]bool{ResultOK: true, ResultRefused: true, ResultUnreachable: true, ResultBusy: true}

var (
	ErrCursor = errors.New("invalid cursor")
	nameRE    = regexp.MustCompile(`^access-([0-9]{19})\.log$`)
	digitsRE  = regexp.MustCompile(`^[0-9]{1,19}$`)
)

// Entry is one forwarded connection. Adding a field needs a privacy
// review: visitor identity is out of scope until visitor tokens are
// verified locally.
type Entry struct {
	Time       time.Time `json:"time"`
	App        string    `json:"app"`
	Peer       string    `json:"peer"`
	Target     string    `json:"target"`
	BytesIn    int64     `json:"bytes_in"`
	BytesOut   int64     `json:"bytes_out"`
	DurationMS int64     `json:"duration_ms"`
	Result     string    `json:"result"`
}

type Config struct {
	Dir           string
	Retention     time.Duration
	MaxFileBytes  int64
	MaxTotalBytes int64
	QueueSize     int
	Now           func() time.Time
	Logger        *slog.Logger
}

type Status struct {
	Dropped     uint64 `json:"dropped"`
	WriteErrors uint64 `json:"write_errors"`
}

type Page struct {
	Entries []Entry `json:"entries"`
	Next    string  `json:"next,omitempty"`
}

type Log struct {
	cfg   Config
	log   *slog.Logger
	queue chan Entry
	reqs  chan func()
	stop  chan struct{}
	done  chan struct{}

	mu     sync.RWMutex
	closed bool

	dropped   atomic.Uint64
	writeErrs atomic.Uint64

	// Owned by the writer goroutine.
	cur      *os.File
	curStart int64
	curSize  int64
}

// Open checks dir, applies retention to existing files and starts the
// writer.
func Open(cfg Config) (*Log, error) {
	if cfg.Dir == "" {
		return nil, errors.New("access log directory required")
	}
	if err := store.CheckDir(cfg.Dir); err != nil {
		return nil, err
	}
	if cfg.Retention <= 0 {
		cfg.Retention = DefaultRetention
	}
	if cfg.MaxFileBytes <= 0 {
		cfg.MaxFileBytes = DefaultMaxFileBytes
	}
	if cfg.MaxTotalBytes <= 0 {
		cfg.MaxTotalBytes = DefaultMaxTotalBytes
	}
	cfg.MaxFileBytes = min(cfg.MaxFileBytes, cfg.MaxTotalBytes)
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = DefaultQueueSize
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	l := &Log{
		cfg: cfg, log: cfg.Logger.With("component", "accesslog"),
		queue: make(chan Entry, cfg.QueueSize), reqs: make(chan func()),
		stop: make(chan struct{}), done: make(chan struct{}),
	}
	l.prune()
	go l.run()
	return l, nil
}

// Record queues e for writing. It never blocks; when the queue is full the
// entry is dropped and counted.
func (l *Log) Record(e Entry) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.closed {
		l.dropped.Add(1)
		return
	}
	select {
	case l.queue <- e:
	default:
		l.dropped.Add(1)
	}
}

// Flush waits until every entry queued before the call is written.
func (l *Log) Flush() { l.do(func() {}) }

// Prune applies retention and the size cap now.
func (l *Log) Prune() { l.do(l.prune) }

func (l *Log) Status() Status {
	return Status{Dropped: l.dropped.Load(), WriteErrors: l.writeErrs.Load()}
}

// Close writes what is queued and stops the writer.
func (l *Log) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	close(l.stop)
	l.mu.Unlock()
	<-l.done
	return nil
}

// do runs fn on the writer goroutine after the entries already queued.
func (l *Log) do(fn func()) {
	ran := make(chan struct{})
	select {
	case l.reqs <- func() { l.drain(); fn(); close(ran) }:
		<-ran
	case <-l.done:
	}
}

func (l *Log) run() {
	defer close(l.done)
	tick := time.NewTicker(pruneEvery)
	defer tick.Stop()
	for {
		select {
		case e := <-l.queue:
			l.write(e)
		case fn := <-l.reqs:
			fn()
		case <-tick.C:
			if l.cur != nil && l.age(l.curStart) >= RotateAfter {
				l.closeCurrent()
			}
			l.prune()
		case <-l.stop:
			l.drain()
			l.closeCurrent()
			return
		}
	}
}

func (l *Log) drain() {
	for {
		select {
		case e := <-l.queue:
			l.write(e)
		default:
			return
		}
	}
}

func (l *Log) age(start int64) time.Duration {
	return l.cfg.Now().Sub(time.Unix(0, start))
}

func (l *Log) write(e Entry) {
	line, ok := encode(e)
	if !ok {
		l.writeErrs.Add(1)
		return
	}
	if l.cur != nil && (l.age(l.curStart) >= RotateAfter || l.curSize+int64(len(line)) > l.cfg.MaxFileBytes) {
		l.closeCurrent()
	}
	if l.cur == nil {
		if err := l.openCurrent(int64(len(line))); err != nil {
			l.writeErrs.Add(1)
			l.log.Warn("access log unavailable", "error", err)
			return
		}
	}
	n, err := l.cur.Write(line)
	l.curSize += int64(n)
	if err != nil {
		l.writeErrs.Add(1)
		l.log.Warn("access log write failed", "error", err)
		l.closeCurrent()
	}
}

func (l *Log) closeCurrent() {
	if l.cur != nil {
		_ = l.cur.Close()
		l.cur = nil
	}
}

// openCurrent continues the newest file if it is young, has room for need
// more bytes and is safe to append to, and otherwise starts a new one named
// after the current time.
func (l *Log) openCurrent(need int64) error {
	files, err := l.files()
	if err != nil {
		return err
	}
	if len(files) > 0 {
		last := files[len(files)-1]
		if l.age(last.start) < RotateAfter && last.size+need <= l.cfg.MaxFileBytes {
			if f, err := store.OpenOwned(last.path, os.O_WRONLY|os.O_APPEND); err == nil {
				l.cur, l.curStart, l.curSize = f, last.start, last.size
				return nil
			}
		}
	}
	start := l.cfg.Now().UnixNano()
	if len(files) > 0 && start <= files[len(files)-1].start {
		start = files[len(files)-1].start + 1
	}
	if start < 0 {
		start = 0
	}
	f, err := store.OpenOwned(filepath.Join(l.cfg.Dir, nameFor(start)), os.O_WRONLY|os.O_APPEND|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return err
	}
	l.cur, l.curStart, l.curSize = f, start, 0
	l.prune()
	return nil
}

// prune deletes files whose start is past retention, then the oldest
// files while the others leave no room for a full current file.
func (l *Log) prune() {
	files, err := l.files()
	if err != nil {
		l.log.Warn("access log prune failed", "error", err)
		return
	}
	cutoff := l.cfg.Now().Add(-l.cfg.Retention).UnixNano()
	var keep []logFile
	for _, f := range files {
		if f.start < cutoff {
			l.remove(f)
			continue
		}
		keep = append(keep, f)
	}
	var others int64
	for _, f := range keep {
		if l.cur == nil || f.start != l.curStart {
			others += f.size
		}
	}
	for _, f := range keep {
		if others <= l.cfg.MaxTotalBytes-l.cfg.MaxFileBytes {
			break
		}
		if l.cur != nil && f.start == l.curStart {
			continue
		}
		l.remove(f)
		others -= f.size
	}
}

func (l *Log) remove(f logFile) {
	if l.cur != nil && f.start == l.curStart {
		l.closeCurrent()
	}
	if err := os.Remove(f.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		l.log.Warn("access log delete failed", "error", err)
	}
}

type logFile struct {
	path  string
	start int64
	size  int64
}

// files lists log files oldest first.
func (l *Log) files() ([]logFile, error) {
	ents, err := os.ReadDir(l.cfg.Dir)
	if err != nil {
		return nil, err
	}
	var out []logFile
	for _, e := range ents {
		m := nameRE.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		start, err := strconv.ParseInt(m[1], 10, 64)
		if err != nil {
			continue
		}
		var size int64
		if info, err := e.Info(); err == nil {
			size = info.Size()
		}
		out = append(out, logFile{path: filepath.Join(l.cfg.Dir, e.Name()), start: start, size: size})
	}
	slices.SortFunc(out, func(a, b logFile) int { return cmpInt(a.start, b.start) })
	return out, nil
}

func cmpInt(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func nameFor(start int64) string { return fmt.Sprintf("access-%019d.log", start) }

func fileName(t time.Time) string { return nameFor(t.UnixNano()) }

// encode clips and cleans e so that the line always parses.
func encode(e Entry) ([]byte, bool) {
	if !knownResult[e.Result] || e.Time.IsZero() {
		return nil, false
	}
	e.Time = e.Time.UTC().Truncate(time.Millisecond)
	e.App, e.Peer, e.Target = cleanField(e.App), cleanField(e.Peer), cleanField(e.Target)
	e.BytesIn, e.BytesOut, e.DurationMS = max(e.BytesIn, 0), max(e.BytesOut, 0), max(e.DurationMS, 0)
	b, err := json.Marshal(e)
	if err != nil || len(b) >= MaxLine {
		return nil, false
	}
	return append(b, '\n'), true
}

func cleanField(s string) string {
	var b strings.Builder
	for i := 0; i < len(s) && b.Len() < maxField; i++ {
		c := s[i]
		if c < 0x20 || c > 0x7e {
			c = '?'
		}
		b.WriteByte(c)
	}
	return b.String()
}

func validField(s string) bool {
	if len(s) > maxField {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// ParseLine accepts exactly one entry object with every field present and
// valid, and nothing else.
func ParseLine(line []byte) (Entry, error) {
	var w struct {
		Time       *time.Time `json:"time"`
		App        *string    `json:"app"`
		Peer       *string    `json:"peer"`
		Target     *string    `json:"target"`
		BytesIn    *int64     `json:"bytes_in"`
		BytesOut   *int64     `json:"bytes_out"`
		DurationMS *int64     `json:"duration_ms"`
		Result     *string    `json:"result"`
	}
	if len(line) > MaxLine {
		return Entry{}, errors.New("line too long")
	}
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&w); err != nil {
		return Entry{}, errors.New("malformed entry")
	}
	if _, err := dec.Token(); err != io.EOF {
		return Entry{}, errors.New("trailing data")
	}
	if w.Time == nil || w.App == nil || w.Peer == nil || w.Target == nil || w.BytesIn == nil ||
		w.BytesOut == nil || w.DurationMS == nil || w.Result == nil {
		return Entry{}, errors.New("missing field")
	}
	e := Entry{Time: w.Time.UTC(), App: *w.App, Peer: *w.Peer, Target: *w.Target,
		BytesIn: *w.BytesIn, BytesOut: *w.BytesOut, DurationMS: *w.DurationMS, Result: *w.Result}
	if e.Time.IsZero() || !validField(e.App) || !validField(e.Peer) || !validField(e.Target) ||
		e.BytesIn < 0 || e.BytesOut < 0 || e.DurationMS < 0 || !knownResult[e.Result] {
		return Entry{}, errors.New("invalid entry")
	}
	return e, nil
}

// Page returns up to limit entries, newest first, starting at cursor (empty
// for the newest entry). Next is empty when there is nothing older.
func (l *Log) Page(cursor string, limit int) (Page, error) {
	if limit <= 0 {
		limit = DefaultPage
	}
	limit = min(limit, MaxPage)
	files, err := l.files()
	if err != nil {
		return Page{}, err
	}
	i, off := len(files)-1, int64(-1)
	if cursor != "" {
		start, o, err := parseCursor(cursor)
		if err != nil {
			return Page{}, err
		}
		i = -1
		for j := len(files) - 1; j >= 0; j-- {
			if files[j].start == start {
				i, off = j, o
				break
			}
			if files[j].start < start {
				i = j
				break
			}
		}
	}
	out := Page{Entries: []Entry{}}
	for ; i >= 0; i, off = i-1, -1 {
		pos, err := readBack(files[i].path, off, limit-len(out.Entries), &out.Entries)
		if err != nil {
			continue
		}
		if len(out.Entries) >= limit {
			if pos > 0 || i > 0 {
				out.Next = fmt.Sprintf("%d:%d", files[i].start, pos)
			}
			break
		}
	}
	return out, nil
}

func parseCursor(c string) (int64, int64, error) {
	a, b, ok := strings.Cut(c, ":")
	if !ok || !digitsRE.MatchString(a) || !digitsRE.MatchString(b) {
		return 0, 0, ErrCursor
	}
	start, err1 := strconv.ParseInt(a, 10, 64)
	off, err2 := strconv.ParseInt(b, 10, 64)
	if err1 != nil || err2 != nil {
		return 0, 0, ErrCursor
	}
	return start, off, nil
}

// readBack appends up to n entries from path, reading lines backward from
// off (-1 for the end of the file), and returns the offset of the last line
// consumed. Lines that are too long or invalid are skipped.
func readBack(path string, off int64, n int, out *[]Entry) (int64, error) {
	f, err := store.OpenOwned(path, os.O_RDONLY)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return 0, err
	}
	r := &backReader{f: f}
	size := info.Size()
	pos := off
	if pos < 0 || pos > size {
		// Start after the last complete line; a partial line at the end
		// is still being written or was cut short.
		nl, err := r.lastNewline(size)
		if err != nil {
			return 0, err
		}
		pos = nl + 1
	}
	for added := 0; pos > 0 && added < n; {
		end := pos - 1
		nl, err := r.lastNewline(end)
		if err != nil {
			return pos, err
		}
		start := nl + 1
		if end-start <= MaxLine {
			line, err := r.load(start, end)
			if err != nil {
				return pos, err
			}
			if e, err := ParseLine(line); err == nil {
				*out = append(*out, e)
				added++
			}
		}
		pos = start
	}
	return pos, nil
}

// backReader caches one window of a file for backward scans.
type backReader struct {
	f     *os.File
	buf   []byte
	start int64
}

// load returns the bytes in [lo, hi), which must span at most chunkSize.
func (r *backReader) load(lo, hi int64) ([]byte, error) {
	if lo >= r.start && hi <= r.start+int64(len(r.buf)) {
		return r.buf[lo-r.start : hi-r.start], nil
	}
	from := max(0, hi-chunkSize)
	if lo < from {
		return nil, errors.New("range too large")
	}
	if cap(r.buf) < chunkSize {
		r.buf = make([]byte, chunkSize)
	}
	r.buf = r.buf[:hi-from]
	if _, err := r.f.ReadAt(r.buf, from); err != nil {
		r.buf = r.buf[:0]
		return nil, err
	}
	r.start = from
	return r.buf[lo-from:], nil
}

// lastNewline returns the offset of the last '\n' before pos, or -1.
func (r *backReader) lastNewline(pos int64) (int64, error) {
	for pos > 0 {
		lo := max(0, pos-chunkSize)
		b, err := r.load(lo, pos)
		if err != nil {
			return 0, err
		}
		if i := bytes.LastIndexByte(b, '\n'); i >= 0 {
			return lo + int64(i), nil
		}
		pos = lo
	}
	return -1, nil
}
