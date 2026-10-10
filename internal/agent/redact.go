package agent

import (
	"bytes"
	"encoding/json"
	"io"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
)

const (
	// maxRedactLine bounds the buffer for output without line breaks.
	maxRedactLine = 16 << 10
	// shortSecret is the length below which a secret is masked only as a
	// whole token, so short values do not garble ordinary words.
	shortSecret  = 4
	redactedMark = "[redacted]"
)

// redactWriter masks secrets in frpc's output before it reaches w. It
// works line by line, holding back enough bytes that a secret split
// across writes, or one that contains a line break, is still found.
type redactWriter struct {
	mu    sync.Mutex
	w     io.Writer
	long  [][]byte
	short []*regexp.Regexp
	// tail is how many bytes may belong to a secret not yet complete.
	tail int
	// hold is the same for secrets that contain a line break.
	hold int
	buf  []byte
}

func newRedactWriter(w io.Writer, secrets ...string) *redactWriter {
	r := &redactWriter{w: w}
	seen := map[string]bool{}
	for _, s := range secrets {
		for _, form := range secretForms(s) {
			if form == "" || seen[form] {
				continue
			}
			seen[form] = true
			r.tail = max(r.tail, len(form)-1)
			if strings.Contains(form, "\n") {
				r.hold = max(r.hold, len(form)-1)
			}
			if len(form) < shortSecret {
				r.short = append(r.short, regexp.MustCompile(`(^|[^A-Za-z0-9])`+regexp.QuoteMeta(form)+`($|[^A-Za-z0-9])`))
				continue
			}
			r.long = append(r.long, []byte(form))
		}
	}
	// Longest first, so a secret that contains another is masked whole.
	slices.SortFunc(r.long, func(a, b []byte) int { return len(b) - len(a) })
	return r
}

// secretForms is a secret as written and as Go's %q and JSON escape it.
func secretForms(s string) []string {
	if s == "" {
		return nil
	}
	q := strconv.Quote(s)
	out := []string{s, q[1 : len(q)-1]}
	if j, err := json.Marshal(s); err == nil {
		out = append(out, string(j[1:len(j)-1]))
	}
	return out
}

func (r *redactWriter) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf = append(r.buf, p...)
	// Emit whole lines, but never the last bytes that could start a
	// secret spanning a line break.
	limit := max(len(r.buf)-r.hold, 0)
	if i := bytes.LastIndexByte(r.buf[:limit], '\n'); i >= 0 {
		if err := r.emit(r.safeCut(i + 1)); err != nil {
			return 0, err
		}
	}
	if len(r.buf) > maxRedactLine {
		if err := r.emit(r.safeCut(len(r.buf) - min(len(r.buf), r.tail))); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

// safeCut moves cut back to the start of any secret that spans it, so the
// buffer is never split inside one.
func (r *redactWriter) safeCut(cut int) int {
	for {
		moved := cut
		for _, s := range r.long {
			for from := max(cut-len(s)+1, 0); from < cut; {
				i := bytes.Index(r.buf[from:], s)
				if i < 0 || from+i >= cut {
					break
				}
				if from+i+len(s) > cut {
					moved = min(moved, from+i)
				}
				from += i + 1
			}
		}
		for _, re := range r.short {
			for _, m := range re.FindAllIndex(r.buf, -1) {
				if m[0] < cut && m[1] > cut {
					moved = min(moved, m[0])
				}
			}
		}
		if moved == cut {
			return cut
		}
		cut = moved
	}
}

// emit masks and writes the first n buffered bytes.
func (r *redactWriter) emit(n int) error {
	if n <= 0 {
		return nil
	}
	err := r.write(r.mask(r.buf[:n]))
	r.buf = append(r.buf[:0], r.buf[n:]...)
	return err
}

// Flush writes whatever is buffered; call it when the process has exited.
func (r *redactWriter) Flush() {
	r.mu.Lock()
	defer r.mu.Unlock()
	_ = r.emit(len(r.buf))
}

func (r *redactWriter) write(b []byte) error {
	_, err := r.w.Write(b)
	return err
}

func (r *redactWriter) mask(b []byte) []byte {
	out := append([]byte(nil), b...)
	for _, s := range r.long {
		out = bytes.ReplaceAll(out, s, []byte(redactedMark))
	}
	for _, re := range r.short {
		// Run twice: adjacent matches share a boundary character.
		for range 2 {
			out = re.ReplaceAll(out, []byte("${1}"+redactedMark+"${2}"))
		}
	}
	return out
}

// proxySecrets returns the proxy user name and password, as written in the
// URL and decoded, since either form can show up in a log line.
func proxySecrets(raw string) []string {
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return nil
	}
	var out []string
	if name := u.User.Username(); name != "" {
		out = append(out, name)
	}
	if pass, ok := u.User.Password(); ok && pass != "" {
		out = append(out, pass)
	}
	_, rest, _ := strings.Cut(raw, "://")
	if at := strings.LastIndexByte(rest, '@'); at >= 0 {
		user, pass, _ := strings.Cut(rest[:at], ":")
		out = append(out, user, pass)
	}
	return slices.DeleteFunc(out, func(s string) bool { return s == "" })
}
