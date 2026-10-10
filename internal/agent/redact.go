package agent

import (
	"bytes"
	"io"
	"net/url"
	"slices"
	"strings"
	"sync"
)

const (
	// maxRedactLine bounds the buffer for output without line breaks.
	maxRedactLine = 16 << 10
	// minSecretLen leaves very short values alone, since masking them
	// would garble ordinary text.
	minSecretLen = 4
	redactedMark = "[redacted]"
)

// redactWriter masks secrets in frpc's output before it reaches w. It
// works line by line so a secret split across writes is still found.
type redactWriter struct {
	mu      sync.Mutex
	w       io.Writer
	secrets [][]byte
	maxLen  int
	buf     []byte
}

func newRedactWriter(w io.Writer, secrets ...string) *redactWriter {
	r := &redactWriter{w: w}
	for _, s := range secrets {
		if len(s) >= minSecretLen {
			r.secrets = append(r.secrets, []byte(s))
			r.maxLen = max(r.maxLen, len(s))
		}
	}
	// Longest first, so a secret that contains another is masked whole.
	slices.SortFunc(r.secrets, func(a, b []byte) int { return len(b) - len(a) })
	return r
}

func (r *redactWriter) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf = append(r.buf, p...)
	if i := bytes.LastIndexByte(r.buf, '\n'); i >= 0 {
		if err := r.emit(r.buf[:i+1]); err != nil {
			return 0, err
		}
		r.buf = append(r.buf[:0], r.buf[i+1:]...)
	}
	if len(r.buf) > maxRedactLine {
		// Mask first, then keep a tail shorter than any secret, so a
		// secret that has only partly arrived is never written.
		masked := r.mask(r.buf)
		keep := min(len(masked), max(r.maxLen-1, 0))
		if err := r.write(masked[:len(masked)-keep]); err != nil {
			return 0, err
		}
		r.buf = append(r.buf[:0], masked[len(masked)-keep:]...)
	}
	return len(p), nil
}

// Flush writes whatever is buffered; call it when the process has exited.
func (r *redactWriter) Flush() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.buf) > 0 {
		_ = r.emit(r.buf)
		r.buf = r.buf[:0]
	}
}

func (r *redactWriter) emit(b []byte) error { return r.write(r.mask(b)) }

func (r *redactWriter) write(b []byte) error {
	_, err := r.w.Write(b)
	return err
}

func (r *redactWriter) mask(b []byte) []byte {
	out := append([]byte(nil), b...)
	for _, s := range r.secrets {
		out = bytes.ReplaceAll(out, s, []byte(redactedMark))
	}
	return out
}

// proxySecrets returns the proxy password as written in the URL and
// decoded, since either form can show up in a log line.
func proxySecrets(raw string) []string {
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return nil
	}
	pass, ok := u.User.Password()
	if !ok || pass == "" {
		return nil
	}
	out := []string{pass}
	_, rest, _ := strings.Cut(raw, "://")
	if at := strings.LastIndexByte(rest, '@'); at >= 0 {
		if _, enc, ok := strings.Cut(rest[:at], ":"); ok && enc != pass {
			out = append(out, enc)
		}
	}
	return out
}
