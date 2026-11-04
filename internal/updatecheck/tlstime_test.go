package updatecheck

import (
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultTransportUsesTheCheckClock(t *testing.T) {
	pinned := loadState(t, "E")["metadata/1.root.json"]
	at := time.Unix(1800000000, 0)
	c, err := New(Config{Root: pinned, AllowTestRoot: true, URL: "https://repo.invalid", Dir: filepath.Join(t.TempDir(), "tuf"),
		Channel: "stable", Version: "v2.0.0", Now: func() time.Time { return at }})
	if err != nil {
		t.Fatal(err)
	}
	tr, ok := c.cfg.Transport.(*http.Transport)
	if !ok || tr.TLSClientConfig.Time == nil || !tr.TLSClientConfig.Time().Equal(at) {
		t.Fatal("TLS certificates not checked on the check clock")
	}
}
