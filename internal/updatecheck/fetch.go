package updatecheck

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// Size caps. go-tuf passes a per-file limit (from signed metadata where it
// has one); maxFileSize bounds every download regardless.
const (
	maxRootSize      = 64 << 10
	maxTimestampSize = 16 << 10
	maxSnapshotSize  = 64 << 10
	maxTargetsSize   = 256 << 10
	maxReleaseSize   = 16 << 10
	maxKeySetSize    = 256 << 10
	maxFileSize      = 512 << 10
)

// fetcher downloads one file per call over HTTPS with the check's context,
// a per-request timeout covering the body, no redirects, and a size cap.
type fetcher struct {
	ctx    context.Context
	client *http.Client
	ua     string
}

func (f *fetcher) DownloadFile(u string, maxLength int64, _ time.Duration) ([]byte, error) {
	if maxLength <= 0 || maxLength > maxFileSize {
		maxLength = maxFileSize
	}
	req, err := http.NewRequestWithContext(f.ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", f.ua)
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &metadata.ErrDownloadHTTP{StatusCode: resp.StatusCode, URL: u}
	}
	if resp.ContentLength > maxLength {
		return nil, &metadata.ErrDownloadLengthMismatch{Msg: fmt.Sprintf("%s is %d bytes, more than %d", u, resp.ContentLength, maxLength)}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxLength+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxLength {
		return nil, &metadata.ErrDownloadLengthMismatch{Msg: fmt.Sprintf("%s is more than %d bytes", u, maxLength)}
	}
	return data, nil
}

func newHTTPClient(rt http.RoundTripper, timeout time.Duration) *http.Client {
	return &http.Client{
		Transport:     rt,
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}
