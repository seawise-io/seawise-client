package tufrepo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/config"
	"github.com/theupdateframework/go-tuf/v2/metadata/updater"
)

const localBase = "https://repo.invalid/"

// Report summarises a verified repository.
type Report struct {
	RootVersion, TargetsVersion, SnapshotVersion, TimestampVersion int64
	RootExpires, TargetsExpires, SnapshotExpires, TimestampExpires time.Time
	Targets                                                        []string
}

// Verify runs the TUF client workflow against the repository in dir,
// starting from trustedRoot at time now. With targets it also downloads
// and checks every target file.
func Verify(dir string, trustedRoot []byte, now time.Time, targets bool) (*Report, error) {
	cache, err := os.MkdirTemp("", "tuf-verify-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(cache)
	cfg, err := config.New(localBase+"metadata", trustedRoot)
	if err != nil {
		return nil, err
	}
	cfg.RemoteTargetsURL = localBase + "targets"
	cfg.LocalMetadataDir = filepath.Join(cache, "metadata")
	cfg.LocalTargetsDir = filepath.Join(cache, "targets")
	cfg.Fetcher = dirFetcher{dir: dir}
	up, err := updater.New(cfg)
	if err != nil {
		return nil, err
	}
	up.UnsafeSetRefTime(now)
	if err := up.Refresh(); err != nil {
		return nil, err
	}
	tm := up.GetTrustedMetadataSet()
	rep := &Report{
		RootVersion: tm.Root.Signed.Version, RootExpires: tm.Root.Signed.Expires,
		TargetsVersion: tm.Targets[metadata.TARGETS].Signed.Version, TargetsExpires: tm.Targets[metadata.TARGETS].Signed.Expires,
		SnapshotVersion: tm.Snapshot.Signed.Version, SnapshotExpires: tm.Snapshot.Signed.Expires,
		TimestampVersion: tm.Timestamp.Signed.Version, TimestampExpires: tm.Timestamp.Signed.Expires,
	}
	for name, tf := range up.GetTopLevelTargets() {
		rep.Targets = append(rep.Targets, name)
		if !targets {
			continue
		}
		if _, _, err := up.DownloadTarget(tf, "", ""); err != nil {
			return nil, fmt.Errorf("target %s: %w", name, err)
		}
	}
	slices.Sort(rep.Targets)
	return rep, nil
}

// dirFetcher serves localBase URLs from a repository directory.
type dirFetcher struct{ dir string }

func (f dirFetcher) DownloadFile(u string, maxLength int64, _ time.Duration) ([]byte, error) {
	rel, ok := strings.CutPrefix(u, localBase)
	if !ok || strings.Contains(rel, "..") {
		return nil, fmt.Errorf("unexpected URL %s", u)
	}
	fh, err := os.Open(filepath.Join(f.dir, filepath.FromSlash(rel)))
	if errors.Is(err, os.ErrNotExist) {
		return nil, &metadata.ErrDownloadHTTP{StatusCode: http.StatusNotFound, URL: u}
	}
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	return readCapped(fh, maxLength, u)
}

func readCapped(r io.Reader, maxLength int64, u string) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxLength+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxLength {
		return nil, &metadata.ErrDownloadLengthMismatch{Msg: fmt.Sprintf("%s is larger than %d bytes", u, maxLength)}
	}
	return data, nil
}

// Size caps for Pull.
const (
	pullRootMax      = 64 << 10
	pullTimestampMax = 16 << 10
	pullSnapshotMax  = 64 << 10
	pullTargetsMax   = 256 << 10
	pullMaxRoots     = 1024
)

// Pull downloads the root chain after trustedRoot and the current
// timestamp, snapshot and targets metadata from a static host, verifies
// them from trustedRoot (see Refresh for the expiry rule) and only then
// writes them to dir/metadata. Target files are not copied.
func Pull(ctx context.Context, hc *http.Client, base, dir string, trustedRoot []byte, now time.Time) error {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" {
		return errors.New("repository URL must be https")
	}
	pinned, err := metadata.Root().FromBytes(trustedRoot)
	if err != nil {
		return fmt.Errorf("trusted root: %w", err)
	}
	staging, err := os.MkdirTemp("", "tuf-pull-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging)
	if err := os.Mkdir(filepath.Join(staging, "metadata"), 0o700); err != nil {
		return err
	}
	get := func(name string, max int64) ([]byte, error) {
		full, err := url.JoinPath(base, "metadata", name)
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, full, nil)
		if err != nil {
			return nil, err
		}
		resp, err := hc.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, &metadata.ErrDownloadHTTP{StatusCode: resp.StatusCode, URL: full}
		}
		data, err := readCapped(resp.Body, max, full)
		if err != nil {
			return nil, err
		}
		return data, writeFile(filepath.Join(staging, "metadata", name), data)
	}
	for v := pinned.Signed.Version + 1; ; v++ {
		if v > pinned.Signed.Version+pullMaxRoots {
			return errors.New("too many root versions")
		}
		_, err := get(strconv.FormatInt(v, 10)+".root.json", pullRootMax)
		var he *metadata.ErrDownloadHTTP
		if errors.As(err, &he) && he.StatusCode == http.StatusNotFound {
			break
		}
		if err != nil {
			return err
		}
	}
	raw, err := get("timestamp.json", pullTimestampMax)
	if err != nil {
		return err
	}
	ts, err := metadata.Timestamp().FromBytes(raw)
	if err != nil {
		return err
	}
	sm := ts.Signed.Meta["snapshot.json"]
	if sm == nil {
		return errors.New("timestamp has no snapshot entry")
	}
	if raw, err = get(fmt.Sprintf("%d.snapshot.json", sm.Version), pullSnapshotMax); err != nil {
		return err
	}
	snap, err := metadata.Snapshot().FromBytes(raw)
	if err != nil {
		return err
	}
	tm := snap.Signed.Meta["targets.json"]
	if tm == nil {
		return errors.New("snapshot has no targets entry")
	}
	if _, err := get(fmt.Sprintf("%d.targets.json", tm.Version), pullTargetsMax); err != nil {
		return err
	}
	v, err := verifyState(staging, trustedRoot, now)
	if err != nil {
		return fmt.Errorf("published metadata does not verify from the trusted root: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "metadata"), 0o750); err != nil {
		return err
	}
	for name, b := range v.files {
		if err := writeFile(filepath.Join(dir, "metadata", name), b); err != nil {
			return err
		}
	}
	return nil
}
