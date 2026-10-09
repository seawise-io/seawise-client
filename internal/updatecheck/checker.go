// Package updatecheck verifies release information and the signing key set
// with TUF and reports when a newer release is available. It never installs
// anything.
//
// Expired metadata only hides update notices and closes the Fresh gate used
// for destructive instructions; the last verified key set stays usable so
// tunnels keep working.
package updatecheck

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/seawise/client/internal/controlplane"
	"github.com/seawise/client/internal/store"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/config"
	"github.com/theupdateframework/go-tuf/v2/metadata/updater"
)

const (
	StateNotConfigured = "not_configured"
	StateDisabled      = "disabled"
	StatePending       = "pending"
	StateOK            = "ok"
	StateExpired       = "expired"
	StateError         = "error"

	keySetTarget = "keyset.json"

	// testOnlyField marks a test root; see tools/tuf.
	testOnlyField = "x-seawise-test-only"

	maxRootRotations = 32
)

var (
	// ErrNotConfigured means this build has no signing root or repository
	// URL, so no update checks are made.
	ErrNotConfigured = errors.New("update checks not configured in this build")
	// ErrTestRoot means the pinned root is a test root.
	ErrTestRoot = errors.New("pinned update root is a test root")
)

// Config configures a Checker.
type Config struct {
	Root          []byte // pinned root metadata
	AllowTestRoot bool
	URL           string // https base; metadata/ and targets/ below it
	Dir           string // private state folder
	Channel       string // "stable" or "beta"
	Version       string // running version
	Transport     http.RoundTripper

	RequestTimeout time.Duration // per file, including the body
	CheckTimeout   time.Duration // whole check
	FirstDelay     time.Duration
	Interval       time.Duration
	RetryInterval  time.Duration

	Now    func() time.Time
	Logger *slog.Logger
}

// Status is the update state shown in the admin UI.
type Status struct {
	State        string     `json:"state"`
	Channel      string     `json:"channel,omitempty"`
	Current      string     `json:"current,omitempty"`
	CheckedAt    *time.Time `json:"checked_at,omitempty"`
	VerifiedAt   *time.Time `json:"verified_at,omitempty"`
	FreshUntil   *time.Time `json:"fresh_until,omitempty"`
	Fresh        bool       `json:"fresh"`
	Available    *Release   `json:"available"`
	KeySetSHA256 string     `json:"keyset_sha256,omitempty"`
	Error        string     `json:"error,omitempty"`
}

// saved is the verified result kept across restarts.
type saved struct {
	VerifiedAt     time.Time `json:"verified_at"`
	FreshUntil     time.Time `json:"fresh_until"`
	TargetsVersion int64     `json:"targets_version"`
	Release        *Release  `json:"release,omitempty"`
	KeySetSHA256   string    `json:"keyset_sha256,omitempty"`
}

// Checker runs TUF update checks.
type Checker struct {
	cfg        Config
	metaURL    string
	targetsURL string
	client     *http.Client
	log        *slog.Logger

	checkMu sync.Mutex // one check at a time

	mu        sync.Mutex
	state     string
	errMsg    string
	checkedAt time.Time
	saved     saved
	keySet    []byte
	announced string
}

// New validates the configuration and loads the last verified state.
func New(cfg Config) (*Checker, error) {
	if len(bytes.TrimSpace(cfg.Root)) == 0 || cfg.URL == "" {
		return nil, ErrNotConfigured
	}
	u, err := url.Parse(cfg.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("update repository URL must be a plain https URL")
	}
	if cfg.Channel != "stable" && cfg.Channel != "beta" {
		return nil, fmt.Errorf("unknown update channel %q", cfg.Channel)
	}
	if cfg.Dir == "" {
		return nil, errors.New("update state folder not set")
	}
	if err := checkPinnedRoot(cfg.Root, cfg.AllowTestRoot); err != nil {
		return nil, err
	}
	if cfg.Transport == nil {
		cfg.Transport = controlplane.NewTransport(os.Getenv, nil)
	}
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = 30 * time.Second
	}
	if cfg.CheckTimeout <= 0 {
		cfg.CheckTimeout = 2 * time.Minute
	}
	if cfg.FirstDelay <= 0 {
		cfg.FirstDelay = time.Minute
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 24 * time.Hour
	}
	if cfg.RetryInterval <= 0 {
		cfg.RetryInterval = time.Hour
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		return nil, err
	}
	if err := store.CheckDir(cfg.Dir); err != nil {
		return nil, err
	}
	base, _ := url.JoinPath(cfg.URL, "/")
	c := &Checker{
		cfg:        cfg,
		metaURL:    base + "metadata/",
		targetsURL: base + "targets/",
		client:     newHTTPClient(cfg.Transport, cfg.RequestTimeout),
		log:        cfg.Logger,
		state:      StatePending,
	}
	c.load()
	return c, nil
}

func checkPinnedRoot(raw []byte, allowTest bool) error {
	r, err := metadata.Root().FromBytes(raw)
	if err != nil {
		return fmt.Errorf("pinned update root: %w", err)
	}
	if err := r.VerifyDelegate(metadata.ROOT, r); err != nil {
		return fmt.Errorf("pinned update root is not self-signed: %w", err)
	}
	if role := r.Signed.Roles[metadata.ROOT]; role == nil || len(role.KeyIDs) < 2 {
		return errors.New("pinned update root needs a primary and a backup root key")
	}
	if isTestRoot(r) && !allowTest {
		return ErrTestRoot
	}
	return nil
}

func isTestRoot(r *metadata.Metadata[metadata.RootType]) bool {
	v, ok := r.Signed.UnrecognizedFields[testOnlyField]
	return ok && v != false
}

// trustedRoot returns the root to start from: the root go-tuf saved after
// the last verified rotation when it is newer than the pinned root and
// still self-signed, otherwise the pinned root.
func (c *Checker) trustedRoot() ([]byte, error) {
	pinned, err := metadata.Root().FromBytes(c.cfg.Root)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(filepath.Join(c.cfg.Dir, "metadata", "root.json"))
	if err != nil {
		return c.cfg.Root, nil
	}
	local, err := metadata.Root().FromBytes(raw)
	if err != nil || local.Signed.Version <= pinned.Signed.Version ||
		local.VerifyDelegate(metadata.ROOT, local) != nil ||
		(isTestRoot(local) && !c.cfg.AllowTestRoot) {
		return c.cfg.Root, nil
	}
	return raw, nil
}

// Check refreshes and verifies the metadata, then the release manifest for
// the configured channel and the key set.
func (c *Checker) Check(ctx context.Context) error {
	c.checkMu.Lock()
	defer c.checkMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, c.cfg.CheckTimeout)
	defer cancel()
	now := c.cfg.Now()
	res, err := c.check(ctx, now)

	c.mu.Lock()
	defer c.mu.Unlock()
	c.checkedAt = now
	if res != nil {
		c.saved = res.saved
		if res.keySet != nil {
			c.keySet = res.keySet
		}
		if werr := c.persist(); werr != nil {
			err = errors.Join(err, werr)
		}
	}
	switch {
	case err == nil:
		c.state, c.errMsg = StateOK, ""
	case isExpired(err):
		c.state, c.errMsg = StateExpired, describe(err)
	default:
		c.state, c.errMsg = StateError, describe(err)
	}
	if err != nil {
		c.log.Warn("update check", "state", c.state, "error", err)
	} else if r := c.available(now); r != nil && r.Version != c.announced {
		c.announced = r.Version
		c.log.Info("a newer release is available", "version", r.Version, "channel", r.Channel, "image", r.Image+":"+r.Version)
	}
	return err
}

type result struct {
	saved  saved
	keySet []byte
}

func (c *Checker) check(ctx context.Context, now time.Time) (*result, error) {
	root, err := c.trustedRoot()
	if err != nil {
		return nil, err
	}
	ucfg, err := config.New(c.metaURL, root)
	if err != nil {
		return nil, err
	}
	ucfg.RemoteTargetsURL = c.targetsURL
	ucfg.LocalMetadataDir = filepath.Join(c.cfg.Dir, "metadata")
	ucfg.LocalTargetsDir = filepath.Join(c.cfg.Dir, "targets")
	ucfg.MaxRootRotations = maxRootRotations
	ucfg.RootMaxLength = maxRootSize
	ucfg.TimestampMaxLength = maxTimestampSize
	ucfg.SnapshotMaxLength = maxSnapshotSize
	ucfg.TargetsMaxLength = maxTargetsSize
	ucfg.Fetcher = &fetcher{ctx: ctx, client: c.client, ua: "seawise-agent/" + c.cfg.Version}
	up, err := updater.New(ucfg)
	if err != nil {
		return nil, err
	}
	up.UnsafeSetRefTime(now)
	if err := up.Refresh(); err != nil {
		return nil, err
	}
	tm := up.GetTrustedMetadataSet()
	targets := tm.Targets[metadata.TARGETS]
	fresh := tm.Root.Signed.Expires
	for _, e := range []time.Time{tm.Timestamp.Signed.Expires, tm.Snapshot.Signed.Expires, targets.Signed.Expires} {
		if e.Before(fresh) {
			fresh = e
		}
	}
	res := &result{saved: saved{VerifiedAt: now, FreshUntil: fresh, TargetsVersion: targets.Signed.Version}}

	var errs []error
	if tf := targets.Signed.Targets[keySetTarget]; tf != nil {
		data, err := c.target(up, tf, maxKeySetSize)
		if err != nil {
			errs = append(errs, err)
			// Keep the last verified key set rather than none.
			c.mu.Lock()
			res.saved.KeySetSHA256 = c.saved.KeySetSHA256
			c.mu.Unlock()
		} else {
			sum := sha256.Sum256(data)
			res.saved.KeySetSHA256 = hex.EncodeToString(sum[:])
			res.keySet = data
		}
	}
	if tf := targets.Signed.Targets["release/"+c.cfg.Channel+".json"]; tf != nil {
		data, err := c.target(up, tf, maxReleaseSize)
		if err == nil {
			res.saved.Release, err = parseManifest(data, c.cfg.Channel)
		}
		if err != nil {
			errs = append(errs, err)
		}
	}
	return res, errors.Join(errs...)
}

func (c *Checker) target(up *updater.Updater, tf *metadata.TargetFiles, max int64) ([]byte, error) {
	if tf.Length > max {
		return nil, fmt.Errorf("target %s too large (%d bytes, limit %d)", tf.Path, tf.Length, max)
	}
	if path, data, err := up.FindCachedTarget(tf, ""); err == nil && path != "" {
		return data, nil
	}
	_, data, err := up.DownloadTarget(tf, "", "")
	if err != nil {
		return nil, fmt.Errorf("target %s: %w", tf.Path, err)
	}
	return data, nil
}

// persist writes the key set first, then the record naming its hash, so a
// crash leaves either the old pair or a key set the record rejects.
func (c *Checker) persist() error {
	if c.keySet != nil {
		if err := store.WriteFileAtomic(filepath.Join(c.cfg.Dir, "keyset.json"), c.keySet, 0o600); err != nil {
			return err
		}
	}
	b, err := json.Marshal(c.saved)
	if err != nil {
		return err
	}
	return store.WriteFileAtomic(filepath.Join(c.cfg.Dir, "state.json"), b, 0o600)
}

func (c *Checker) load() {
	b, err := os.ReadFile(filepath.Join(c.cfg.Dir, "state.json"))
	if err != nil {
		return
	}
	var s saved
	if err := json.Unmarshal(b, &s); err != nil {
		c.log.Warn("update state unreadable, starting over", "error", err)
		return
	}
	if s.Release != nil {
		if _, err := parseManifest(mustJSON(s.Release), c.cfg.Channel); err != nil {
			s.Release = nil
		}
	}
	c.saved = s
	if s.KeySetSHA256 == "" {
		return
	}
	ks, err := os.ReadFile(filepath.Join(c.cfg.Dir, "keyset.json"))
	if err != nil {
		return
	}
	sum := sha256.Sum256(ks)
	if hex.EncodeToString(sum[:]) != s.KeySetSHA256 {
		c.log.Warn("saved key set does not match its recorded hash; ignoring it")
		return
	}
	c.keySet = ks
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// Fresh reports whether every role of the last verified metadata is still
// unexpired at now. Destructive instructions must not be accepted unless
// it is true; tunnels and the last verified key set never depend on it.
func (c *Checker) Fresh(now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.fresh(now)
}

func (c *Checker) fresh(now time.Time) bool {
	return !c.saved.FreshUntil.IsZero() && now.Before(c.saved.FreshUntil)
}

// KeySet returns the last verified key set, or nil. It stays available
// after the metadata expires.
func (c *Checker) KeySet() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Clone(c.keySet)
}

func (c *Checker) available(now time.Time) *Release {
	r := c.saved.Release
	if r == nil || !c.fresh(now) || !now.Before(r.Expires) || !newer(c.cfg.Version, r.Version) {
		return nil
	}
	cp := *r
	return &cp
}

// Status returns the current update state.
func (c *Checker) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.cfg.Now()
	st := Status{
		State: c.state, Channel: c.cfg.Channel, Current: c.cfg.Version, Error: c.errMsg,
		Fresh: c.fresh(now), Available: c.available(now), KeySetSHA256: c.saved.KeySetSHA256,
	}
	if st.State == StateOK && !st.Fresh {
		st.State = StateExpired
	}
	if !c.checkedAt.IsZero() {
		t := c.checkedAt
		st.CheckedAt = &t
	}
	if !c.saved.VerifiedAt.IsZero() {
		v, f := c.saved.VerifiedAt, c.saved.FreshUntil
		st.VerifiedAt, st.FreshUntil = &v, &f
	}
	return st
}

// Run checks after FirstDelay (plus up to 4 minutes), then every Interval
// (plus up to an hour), retrying after RetryInterval on failure.
func (c *Checker) Run(ctx context.Context) {
	wait := c.cfg.FirstDelay + jitter(4*time.Minute, c.cfg.FirstDelay)
	for {
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		if err := c.Check(ctx); err != nil {
			wait = c.cfg.RetryInterval
		} else {
			wait = c.cfg.Interval + jitter(time.Hour, c.cfg.Interval)
		}
	}
}

// jitter returns a random duration below max, scaled down for short base
// intervals so tests stay fast.
func jitter(max, base time.Duration) time.Duration {
	if base < max {
		max = base
	}
	if max <= 0 {
		return 0
	}
	return rand.N(max)
}

func isExpired(err error) bool {
	var e *metadata.ErrExpiredMetadata
	return errors.As(err, &e)
}

// describe gives a short reason without URLs for the admin UI.
func describe(err error) string {
	var (
		exp  *metadata.ErrExpiredMetadata
		ver  *metadata.ErrBadVersionNumber
		sig  *metadata.ErrUnsignedMetadata
		size *metadata.ErrDownloadLengthMismatch
		hash *metadata.ErrLengthOrHashMismatch
		dl   *metadata.ErrDownloadHTTP
	)
	switch {
	case errors.As(err, &exp):
		return "signed update information has expired"
	case errors.As(err, &ver):
		return "update information is older than what this client has seen"
	case errors.As(err, &sig):
		return "update information is not correctly signed"
	case errors.As(err, &size):
		return "update information is larger than allowed"
	case errors.As(err, &hash):
		return "update information does not match its signed hash"
	case errors.As(err, &dl):
		return fmt.Sprintf("update server answered HTTP %d", dl.StatusCode)
	case errors.Is(err, context.DeadlineExceeded) || isTimeout(err):
		return "update server did not answer in time"
	}
	return "update check failed"
}

func isTimeout(err error) bool {
	var t interface{ Timeout() bool }
	return errors.As(err, &t) && t.Timeout()
}
