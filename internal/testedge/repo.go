package testedge

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/seawise/client/internal/tufrepo"
)

// UpdateRepo writes a signed update repository to repo whose targets are
// a stable manifest and the key set, and the files the agent's test build
// reads from SEAWISE_TEST_TUF_DIR to tdir: root.json, url (repoURL),
// ca.pem and keyset-root.
func UpdateRepo(repo, tdir, repoURL string, keys Keys, ca *CA, now time.Time) error {
	tk, err := tufrepo.InitTest(repo, now)
	if err != nil {
		return err
	}
	ks, err := keys.KeySet(1, now.Unix())
	if err != nil {
		return err
	}
	manifest := `{"channel":"stable","image":"ghcr.io/seawise-io/seawise-client","version":"9.0.0","digest":"sha256:` + strings.Repeat("a", 64) +
		`","expires":"` + now.Add(30*24*time.Hour).UTC().Format(time.RFC3339) + `"}`
	if _, err := tufrepo.SignTargets(repo, tk.Targets, map[string][]byte{"release/stable.json": []byte(manifest), "keyset.json": []byte(ks)},
		nil, now, tufrepo.DefaultTargetsExpiry); err != nil {
		return err
	}
	root, err := os.ReadFile(filepath.Join(repo, "metadata", "1.root.json"))
	if err != nil {
		return err
	}
	if _, err := tufrepo.Refresh(repo, root, tk.Snapshot, tk.Timestamp, now, tufrepo.DefaultOnlineExpiry, tufrepo.DefaultMinRemaining); err != nil {
		return err
	}
	for name, b := range map[string][]byte{
		"root.json": root, "url": []byte(repoURL), "ca.pem": ca.PEM(),
		"keyset-root": []byte(base64.RawURLEncoding.EncodeToString(keys.RootPublic())),
	} {
		if err := os.WriteFile(filepath.Join(tdir, name), b, 0o600); err != nil {
			return err
		}
	}
	return nil
}
