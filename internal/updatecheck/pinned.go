package updatecheck

import (
	"bytes"
	_ "embed"
)

// productionRoot is the root metadata of the release repository, created
// in an offline key ceremony. Empty means this build makes no update
// checks.
//
//go:embed root/production.json
var productionRoot []byte

// productionURL is the static host serving the release repository. Empty
// until the hosting is chosen.
const productionURL = ""

// Pinned returns the production root and repository URL built into this
// binary. Either may be empty, and then New returns ErrNotConfigured.
func Pinned() ([]byte, string) {
	return bytes.TrimSpace(productionRoot), productionURL
}
