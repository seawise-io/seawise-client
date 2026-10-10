//go:build !unix

package legacy

import "os"

const readOnlyFlags = os.O_RDONLY
