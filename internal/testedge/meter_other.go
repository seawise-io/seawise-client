//go:build !linux

package testedge

import "net"

func readTCPInfo(net.Conn) (Sample, bool) { return Sample{}, false }
