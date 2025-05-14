//go:build !linux

package nodestats

import (
	"fmt"

	"github.com/prometheus/procfs"
	"github.com/prometheus/procfs/blockdevice"
)

func parseUname() (unixName, error) {
	return unixName{}, fmt.Errorf("not implemented yet")
}

func parseMemInfo() (procfs.Meminfo, error) {
	return procfs.Meminfo{}, fmt.Errorf("not implemented yet")
}

func parseStat() (procfs.Stat, error) {
	return procfs.Stat{}, fmt.Errorf("not implemented yet")
}

func parseNetDev() (procfs.NetDev, error) {
	return procfs.NetDev{}, fmt.Errorf("not implemented yet")
}

func parseDiskStats() ([]blockdevice.Diskstats, error) {
	return nil, fmt.Errorf("not implemented yet")
}
