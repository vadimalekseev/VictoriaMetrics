//go:build linux

package nodestats

import (
	"flag"
	"fmt"
	"sync"

	"github.com/VictoriaMetrics/VictoriaMetrics/lib/logger"
	"github.com/prometheus/procfs"
	"github.com/prometheus/procfs/blockdevice"
	"golang.org/x/sys/unix"
)

var (
	procfsPath = flag.String("promscrape.procfsPath", "/proc", "The path to the procfs filesystem")
	sysfsPath  = flag.String("promscrape.sysfsPath", "/sys", "The path to the sysfs filesystem")
)

var (
	procFS        procfs.FS
	blockDeviceFS blockdevice.FS
	initOnce      sync.Once
)

func mustInitProcFS() {
	initOnce.Do(func() {
		var err error
		procFS, err = procfs.NewFS(*procfsPath)
		if err != nil {
			logger.Fatalf("cannot open %q filesystem: %s", *procfsPath, err)
		}
		blockDeviceFS, err = blockdevice.NewFS(*procfsPath, *sysfsPath)
		if err != nil {
			logger.Fatalf("cannot open %q/%q filesystem: %s", *procfsPath, sysfsPath, err)
		}
	})
}

func parseUname() (unixName, error) {
	var n unix.Utsname
	if err := unix.Uname(&n); err != nil {
		return unixName{}, err
	}
	return unixName{
		SysName:    unix.ByteSliceToString(n.Sysname[:]),
		Release:    unix.ByteSliceToString(n.Release[:]),
		Version:    unix.ByteSliceToString(n.Version[:]),
		Machine:    unix.ByteSliceToString(n.Machine[:]),
		NodeName:   unix.ByteSliceToString(n.Nodename[:]),
		DomainName: unix.ByteSliceToString(n.Domainname[:]),
	}, nil
}

func parseMemoryStats() (procfs.Meminfo, error) {
	return procFS.Meminfo()
}

func parseCPUStats() (procfs.Stat, error) {
	return procFS.Stat()
}

func parseNetDev() (procfs.NetDev, error) {
	netDev, err := procFS.NetDev()
	if err != nil {
		return nil, fmt.Errorf("cannot determine network interface: %s", err)
	}
	return netDev, nil
}

func parseDiskStats() ([]blockdevice.Diskstats, error) {
	diskStats, err := blockDeviceFS.ProcDiskstats()
	if err != nil {
		return nil, fmt.Errorf("cannot parse disk stats: %s", err)
	}
	return diskStats, nil
}
