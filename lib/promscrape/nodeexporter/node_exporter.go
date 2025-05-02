package nodeexporter

import (
	"regexp"
	"strconv"
	"time"

	"github.com/VictoriaMetrics/VictoriaMetrics/lib/logger"
	"github.com/VictoriaMetrics/VictoriaMetrics/lib/prompbmarshal"
)

type NodeExporter struct {
	labelInstance string
}

func New(labelInstance string) (*NodeExporter, error) {
	mustInitProcFS()
	return &NodeExporter{
		labelInstance: labelInstance,
	}, nil
}

func (n *NodeExporter) AppendMetrics(ts []prompbmarshal.TimeSeries) []prompbmarshal.TimeSeries {
	timestamp := time.Now().UnixMilli()

	ts = n.appendUname(ts, timestamp)
	ts = n.appendMemoryMetrics(ts, timestamp)
	ts = n.appendCPUMetrics(ts, timestamp)
	ts = n.appendNetworkMetrics(ts, timestamp)
	ts = n.appendDiskMetrics(ts, timestamp)

	return ts
}

const jobName = "vmagent_node_exporter"

func (n *NodeExporter) appendMetric(ts []prompbmarshal.TimeSeries, name string, value float64, timestamp int64, additionalLabels ...prompbmarshal.Label) []prompbmarshal.TimeSeries {
	labels := []prompbmarshal.Label{
		{Name: "__name__", Value: name},
		{Name: "instance", Value: n.labelInstance},
		{Name: "job", Value: jobName},
	}
	labels = append(labels, additionalLabels...)
	ts = append(ts, prompbmarshal.TimeSeries{
		Labels:  labels,
		Samples: []prompbmarshal.Sample{{Value: value, Timestamp: timestamp}},
	})
	return ts
}

type unixName struct {
	SysName    string
	NodeName   string
	Release    string
	Version    string
	Machine    string
	DomainName string
}

func (n *NodeExporter) appendUname(ts []prompbmarshal.TimeSeries, timestamp int64) []prompbmarshal.TimeSeries {
	uname, err := parseUname()
	if err != nil {
		logger.Errorf("cannot get uname: %s", err)
		return ts
	}
	ts = n.appendMetric(ts, "node_uname_info", 1, timestamp,
		prompbmarshal.Label{Name: "sysname", Value: uname.SysName},
		prompbmarshal.Label{Name: "release", Value: uname.Release},
		prompbmarshal.Label{Name: "version", Value: uname.Version},
		prompbmarshal.Label{Name: "machine", Value: uname.Machine},
		prompbmarshal.Label{Name: "nodename", Value: uname.NodeName},
		prompbmarshal.Label{Name: "domainname", Value: uname.DomainName},
	)
	return ts
}

func (n *NodeExporter) appendMemoryMetrics(ts []prompbmarshal.TimeSeries, timestamp int64) []prompbmarshal.TimeSeries {
	stats, err := parseMemoryStats()
	if err != nil {
		logger.Errorf("cannot get memory info from: %s", err)
		return ts
	}

	push := func(name string, v *uint64) {
		if v == nil {
			return
		}
		ts = n.appendMetric(ts, name, float64(*v), timestamp)
	}
	push("node_memory_MemAvailable_bytes", stats.MemAvailableBytes)
	push("node_memory_MemTotal_bytes", stats.MemTotalBytes)
	push("node_memory_SwapFree_bytes", stats.SwapFreeBytes)
	push("node_memory_SwapTotal_bytes", stats.SwapTotalBytes)

	return ts
}

func (n *NodeExporter) appendCPUMetrics(ts []prompbmarshal.TimeSeries, timestamp int64) []prompbmarshal.TimeSeries {
	stats, err := parseCPUStats()
	if err != nil {
		logger.Errorf("cannot get cpu stats: %s", err)
		return ts
	}

	push := func(numCPU int64, mode string, value float64) {
		ts = n.appendMetric(ts, "node_cpu_seconds_total", value, timestamp,
			prompbmarshal.Label{Name: "mode", Value: mode},
			prompbmarshal.Label{Name: "cpu", Value: strconv.Itoa(int(numCPU))})
	}
	for cpuNum, cpuStat := range stats.CPU {
		push(cpuNum, "user", cpuStat.User)
		push(cpuNum, "nice", cpuStat.Nice)
		push(cpuNum, "system", cpuStat.System)
		push(cpuNum, "idle", cpuStat.Idle)
		push(cpuNum, "iowait", cpuStat.Iowait)
		push(cpuNum, "irq", cpuStat.IRQ)
		push(cpuNum, "softirq", cpuStat.SoftIRQ)
		push(cpuNum, "steal", cpuStat.Steal)
	}

	return ts
}

func (n *NodeExporter) appendNetworkMetrics(ts []prompbmarshal.TimeSeries, timestamp int64) []prompbmarshal.TimeSeries {
	stats, err := parseNetDev()
	if err != nil {
		logger.Errorf("cannot get net info: %s", err)
		return ts
	}

	for device, stat := range stats {
		deviceLabel := prompbmarshal.Label{Name: "device", Value: device}
		ts = n.appendMetric(ts, "node_network_receive_bytes_total", float64(stat.RxBytes), timestamp, deviceLabel)
		ts = n.appendMetric(ts, "node_network_receive_errs_total", float64(stat.RxErrors), timestamp, deviceLabel)
		ts = n.appendMetric(ts, "node_network_transmit_bytes_total", float64(stat.TxBytes), timestamp, deviceLabel)
		ts = n.appendMetric(ts, "node_network_transmit_errs_total", float64(stat.TxErrors), timestamp, deviceLabel)
	}
	return ts
}

// This regexp was copied from node-exporter for compatibility.
// TODO: Replace with a more readable and maintainable version.
var diskDeviceFilter = regexp.MustCompile("^(z?ram|loop|fd|(h|s|v|xv)d[a-z]|nvme\\d+n\\d+p)\\d+$")

func (n *NodeExporter) appendDiskMetrics(ts []prompbmarshal.TimeSeries, timestamp int64) []prompbmarshal.TimeSeries {
	diskStats, err := parseDiskStats()
	if err != nil {
		logger.Errorf("cannot get disk stats: %s", err)
		return ts
	}

	// Standard UNIX sector size, see this doc for more details: https://www.kernel.org/doc/Documentation/block/stat.txt
	const sectorSizeBytes = 512
	for _, stat := range diskStats {
		if diskDeviceFilter.MatchString(stat.DeviceName) {
			continue
		}
		deviceLabel := prompbmarshal.Label{Name: "device", Value: stat.DeviceName}
		ts = n.appendMetric(ts, "node_disk_read_bytes_total", float64(stat.ReadSectors*sectorSizeBytes), timestamp, deviceLabel)
		ts = n.appendMetric(ts, "node_disk_written_bytes_total", float64(stat.WriteSectors*sectorSizeBytes), timestamp, deviceLabel)
	}
	return ts
}
