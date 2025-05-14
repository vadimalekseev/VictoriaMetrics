package containerstats

import (
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/VictoriaMetrics/VictoriaMetrics/lib/logger"
	"github.com/VictoriaMetrics/VictoriaMetrics/lib/prompbmarshal"
)

func StartWatch() *ContainerStats {
	client := newContainerdClient()
	w := &ContainerStats{
		client:       client,
		containersMu: &sync.RWMutex{},
		containers:   make(map[string]container),
	}
	go func() {
		for {
			w.updateContainersInfo()
			time.Sleep(time.Second * 5)
		}
	}()
	return w
}

type ContainerStats struct {
	// client used to get pid by pid and container uid.
	client *containerdClient

	containersMu *sync.RWMutex
	containers   map[string]container
}

type container struct {
	PID        int
	CgroupPath string
	PodUID     string
}

func (w *ContainerStats) updateContainersInfo() {
	burstablePodPaths, err := filepath.Glob("/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod*.slice")
	if err != nil {
		logger.Fatalf("cannot find burstable pods: %s", err)
	}
	bestEffortPodPaths, err := filepath.Glob("/sys/fs/cgroup/kubepods.slice/kubepods-besteffort.slice/kubepods-burstable-pod*.slice")
	if err != nil {
		logger.Fatalf("cannot find besteffort pods: %s", err)
	}

	podPaths := append(burstablePodPaths, bestEffortPodPaths...)

	newContainers := make(map[string]container)
	for _, podPath := range podPaths {
		s := path.Base(podPath)
		strings.TrimSuffix(s, ".slice")
		n := strings.Index(s, "-pod")
		if n < 0 {
			logger.Errorf("cannot find '-pod' prefix in %s: %s", podPath, s)
			continue
		}
		podUID := s[n+len("-pod"):]

		files, err := os.ReadDir(podPath)
		if err != nil {
			logger.Errorf("cannot read dir %s: %s", podPath, err)
		}

		for _, f := range files {
			s := f.Name()
			if !strings.HasSuffix(s, ".scope") {
				continue
			}
			s = strings.TrimSuffix(s, ".scope")
			s = path.Base(s)
			if len(s) < 64 {
				// container must have an id of length 64, e.g.:
				// docker-744c9bb3a2fe09b1183448a5a56864a94f9df8bc9d73e946e607243b9741581c
				continue
			}
			containerUID := s[len(s)-64:]

			absPath := path.Join(podPath, f.Name())
			newContainers[containerUID] = container{
				CgroupPath: absPath,
				PodUID:     podUID,
			}
		}
	}
	w.containersMu.Lock()
	w.containers = newContainers
	w.containersMu.Unlock()
}

func (w *ContainerStats) Append(ts []prompbmarshal.TimeSeries) []prompbmarshal.TimeSeries {
	timestamp := time.Now().UnixMilli()
	w.containersMu.RLock()
	defer w.containersMu.RUnlock()
	for _, c := range w.containers {
		cgroup, err := parseCgroupV2Metrics(c.CgroupPath)
		if err != nil {
			logger.Errorf("cannot parse cgroup metrics: %s", err)
			continue
		}

		push := func(name string, value float64) {
			ts = appendMetric(ts, name, value, timestamp, c.PodUID, prompbmarshal.Label{Name: "id", Value: c.CgroupPath})
		}
		push("container_spec_cpu_shares", float64(cgroup.CPU.Limit))
		push("container_spec_cpu_quota", float64(cgroup.CPU.Quota))
		push("container_spec_cpu_period", float64(cgroup.CPU.Period))

		push("container_spec_memory_limit_bytes", float64(cgroup.Memory.Limit))
		push("container_spec_memory_reservation_limit_bytes", float64(cgroup.Memory.Reservation))
		push("container_spec_memory_reservation_limit_bytes", float64(cgroup.Memory.Reservation))

		push("container_cpu_usage_seconds_total", float64(cgroup.CPU.TotalUsage)/float64(time.Second))
		push("container_cpu_user_seconds_total", float64(cgroup.CPU.UsageInUsermode)/float64(time.Second))
		push("container_cpu_system_seconds_total", float64(cgroup.CPU.UsageInKernelmode)/float64(time.Second))

		push("container_cpu_cfs_periods_total", float64(cgroup.CPU.ThrottlingPeriods)/float64(time.Second))
		push("container_cpu_cfs_throttled_periods_total", float64(cgroup.CPU.ThrottlingThrottledPeriods))
		push("container_cpu_cfs_throttled_seconds_total", float64(cgroup.CPU.ThrottlingThrottledTime)/float64(time.Second))
	}
	return ts
}

const jobName = "vmscrape_cadvisor"

func appendMetric(ts []prompbmarshal.TimeSeries, name string, value float64, timestamp int64, instance string, additionalLabels ...prompbmarshal.Label) []prompbmarshal.TimeSeries {
	labels := []prompbmarshal.Label{
		{Name: "__name__", Value: name},
		{Name: "instance", Value: instance},
		{Name: "job", Value: jobName},
	}
	labels = append(labels, additionalLabels...)
	ts = append(ts, prompbmarshal.TimeSeries{
		Labels:  labels,
		Samples: []prompbmarshal.Sample{{Value: value, Timestamp: timestamp}},
	})
	return ts
}
