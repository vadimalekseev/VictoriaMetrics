package containerstats

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/VictoriaMetrics/VictoriaMetrics/lib/logger"
)

type cgroupMetrics struct {
	Memory memoryMetrics
	CPU    cpuMetrics
}

// memoryMetrics represents cgroup statistics from cpu.* files
// See: https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html#cpu-interface-files
type cpuMetrics struct {
	Limit  int
	Quota  int
	Period int

	// All usage fields below are in nanoseconds.
	TotalUsage        uint64
	UsageInUsermode   uint64
	UsageInKernelmode uint64

	// Number of periods with throttling active
	ThrottlingPeriods uint64
	// Number of periods when the container hit its throttling limit.
	ThrottlingThrottledPeriods uint64
	// Aggregate time the container was throttled for in nanoseconds.
	ThrottlingThrottledTime uint64
}

// memoryMetrics represents cgroup statistics from memory.* files
// See: https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html#memory-interface-files
type memoryMetrics struct {
	// Limit is memory usage hard limit.
	Limit int
	// Reservation is the amount of guaranteed memory.
	Reservation int
	SwapLimit   int
}

func parseCgroupV2Metrics(cgroupRoot string) (cgroupMetrics, error) {
	s := cgroupMetrics{}

	p := path.Join(cgroupRoot, "memory.min")
	s.Memory.Reservation = parseIntFromFile(p)

	p = path.Join(cgroupRoot, "memory.max")
	s.Memory.Limit = parseIntFromFile(p)

	p = path.Join(cgroupRoot, "memory.swap.max")
	s.Memory.SwapLimit = parseIntFromFile(p)

	p = path.Join(cgroupRoot, "cpu.weight")
	weight := parseIntFromFile(p)
	cpuShares := convertCPUWeightToCPULimit(weight)
	s.CPU.Limit = cpuShares

	p = path.Join(cgroupRoot, "cpu.max")
	quota, period := parseCPUMax(p)
	s.CPU.Quota = quota
	s.CPU.Period = period

	p = path.Join(cgroupRoot, "cpu.stat")
	if err := setCPUStats(p, &s.CPU); err != nil {
		return s, err
	}

	return s, nil
}

func parseCPUMax(p string) (int, int) {
	content := readFile(p)
	if content == "" {
		return 0, 0
	}
	parts := strings.Split(content, " ")
	if len(parts) != 2 {
		return 0, 0
	}
	var quota int
	if parts[0] != "max" {
		quota, _ = strconv.Atoi(parts[0])
	}
	period, _ := strconv.Atoi(parts[1])
	return quota, period
}

func setCPUStats(p string, cpu *cpuMetrics) error {
	content := readFile(p)
	if content == "" {
		return fmt.Errorf("cannot read cpu stats from %q", p)
	}
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		t, v, err := parseKeyValue(line)
		if err != nil {
			return fmt.Errorf("cannot parse key-value %q: %s", line, err)
		}
		switch t {
		case "usage_usec":
			cpu.TotalUsage = v * 1000
		case "user_usec":
			cpu.UsageInUsermode = v * 1000
		case "system_usec":
			cpu.UsageInKernelmode = v * 1000
		case "nr_periods":
			cpu.ThrottlingPeriods = v
		case "nr_throttled":
			cpu.ThrottlingThrottledPeriods = v
		case "throttled_usec":
			cpu.ThrottlingThrottledTime = v * 1000
		}
	}
	return nil
}

func parseKeyValue(t string) (string, uint64, error) {
	key, val, ok := strings.Cut(t, " ")
	if !ok || key == "" || val == "" {
		return "", 0, fmt.Errorf(`line %q is not in "key value" format`, t)
	}
	value, err := strconv.ParseUint(val, 10, 64)
	if err != nil {
		return "", 0, err
	}
	return key, value, nil
}

// convertCPUWeightToCPULimit converts cgroup v2 cpu.weight value to cgroup v1 cpu.shares
// https://github.com/kubernetes/enhancements/tree/master/keps/sig-node/2254-cgroup-v2#phase-1-convert-from-cgroups-v1-settings-to-v2
func convertCPUWeightToCPULimit(weight int) int {
	return 2 + ((weight-1)*262142)/9999
}

func parseIntFromFile(p string) int {
	content := readFile(p)
	if string(content) == ("max") {
		return math.MaxInt
	}
	v, err := strconv.ParseInt(content, 10, 64)
	if err != nil {
		logger.Errorf("cannot parse integer %q from %q: %s", content, p, err)
		return 0
	}
	return int(v)
}

func readFile(p string) string {
	content, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ""
		}
		logger.Errorf("cannot read %q: %s", p, err)
		return ""
	}
	content = bytes.TrimSpace(content)
	return string(content)
}
