package containerstats

import (
	"math"
	"reflect"
	"testing"
)

func TestParseCgroupV2(t *testing.T) {
	path := "testdata/1"
	got, err := parseCgroupV2Metrics(path)
	if err != nil {
		t.Errorf("cannot parse cgroup metrics: %s", err)
	}
	expected := cgroupMetrics{
		Memory: memoryMetrics{
			Limit:       math.MaxInt,
			Reservation: 0,
			SwapLimit:   math.MaxInt,
		},
		CPU: cpuMetrics{
			Limit:                      185,
			Quota:                      0,
			Period:                     100000,
			TotalUsage:                 344105365000,
			UsageInUsermode:            212820991000,
			UsageInKernelmode:          131284373000,
			ThrottlingPeriods:          1,
			ThrottlingThrottledPeriods: 2,
			ThrottlingThrottledTime:    3000,
		},
	}
	if !reflect.DeepEqual(got, expected) {
		t.Errorf("unexpected result from parseCgroupV2Metrics:\ngot\n %v\nwant\n %v", got, expected)
	}
}
