package xorfilter

import (
	"testing"
)

func TestBasic16(t *testing.T) {
	var bld Builder
	testPopulateN := func(keys []uint64, bits int) (Filter, error) {
		return bld.Populate16(keys)
	}
	_testBasicN(t, 16, testPopulateN)
}

func BenchmarkPopulate16b10000Builder(b *testing.B) {
	var bu Builder
	innerBenchmarkPopulate10000(b, func(keys []uint64) (Filter, error) {
		return bu.Populate16(keys)
	})
}

func BenchmarkContains16b10000(b *testing.B) {
	innerBenchmarkContains10000(b, func(keys []uint64) (Filter, error) {
		return Populate16(keys)
	})
}
