package xorfilter

import (
	"testing"
)

func TestBasic32(t *testing.T) {
	var bld Builder
	testPopulateN := func(keys []uint64, bits int) (Filter, error) {
		return bld.Populate32(keys)
	}
	_testBasicN(t, 32, testPopulateN)
}

func BenchmarkPopulate32b10000Builder(b *testing.B) {
	var bu Builder
	innerBenchmarkPopulate10000(b, func(keys []uint64) (Filter, error) {
		return bu.Populate32(keys)
	})
}

func BenchmarkContains32b10000(b *testing.B) {
	innerBenchmarkContains10000(b, func(keys []uint64) (Filter, error) {
		return Populate32(keys)
	})
}
