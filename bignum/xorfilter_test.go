package xorfilter

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestBasicN(t *testing.T) {
	var bld Builder
	testPopulateN := func(keys [][]byte, bits int) (Filter, error) {
		return bld.PopulateN(keys, bits)
	}
	for n := 9; n <= 32; n++ {
		t.Run(fmt.Sprintf("%d", n), func(t *testing.T) {
			_testBasicN(t, n, testPopulateN)
		})
	}
}

const (
	minFalseHits  = 100
	minFalseTries = 100000
	maxFalseTries = 1000000000000

	// edit maxFalseTime to run a more extensive test, e.g. 20 * time.Second
	maxFalseTime = 100 * time.Millisecond
)

func randUint256Bytes() []byte {
	out := make([]byte, 32)
	rand.Read(out)
	return out
}

func _testBasicN(t *testing.T, bits int, testPopulateN func(keys [][]byte, bits int) (Filter, error)) {
	testsize := 10000
	keys := make([][]byte, testsize)
	for i := range keys {
		keys[i] = randUint256Bytes()
	}
	filter, _ := testPopulateN(keys, bits)
	for _, v := range keys {
		assert.Equal(t, true, filter.Contains(v))
	}
	var lenFingerprints int = 0
	switch xf := filter.(type) {
	/*
		case *Xor8:
			lenFingerprints = len(xf.Fingerprints)
		case *Xor16:
			lenFingerprints = len(xf.Fingerprints)
		case *Xor32:
			lenFingerprints = len(xf.Fingerprints)
	*/
	case *XorN:
		lenFingerprints = len(xf.Fingerprints)
	default:
		t.Errorf("unknown type of filter: %T", filter)
	}
	bpv := float64(lenFingerprints) * float64(bits) / float64(testsize)
	tries := 0
	matches := 0
	start := time.Now()
	for {
		v := randUint256Bytes()
		if filter.Contains(v) {
			matches++
		}
		tries++
		if (tries > minFalseTries) && (matches > minFalseHits) {
			break
		}
		if tries > maxFalseTries {
			break
		}
		// at 8ns per Contains() we can run a lot of these and not call time.Now() too often (calling time takes time!)
		if (tries % 100000) == 0 {
			now := time.Now()
			dt := now.Sub(start)
			if dt > maxFalseTime {
				break
			}
		}
	}
	fpp := float64(matches) * 100.0 / float64(tries)
	fmt.Printf("Xor[%d] filter: %0.2f bits per entry, false positive rate %0.7f%% (%d/%d)\n", bits, bpv, fpp, matches, tries)
	// capture stdout to a file then `grep ^bits` to get csv for a report
	fmt.Printf("bits, %d, %2.3f, %0.9g, %d, %d\n", bits, bpv, fpp/100.0, matches, tries)
	keys = keys[:1000]
	for trial := 0; trial < 10; trial++ {
		for i := range keys {
			keys[i] = randUint256Bytes()
		}
		filter, _ = testPopulateN(keys, bits)
		for _, v := range keys {
			assert.Equal(t, true, filter.Contains(v))
		}
	}
}

func innerBenchmarkPopulate10000(b *testing.B, populatef func([][]byte) (Filter, error)) {
	testsize := 10000
	keys := make([][]byte, testsize)

	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		b.StopTimer()
		for i := range keys {
			keys[i] = randUint256Bytes()
		}
		b.StartTimer()
		populatef(keys)
	}
}

func BenchmarkPopulateN10000Builder(b *testing.B) {
	for n := 9; n <= 32; n++ {
		b.Run(fmt.Sprintf("%d", n), func(b *testing.B) {
			var bu Builder
			innerBenchmarkPopulate10000(b, func(keys [][]byte) (Filter, error) {
				return bu.PopulateN(keys, n)
			})
		})
	}
}

func innerBenchmarkContains10000(b *testing.B, populatef func([][]byte) (Filter, error)) {
	testsize := 10000
	keys := make([][]byte, testsize)
	for i := range keys {
		keys[i] = randUint256Bytes()
	}
	filter, _ := populatef(keys)

	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		filter.Contains(keys[n%len(keys)])
	}
}

func BenchmarkContainsN10000(b *testing.B) {
	for n := 9; n <= 32; n++ {
		b.Run(fmt.Sprintf("%d", n), func(b *testing.B) {
			innerBenchmarkContains10000(b, func(keys [][]byte) (Filter, error) {
				return PopulateN(keys, n)
			})
		})
	}
}

func TestNMask(t *testing.T) {
	var xn XorN
	xn.Bits = 8
	assert.Equal(t, uint32(0x0ff), xn.mask())
	xn.Bits = 9
	assert.Equal(t, uint32(0x1ff), xn.mask())
	xn.Bits = 12
	assert.Equal(t, uint32(0x0fff), xn.mask())
	xn.Bits = 16
	assert.Equal(t, uint32(0x0ffff), xn.mask())
	xn.Bits = 24
	assert.Equal(t, uint32(0x0ffffff), xn.mask())
	xn.Bits = 32
	assert.Equal(t, uint32(0xffffffff), xn.mask())
}
