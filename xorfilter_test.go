package xorfilter

import (
	"fmt"
	"math/rand"
	"runtime/debug"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var rng = uint64(time.Now().UnixNano())

func TestBasic8(t *testing.T) {
	var bld Builder
	testPopulateN := func(keys []uint64, bits int) (Filter, error) {
		return bld.Populate(keys)
	}
	_testBasicN(t, 8, testPopulateN)
}

func TestOne(t *testing.T) {
	testsize := 1
	keys := make([]uint64, testsize)
	for i := range keys {
		keys[i] = 12043587783372603620 //splitmix64(&rng)
	}
	filter, err := Populate(keys)
	assert.NoError(t, err)
	for _, v := range keys {
		assert.Equal(t, true, filter.Contains(v))
	}
}

func TestManyOne(t *testing.T) {
	var g int
	var keys []uint64
	defer func() {
		x := recover()
		if x != nil {
			t.Logf("panic @%d with key %d %x : %v %s", g, keys[0], keys[0], x, debug.Stack())
			panic(x)
		}
	}()
	testsize := 1
	for g = 0; g < 1000000; g++ {
		keys = make([]uint64, testsize)
		for i := range keys {
			keys[i] = splitmix64(&rng)
		}
		filter, err := Populate(keys)
		assert.NoError(t, err)
		for _, v := range keys {
			assert.Equal(t, true, filter.Contains(v))
		}
	}
}

func TestManyOneBuilder(t *testing.T) {
	var g int
	var keys []uint64
	defer func() {
		x := recover()
		if x != nil {
			t.Logf("panic @%d with key %d %x : %v %s", g, keys[0], keys[0], x, debug.Stack())
			panic(x)
		}
	}()
	testsize := 1
	var b Builder
	for g = 0; g < 1000000; g++ {
		keys = make([]uint64, testsize)
		for i := range keys {
			keys[i] = splitmix64(&rng)
		}
		filter, err := b.Populate(keys)
		assert.NoError(t, err)
		for _, v := range keys {
			assert.Equal(t, true, filter.Contains(v))
		}
	}
}

func TestZero(t *testing.T) {
	testsize := 0
	keys := make([]uint64, testsize)
	for i := range keys {
		keys[i] = splitmix64(&rng)
	}
	filter, err := Populate(keys)
	assert.NoError(t, err)
	for _, v := range keys {
		assert.Equal(t, true, filter.Contains(v))
	}
}

func BenchmarkPopulate10000(b *testing.B) {
	innerBenchmarkPopulate10000(b, func(keys []uint64) (Filter, error) {
		return Populate(keys)
	})
}

func XBenchmarkPopulate10000(b *testing.B) {
	testsize := 10000
	keys := make([]uint64, testsize)

	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		b.StopTimer()
		for i := range keys {
			keys[i] = splitmix64(&rng)
		}
		b.StartTimer()
		Populate(keys)
	}
}

func BenchmarkPopulate10000Builder(b *testing.B) {
	var bu Builder
	innerBenchmarkPopulate10000(b, func(keys []uint64) (Filter, error) {
		return bu.Populate(keys)
	})
}

func innerBenchmarkPopulate10000(b *testing.B, populatef func([]uint64) (Filter, error)) {
	testsize := 10000
	keys := make([]uint64, testsize)

	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		b.StopTimer()
		for i := range keys {
			keys[i] = splitmix64(&rng)
		}
		b.StartTimer()
		populatef(keys)
	}
}

// credit: el10savio
func Test_DuplicateKeys(t *testing.T) {
	keys := []uint64{1, 77, 31, 241, 303, 303}
	expectedErr := "too many iterations, you probably have duplicate keys"
	_, err := Populate(keys)
	if err.Error() != expectedErr {
		t.Fatalf("Unexpected error: %v, Expected: %v", err, expectedErr)
	}
}

func BenchmarkContains10000(b *testing.B) {
	innerBenchmarkContains10000(b, func(keys []uint64) (Filter, error) {
		return Populate(keys)
	})
}

func innerBenchmarkContains10000(b *testing.B, populatef func([]uint64) (Filter, error)) {
	testsize := 10000
	keys := make([]uint64, testsize)
	for i := range keys {
		keys[i] = splitmix64(&rng)
	}
	filter, _ := populatef(keys)

	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		filter.Contains(keys[n%len(keys)])
	}
}

var xor8big *Xor8

func xor8bigInit() {
	fmt.Println("Xor8 setup")
	keys := make([]uint64, 50000000)
	for i := range keys {
		keys[i] = rand.Uint64()
	}
	xor8big, _ = Populate(keys)
	fmt.Println("Xor8 setup ok")
}

func BenchmarkXor8bigContains50000000(b *testing.B) {
	if xor8big == nil {
		xor8bigInit()
	}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		xor8big.Contains(rand.Uint64())
	}
}
