package xorfilter

import (
	"errors"
	"math"
	"math/big"
	"math/rand"
)

type Filter interface {
	Contains(key []byte) bool
}

type XorN struct {
	XorFilterCommon

	Bits int

	// Fingerprints should be serialized as keeping the low XorN.Bits of each entry
	Fingerprints []uint32
}

type XorFilterCommon struct {
	Seed        big.Int
	BlockLength uint32
}

type xorset struct {
	xormask big.Int
	count   uint32
}

type hashes struct {
	h  *big.Int
	h0 uint32
	h1 uint32
	h2 uint32
}

type keyindex struct {
	hash  big.Int
	index uint32
}

// ErrTooManyIterations returned by populateCommon if the methos is unable to populate the stack within the iterations limit.
var ErrTooManyIterations = errors.New("too many iterations, you probably have duplicate keys")

// https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp
// MurmurHash3.cpp calls this fmix64()
/*
func murmur64(h uint64) uint64 {
	h ^= h >> 33
	h *= 0xff51afd7ed558ccd
	h ^= h >> 33
	h *= 0xc4ceb9fe1a85ec53
	h ^= h >> 33
	return h
        }
*/

var bigNegativeOne = big.NewInt(-1)

func bigmask(bits uint) *big.Int {
	x := new(big.Int)
	x.SetUint64(1)
	x.Lsh(x, bits)
	return x.Add(x, bigNegativeOne)
}

var mixa big.Int
var mixb big.Int
var mask256 = bigmask(256)
var maskuint32 big.Int

func init() {
	// TODO: test various mixa, mixb for resulting distribution?
	_, ok := mixa.SetString("0xff51afd7ed558ccd_ff51afd7ed558ccd_ff51afd7ed558ccd_ff51afd7ed558ccd", 0)
	if !ok {
		panic("bad mixa")
	}
	_, ok = mixb.SetString("0xc4ceb9fe1a85ec53_c4ceb9fe1a85ec53_c4ceb9fe1a85ec53_c4ceb9fe1a85ec53", 0)
	if !ok {
		panic("bad mixb")
	}
	/*
		mask256.SetUint64(1)
		mask256.Lsh(&mask256, 256)
		mask256.Add(&mask256, big.NewInt(-1))
	*/

	maskuint32.SetUint64(0x00000000ffffffff)
}

func fmix(h *big.Int) *big.Int {
	var b big.Int
	var c big.Int
	var d big.Int
	// c = h ^ (h >> 129)
	b.Rsh(h, 129)
	c.Xor(h, &b)

	b.Mul(&c, &mixa)
	c.And(&b, mask256) // mimic uint64*uint64 overflowing multiply keeping low bits

	b.Rsh(&c, 129)
	d.Xor(&c, &b)

	b.Mul(&d, &mixb)
	c.And(&b, mask256)

	b.Rsh(&c, 129)
	return d.Xor(&c, &b)
}

// returns random number, modifies the seed
func splitmix64(seed *uint64) uint64 {
	*seed = *seed + 0x9E3779B97F4A7C15
	z := *seed
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
	z = (z ^ (z >> 27)) * 0x94D049BB133111EB
	return z ^ (z >> 31)
}

/*
func mixsplit(key, seed uint64) uint64 {
	return murmur64(key + seed)
}
*/
func mixsplit(key, seed *big.Int) *big.Int {
	var t big.Int
	return fmix(t.Add(key, seed))
}

func reduce(hash, n uint32) uint32 {
	// http://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction/
	return uint32((uint64(hash) * uint64(n)) >> 32)
}

/*
func fingerprint(hash uint64) uint64 {
	return hash ^ (hash >> 32)
}
*/
func fingerprint(hash *big.Int) uint32 {
	var a big.Int
	a.Rsh(hash, 128)
	var b big.Int
	b.Xor(&a, hash)
	a.And(&b, &maskuint32)
	return uint32(a.Uint64())
}

func bigTo32(x *big.Int) uint32 {
	var a big.Int
	a.And(x, &maskuint32)
	return uint32(a.Uint64())
}

/*
func rotl64(n uint64, c int) uint64 {
	return (n << uint(c&63)) | (n >> uint((-c)&63))
}
*/

var mask85 = bigmask(85)
var mask171 = bigmask(171)

func rotl85(x *big.Int) *big.Int {
	// grab top bits, shift from hi to lo then mask
	var hilo big.Int
	hilo.Rsh(x, 256-85)
	hilo.And(&hilo, mask85)

	// mask low bits then shift up
	var lohi big.Int
	lohi.And(x, mask171)
	lohi.Lsh(&lohi, 85)
	return hilo.Or(&hilo, &lohi)
}

var mask86 = bigmask(86)
var mask170 = bigmask(170)

func rotl170(x *big.Int) *big.Int {
	var hilo big.Int
	hilo.Rsh(x, 256-170)
	hilo.And(&hilo, mask86)

	var lohi big.Int
	lohi.And(x, mask170)
	lohi.Lsh(&lohi, 86)
	return hilo.Or(&hilo, &lohi)
}

func (filter *XorN) mask() uint32 {
	return uint32(0x00000000ffffffff >> (32 - filter.Bits))
}

// Contains tell you whether the key is likely part of the set
func (filter *XorN) Contains(data []byte) bool {
	var key big.Int
	key.SetBytes(data)
	hash := mixsplit(&key, &filter.Seed)
	mask := filter.mask()
	f := uint32(fingerprint(hash)) & mask
	r0 := bigTo32(hash)
	r1 := bigTo32(rotl85(hash))  //uint32(rotl64(hash, 21))
	r2 := bigTo32(rotl170(hash)) //uint32(rotl64(hash, 42))
	h0 := reduce(r0, filter.BlockLength)
	h1 := reduce(r1, filter.BlockLength) + filter.BlockLength
	h2 := reduce(r2, filter.BlockLength) + 2*filter.BlockLength
	return f == (filter.Fingerprints[h0] ^ filter.Fingerprints[h1] ^ filter.Fingerprints[h2])
}

func (filter *XorFilterCommon) geth0h1h2(k *big.Int) hashes {
	hash := mixsplit(k, &filter.Seed)
	answer := hashes{}
	answer.h = hash
	r0 := bigTo32(hash)
	r1 := bigTo32(rotl85(hash))  //uint32(rotl64(hash, 21))
	r2 := bigTo32(rotl170(hash)) //uint32(rotl64(hash, 42))

	answer.h0 = reduce(r0, filter.BlockLength)
	answer.h1 = reduce(r1, filter.BlockLength)
	answer.h2 = reduce(r2, filter.BlockLength)
	return answer
}

func (filter *XorFilterCommon) geth0(hash *big.Int) uint32 {
	r0 := bigTo32(hash)
	return reduce(r0, filter.BlockLength)
}

func (filter *XorFilterCommon) geth1(hash *big.Int) uint32 {
	r1 := bigTo32(rotl85(hash)) //uint32(rotl64(hash, 21))
	return reduce(r1, filter.BlockLength)
}

func (filter *XorFilterCommon) geth2(hash *big.Int) uint32 {
	r2 := bigTo32(rotl170(hash)) //uint32(rotl64(hash, 42))
	return reduce(r2, filter.BlockLength)
}

// scan for values with a count of one
func scanCount(Qi []keyindex, setsi []xorset) ([]keyindex, int) {
	QiSize := 0

	// len(setsi) = filter.BlockLength
	for i, s := range setsi {
		if s.count == 1 {
			Qi[QiSize].index = uint32(i)
			Qi[QiSize].hash = s.xormask
			QiSize++
		}
	}
	return Qi, QiSize
}

// fill setsi to xorset{0, 0}
func resetSets(setsi []xorset) []xorset {
	for i := range setsi {
		//setsi[i] = xorset{0, 0}
		setsi[i].xormask.SetUint64(0)
		setsi[i].count = 0
	}
	return setsi
}

// The maximum  number of iterations allowed before the populate function returns an error
var MaxIterations = 100

type Rand interface {
	Read([]byte) (int, error)
}

// Builder holds allocated structures so that repeated filter construction can have a lower garbage collection overhead
type Builder struct {
	kiStore  []keyindex
	setStore []xorset

	//rngcounter uint64
	Rng Rand
}

func ensureKeyindexes(v []keyindex, n int) []keyindex {
	if cap(v) < n {
		return make([]keyindex, n)
	}
	// zero out prior data
	for i := 0; i < n; i++ {
		v[i].hash.SetUint64(0)
		v[i].index = 0
	}
	return v
}

func ensureXorset(v []xorset, n int) []xorset {
	if cap(v) < n {
		return make([]xorset, n)
	}
	// zero out prior data
	for i := 0; i < n; i++ {
		v[i].xormask.SetUint64(0)
		v[i].count = 0
	}
	return v
}

func (bld *Builder) getKeyIndexes(size, blockLength int) (stack, q0, q1, q2 []keyindex) {
	tot := size + (blockLength * 3)
	if len(bld.kiStore) < tot {
		bld.kiStore = make([]keyindex, tot)
	} else {
		// zero out old storage (make() zeroes new storage)
		for i := 0; i < tot; i++ {
			bld.kiStore[i] = keyindex{}
		}
	}
	stack = bld.kiStore[:size]
	pos := size
	q0 = bld.kiStore[pos : pos+blockLength]
	pos += blockLength
	q1 = bld.kiStore[pos : pos+blockLength]
	pos += blockLength
	q2 = bld.kiStore[pos : pos+blockLength]
	return
}

func (bld *Builder) getSets(blockLength int) (sets0, sets1, sets2 []xorset) {
	tot := blockLength * 3
	if len(bld.setStore) < tot {
		bld.setStore = make([]xorset, tot)
	} else {
		// zero out prior storage
		for i := 0; i < tot; i++ {
			bld.setStore[i] = xorset{}
		}
	}
	sets0 = bld.setStore[:blockLength]
	pos := blockLength
	sets1 = bld.setStore[pos : pos+blockLength]
	pos += blockLength
	sets2 = bld.setStore[pos : pos+blockLength]
	return
}

/*
func Populate(keys [][]byte) (*XorN, error) {
	var bld Builder
	return bld.Populate(keys)
}
*/
func PopulateN(keys [][]byte, bits int) (*XorN, error) {
	var bld Builder
	return bld.PopulateN(keys, bits)
}

// Populate fills the filter with provided keys.
// The caller is responsible to ensure that there are no duplicate keys.
// The function may return an error after too many iterations: it is almost
// surely an indication that you have duplicate keys.
func (bld *Builder) PopulateN(keys [][]byte, bits int) (*XorN, error) {
	size := len(keys)
	capacity := 32 + uint32(math.Ceil(1.23*float64(size)))
	capacity = capacity / 3 * 3 // round it down to a multiple of 3

	filter := &XorN{}
	// slice capacity defaults to length
	filter.Fingerprints = make([]uint32, capacity)
	filter.BlockLength = capacity / 3
	filter.Bits = bits

	stack, err := bld.populateCommon(keys, &filter.XorFilterCommon)
	if err != nil {
		return nil, err
	}

	mask := filter.mask()

	stacksize := size
	for stacksize > 0 {
		stacksize--
		ki := stack[stacksize]
		val := uint32(fingerprint(&ki.hash)) & mask
		if ki.index < filter.BlockLength {
			val ^= filter.Fingerprints[filter.geth1(&ki.hash)+filter.BlockLength] ^ filter.Fingerprints[filter.geth2(&ki.hash)+2*filter.BlockLength]
		} else if ki.index < 2*filter.BlockLength {
			val ^= filter.Fingerprints[filter.geth0(&ki.hash)] ^ filter.Fingerprints[filter.geth2(&ki.hash)+2*filter.BlockLength]
		} else {
			val ^= filter.Fingerprints[filter.geth0(&ki.hash)] ^ filter.Fingerprints[filter.geth1(&ki.hash)+filter.BlockLength]
		}
		filter.Fingerprints[ki.index] = val
	}

	return filter, nil
}

func (bld *Builder) randBytes(p []byte) {
	if bld.Rng == nil {
		bld.Rng = rand.New(rand.NewSource(rand.Int63()))
	}
	bld.Rng.Read(p)
}

func (bld *Builder) randUint256() *big.Int {
	var b [32]byte
	bld.randBytes(b[:])
	var out big.Int
	return out.SetBytes(b[:])
}

func (bld *Builder) populateCommon(keys [][]byte, filter *XorFilterCommon) (stack []keyindex, err error) {
	size := len(keys)
	filter.Seed.Set(bld.randUint256())

	stack, Q0, Q1, Q2 := bld.getKeyIndexes(size, int(filter.BlockLength))
	sets0, sets1, sets2 := bld.getSets(int(filter.BlockLength))
	iterations := 0

	for {
		iterations += 1
		if iterations > MaxIterations {
			return nil, ErrTooManyIterations
		}

		for i := 0; i < size; i++ {
			var v big.Int
			v.SetBytes(keys[i])
			hs := filter.geth0h1h2(&v)
			sets0[hs.h0].xormask.Xor(&sets0[hs.h0].xormask, hs.h)
			sets0[hs.h0].count++
			sets1[hs.h1].xormask.Xor(&sets1[hs.h1].xormask, hs.h)
			sets1[hs.h1].count++
			sets2[hs.h2].xormask.Xor(&sets2[hs.h2].xormask, hs.h)
			sets2[hs.h2].count++
		}

		// scan for values with a count of one
		Q0, Q0size := scanCount(Q0, sets0)
		Q1, Q1size := scanCount(Q1, sets1)
		Q2, Q2size := scanCount(Q2, sets2)

		stacksize := 0
		for Q0size+Q1size+Q2size > 0 {
			for Q0size > 0 {
				Q0size--
				keyindexvar := Q0[Q0size]
				index := keyindexvar.index
				if sets0[index].count == 0 {
					continue // not actually possible after the initial scan.
				}
				hash := &keyindexvar.hash
				h1 := filter.geth1(hash)
				h2 := filter.geth2(hash)
				stack[stacksize] = keyindexvar
				stacksize++

				sets1[h1].xormask.Xor(&sets1[h1].xormask, hash)
				sets1[h1].count--
				if sets1[h1].count == 1 {
					Q1[Q1size].index = h1
					Q1[Q1size].hash = sets1[h1].xormask
					Q1size++
				}

				sets2[h2].xormask.Xor(&sets2[h2].xormask, hash)
				sets2[h2].count--
				if sets2[h2].count == 1 {
					Q2[Q2size].index = h2
					Q2[Q2size].hash = sets2[h2].xormask
					Q2size++
				}
			}
			for Q1size > 0 {
				Q1size--
				keyindexvar := Q1[Q1size]
				index := keyindexvar.index
				if sets1[index].count == 0 {
					continue
				}
				hash := &keyindexvar.hash
				h0 := filter.geth0(hash)
				h2 := filter.geth2(hash)
				keyindexvar.index += filter.BlockLength
				stack[stacksize] = keyindexvar
				stacksize++

				sets0[h0].xormask.Xor(&sets0[h0].xormask, hash)
				sets0[h0].count--
				if sets0[h0].count == 1 {
					Q0[Q0size].index = h0
					Q0[Q0size].hash = sets0[h0].xormask
					Q0size++
				}

				sets2[h2].xormask.Xor(&sets2[h2].xormask, hash)
				sets2[h2].count--
				if sets2[h2].count == 1 {
					Q2[Q2size].index = h2
					Q2[Q2size].hash = sets2[h2].xormask
					Q2size++
				}
			}
			for Q2size > 0 {
				Q2size--
				keyindexvar := Q2[Q2size]
				index := keyindexvar.index
				if sets2[index].count == 0 {
					continue
				}
				hash := &keyindexvar.hash
				h0 := filter.geth0(hash)
				h1 := filter.geth1(hash)
				keyindexvar.index += 2 * filter.BlockLength
				stack[stacksize] = keyindexvar
				stacksize++

				sets0[h0].xormask.Xor(&sets0[h0].xormask, hash)
				sets0[h0].count--
				if sets0[h0].count == 1 {
					Q0[Q0size].index = h0
					Q0[Q0size].hash = sets0[h0].xormask
					Q0size++
				}

				sets1[h1].xormask.Xor(&sets1[h1].xormask, hash)
				sets1[h1].count--
				if sets1[h1].count == 1 {
					Q1[Q1size].index = h1
					Q1[Q1size].hash = sets1[h1].xormask
					Q1size++
				}
			}
		}

		if stacksize == size {
			// success
			break
		}

		sets0 = resetSets(sets0)
		sets1 = resetSets(sets1)
		sets2 = resetSets(sets2)

		filter.Seed.Set(bld.randUint256())
	}
	return stack, nil
}
