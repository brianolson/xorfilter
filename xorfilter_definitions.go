package xorfilter

// Xor8 offers a 0.3% false-positive probability
type Xor8 struct {
	XorFilterCommon
	Fingerprints []uint8
}

type XorFilterCommon struct {
	Seed        uint64
	BlockLength uint32
}

type xorset struct {
	xormask uint64
	count   uint32
}

type hashes struct {
	h  uint64
	h0 uint32
	h1 uint32
	h2 uint32
}

type keyindex struct {
	hash  uint64
	index uint32
}

type Filter interface {
	Contains(key uint64) bool
}
