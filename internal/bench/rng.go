package bench

import (
	"crypto/sha256"
	"encoding/binary"
	"io"
)

// detReader is a deterministic byte stream: SHA-256 in counter mode over a
// 32-byte seed. It is an io.Reader we can hand to the crypto primitives so that,
// given the same seed, a run produces byte-for-byte identical randomness — and
// therefore identical ciphertexts and an identical (verified) tally — regardless
// of how work is scheduled across cores.
//
// This is NOT a production RNG. ÁBACO is a measurement instrument; reproducibility
// beats unpredictability here, and this is only ever used to drive a benchmark.
type detReader struct {
	seed    [32]byte
	counter uint64
	buf     []byte
}

func newDetReader(seed [32]byte) *detReader { return &detReader{seed: seed} }

func (d *detReader) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if len(d.buf) == 0 {
			var block [40]byte
			copy(block[:32], d.seed[:])
			binary.LittleEndian.PutUint64(block[32:], d.counter)
			d.counter++
			sum := sha256.Sum256(block[:])
			d.buf = sum[:]
		}
		c := copy(p[n:], d.buf)
		d.buf = d.buf[c:]
		n += c
	}
	return n, nil
}

// ballotSeed derives the per-ballot seed from the run seed and the ballot index,
// so ballot i always uses the same randomness independent of scheduling.
func ballotSeed(runSeed uint64, index int) [32]byte {
	var in [16]byte
	binary.LittleEndian.PutUint64(in[0:8], runSeed)
	binary.LittleEndian.PutUint64(in[8:16], uint64(index))
	return sha256.Sum256(in[:])
}

// setupReader derives the deterministic reader used for one-time setup (key
// dealing) from the run seed.
func setupReader(runSeed uint64) io.Reader {
	var in [16]byte
	binary.LittleEndian.PutUint64(in[0:8], runSeed)
	binary.LittleEndian.PutUint64(in[8:16], 0x5E10_0000)
	return newDetReader(sha256.Sum256(in[:]))
}

// NewSeededReader returns a deterministic byte stream from a 64-bit seed, so the
// demo command can be reproduced exactly with --seed. Not for production use.
func NewSeededReader(seed uint64) io.Reader {
	var in [16]byte
	binary.LittleEndian.PutUint64(in[0:8], seed)
	binary.LittleEndian.PutUint64(in[8:16], 0xDE_10_0000)
	return newDetReader(sha256.Sum256(in[:]))
}
