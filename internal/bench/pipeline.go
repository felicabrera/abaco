package bench

import (
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"github.com/felicabrera/abaco/internal/elgamal"
	"github.com/felicabrera/abaco/internal/group"
	"github.com/felicabrera/abaco/internal/merkle"
	"github.com/felicabrera/abaco/internal/threshold"
	"github.com/felicabrera/abaco/internal/zkp"
)

// election holds the fixed setup shared by every scale and repeat of a run: the
// group, the (threshold-shared) key, and the ballot shape. It is built once,
// deterministically from the run seed.
type election struct {
	g           group.Group
	pk          *elgamal.PublicKey
	shares      []threshold.Share
	threshold   int
	candidates  int
	runSeed     uint64
	reservoirID int64
}

// newElection deals a fresh threshold key and returns the election setup.
func newElection(g group.Group, runSeed uint64, candidates, authorities, threshold_ int) (*election, error) {
	if candidates < 1 {
		return nil, fmt.Errorf("bench: need at least 1 candidate")
	}
	x, shares, err := threshold.Deal(g, authorities, threshold_, setupReader(runSeed))
	if err != nil {
		return nil, err
	}
	return &election{
		g:          g,
		pk:         elgamal.PublicKeyFrom(g, x),
		shares:     shares,
		threshold:  threshold_,
		candidates: candidates,
		runSeed:    runSeed,
	}, nil
}

// ballotResult is what a worker produces for one ballot: the C ciphertexts to be
// tallied, the log entry to append, and which candidate was selected (for the
// expected-tally bookkeeping). Proofs are verified and then discarded.
type ballotResult struct {
	cts  []*elgamal.Ciphertext
	leaf []byte
	sel  int
}

// computeBallot runs the parallel part of the pipeline for one ballot: encrypt
// each candidate slot, prove and verify each {0,1} ciphertext, then prove and
// verify the 1-of-C aggregate. All six per-ballot operations are timed into
// meter. Randomness is deterministic in the ballot index.
func (e *election) computeBallot(index int, meter *Meter) (ballotResult, error) {
	g, pk, C := e.g, e.pk, e.candidates
	rd := newDetReader(ballotSeed(e.runSeed, index))
	sel := int(readUint64(rd) % uint64(C))

	cts := make([]*elgamal.Ciphertext, C)
	rs := make([]group.Scalar, C)
	for c := 0; c < C; c++ {
		v := uint64(0)
		if c == sel {
			v = 1
		}
		var (
			ct     *elgamal.Ciphertext
			r      group.Scalar
			encErr error
		)
		meter.time(OpEncrypt, func() { ct, r, encErr = elgamal.EncryptRandom(pk, v, rd) })
		if encErr != nil {
			return ballotResult{}, encErr
		}
		var proof *zkp.BallotProof
		var pErr error
		meter.time(OpProveBallot, func() { proof, pErr = zkp.ProveBallot(pk, ct, v, r, rd) })
		if pErr != nil {
			return ballotResult{}, pErr
		}
		var ok bool
		meter.time(OpVerifyBallot, func() { ok = zkp.VerifyBallot(pk, ct, proof) })
		if !ok {
			return ballotResult{}, fmt.Errorf("bench: ballot %d slot %d: OR-proof failed to verify", index, c)
		}
		cts[c], rs[c] = ct, r
	}

	// Aggregate the ballot's ciphertexts and the summed randomness R, then prove
	// the aggregate encrypts exactly 1 (the 1-of-C rule). Building the aggregate
	// here is proof preparation; the measured "Homomorphic add" is the tally
	// aggregation in the sequential stage.
	agg := elgamal.Identity(g)
	R := g.NewScalar()
	for c := 0; c < C; c++ {
		agg = elgamal.Add(agg, cts[c])
		R = R.Add(rs[c])
	}
	var sumProof *zkp.SumProof
	var spErr error
	meter.time(OpProveSum, func() { sumProof, spErr = zkp.ProveSum(pk, agg, R, rd) })
	if spErr != nil {
		return ballotResult{}, spErr
	}
	var ok bool
	meter.time(OpVerifySum, func() { ok = zkp.VerifySum(pk, agg, sumProof) })
	if !ok {
		return ballotResult{}, fmt.Errorf("bench: ballot %d: 1-of-C proof failed to verify", index)
	}

	// The log entry is the encrypted ballot: A||B for each candidate slot.
	leaf := make([]byte, 0, C*64)
	for c := 0; c < C; c++ {
		leaf = append(leaf, cts[c].A.Bytes()...)
		leaf = append(leaf, cts[c].B.Bytes()...)
	}
	return ballotResult{cts: cts, leaf: leaf, sel: sel}, nil
}

// runScale executes the full streaming pipeline for `votes` ballots and returns
// the per-candidate homomorphic accumulators, the expected per-candidate tally,
// and the final Merkle head. Peak memory is O(batch*C + log n): constant in the
// number of votes.
func (e *election) runScale(votes, batch, cores int, meter *Meter, progress func(done int)) ([]*elgamal.Ciphertext, []uint64, []byte, error) {
	g, C := e.g, e.candidates

	acc := make([]*elgamal.Ciphertext, C)
	for c := range acc {
		acc[c] = elgamal.Identity(g)
	}
	expected := make([]uint64, C)
	tree := merkle.NewTree()

	for start := 0; start < votes; start += batch {
		end := min(start+batch, votes)
		results := make([]ballotResult, end-start)

		// Parallel stage: workers pull ballot indices from a shared counter, each
		// timing into its own meter to avoid contention.
		workerMeters := make([]*Meter, cores)
		counter := int64(start)
		var wg sync.WaitGroup
		var once sync.Once
		var firstErr error
		for w := 0; w < cores; w++ {
			wm := newMeter(e.reservoirID + int64(w)*int64(numOps))
			workerMeters[w] = wm
			wg.Add(1)
			go func(wm *Meter) {
				defer wg.Done()
				for {
					i := int(atomic.AddInt64(&counter, 1) - 1)
					if i >= end {
						return
					}
					res, err := e.computeBallot(i, wm)
					if err != nil {
						once.Do(func() { firstErr = err })
						return
					}
					results[i-start] = res
				}
			}(wm)
		}
		wg.Wait()
		if firstErr != nil {
			return nil, nil, nil, firstErr
		}
		for _, wm := range workerMeters {
			meter.merge(wm)
		}
		// Advance the reservoir seed base so different batches don't reuse seeds.
		e.reservoirID += int64(cores) * int64(numOps)

		// Sequential stage, in ballot-index order (the Merkle log demands a
		// deterministic order). Ballots are discarded as we go.
		for j := range results {
			res := results[j]
			for c := 0; c < C; c++ {
				meter.time(OpHomomorphicAdd, func() { acc[c] = elgamal.Add(acc[c], res.cts[c]) })
			}
			meter.time(OpMerkleAppend, func() { tree.Append(res.leaf) })
			expected[res.sel]++
		}
		if progress != nil {
			progress(end)
		}
	}

	return acc, expected, tree.Root(), nil
}

// finalizeTally performs threshold decryption of every candidate accumulator and
// recovers the integer tallies with BSGS. The partial-decrypt, Lagrange-combine
// and BSGS steps are timed into meter.
func (e *election) finalizeTally(acc []*elgamal.Ciphertext, votes int, meter *Meter) ([]uint64, error) {
	g, C := e.g, e.candidates
	quorum := e.shares[:e.threshold]
	tallies := make([]uint64, C)

	for c := 0; c < C; c++ {
		partials := make([]threshold.PartialDecryption, e.threshold)
		for k := 0; k < e.threshold; k++ {
			share := quorum[k]
			A := acc[c].A
			meter.time(OpPartialDecrypt, func() { partials[k] = share.PartialDecrypt(A) })
		}
		var xA group.Element
		meter.time(OpLagrangeCombine, func() { xA = threshold.Combine(g, partials) })
		mPoint := acc[c].B.Sub(xA)

		var cnt uint64
		var ok bool
		meter.time(OpBSGS, func() { cnt, ok = BSGS(g, mPoint, uint64(votes)) })
		if !ok {
			return nil, fmt.Errorf("bench: BSGS failed to recover tally for candidate %d", c)
		}
		tallies[c] = cnt
	}
	return tallies, nil
}

func readUint64(r io.Reader) uint64 {
	var b [8]byte
	_, _ = io.ReadFull(r, b[:])
	return binary.LittleEndian.Uint64(b[:])
}
