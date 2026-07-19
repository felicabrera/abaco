package bench

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"math/rand"
	"sort"
	"time"

	"github.com/felicabrera/abaco/internal/merkle"
	"github.com/felicabrera/abaco/internal/report"
)

// The four audit-proof operations. They are FARO's core auditing feature but sit
// off the election hot path, so they are measured in this separate phase with
// their own accumulators and reported apart from the pipeline breakdown — the
// pipeline's "% of pipeline" column stays about the pipeline.
const (
	proofInclProve = iota
	proofInclVerify
	proofConsProve
	proofConsVerify
	numProofOps
)

var proofOpNames = [numProofOps]string{
	proofInclProve:  "Inclusion prove",
	proofInclVerify: "Inclusion verify",
	proofConsProve:  "Consistency prove",
	proofConsVerify: "Consistency verify",
}

// proofEntry is the deterministic synthetic log entry for leaf index i. Proof
// cost and shape depend only on the tree size and structure, not on ballot
// contents, so index-derived entries keep the proof benchmark independent of the
// election pipeline (which discards its leaves to stay memory-flat).
func proofEntry(i int) []byte {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], uint64(i))
	return b[:]
}

// measureProofs builds a stored Merkle tree of treeSize leaves and times
// inclusion and consistency proof generation and verification over `samples`
// random leaves/splits, recording proof sizes. Verification results are gated:
// every sampled proof must verify and a tampered proof must be rejected, else it
// fails loudly — a benchmark of an incorrect proof is worthless.
func measureProofs(treeSize, samples int, seed int64) (report.ProofResult, error) {
	if treeSize < 2 {
		return report.ProofResult{}, fmt.Errorf("proof scale must be >= 2, got %d", treeSize)
	}
	if samples < 1 {
		samples = 1
	}

	leaves := make([][]byte, treeSize)
	for i := range leaves {
		leaves[i] = merkle.LeafHash(proofEntry(i))
	}
	st := merkle.NewStoredTree(leaves)
	root := st.Root()

	// Correctness gate: the stored tree head must equal the independent streaming
	// tree over the same entries.
	streaming := merkle.NewTree()
	for i := 0; i < treeSize; i++ {
		streaming.Append(proofEntry(i))
	}
	if !bytes.Equal(root, streaming.Root()) {
		return report.ProofResult{}, fmt.Errorf(
			"CORRECTNESS FAILURE: stored proof-tree head != streaming head at size %d", treeSize)
	}

	rng := rand.New(rand.NewSource(seed ^ int64(treeSize)))

	inclProve := newOpStats(seed + 1)
	inclVerify := newOpStats(seed + 2)
	consProve := newOpStats(seed + 3)
	consVerify := newOpStats(seed + 4)

	// Warm up caches/branch predictor with a few untimed proofs.
	for i := 0; i < 8; i++ {
		m := rng.Intn(treeSize)
		_ = merkle.VerifyInclusion(m, treeSize, leaves[m], root, st.InclusionProof(m))
	}

	// --- Inclusion proofs ---
	inclMin, inclMax := -1, 0
	for i := 0; i < samples; i++ {
		m := rng.Intn(treeSize)

		t0 := time.Now()
		path := st.InclusionProof(m)
		inclProve.record(time.Since(t0))

		t1 := time.Now()
		ok := merkle.VerifyInclusion(m, treeSize, leaves[m], root, path)
		inclVerify.record(time.Since(t1))
		if !ok {
			return report.ProofResult{}, fmt.Errorf(
				"CORRECTNESS FAILURE: inclusion proof for leaf %d of %d did not verify", m, treeSize)
		}
		if n := len(path); inclMin < 0 || n < inclMin {
			inclMin = n
		}
		if n := len(path); n > inclMax {
			inclMax = n
		}
	}
	if err := checkTamperInclusion(st, leaves, root, treeSize); err != nil {
		return report.ProofResult{}, err
	}

	// --- Consistency proofs (m = treeSize/2 first, then random splits) ---
	consMin, consMax := -1, 0
	for i := 0; i < samples; i++ {
		m := 1 + rng.Intn(treeSize-1)
		if i == 0 {
			if half := treeSize / 2; half >= 1 {
				m = half
			}
		}
		root1 := st.PrefixRoot(m) // the log's head at size m; stored server state

		t0 := time.Now()
		proof := st.ConsistencyProof(m)
		consProve.record(time.Since(t0))

		t1 := time.Now()
		ok := merkle.VerifyConsistency(m, treeSize, root1, root, proof)
		consVerify.record(time.Since(t1))
		if !ok {
			return report.ProofResult{}, fmt.Errorf(
				"CORRECTNESS FAILURE: consistency proof m=%d n=%d did not verify", m, treeSize)
		}
		if n := len(proof); consMin < 0 || n < consMin {
			consMin = n
		}
		if n := len(proof); n > consMax {
			consMax = n
		}
	}
	if err := checkTamperConsistency(st, root, treeSize); err != nil {
		return report.ProofResult{}, err
	}

	log2n := math.Ceil(math.Log2(float64(treeSize)))
	return report.ProofResult{
		TreeSize: treeSize,
		Samples:  samples,
		Ops: []report.OpSummary{
			proofSummary(proofOpNames[proofInclProve], inclProve),
			proofSummary(proofOpNames[proofInclVerify], inclVerify),
			proofSummary(proofOpNames[proofConsProve], consProve),
			proofSummary(proofOpNames[proofConsVerify], consVerify),
		},
		InclusionSize:   proofSize(inclMin, inclMax, log2n),
		ConsistencySize: proofSize(consMin, consMax, log2n),
	}, nil
}

// checkTamperInclusion asserts a proof with one flipped hash is rejected.
func checkTamperInclusion(st *merkle.StoredTree, leaves [][]byte, root []byte, treeSize int) error {
	path := st.InclusionProof(0)
	if len(path) == 0 {
		return nil
	}
	bad := clonePath(path)
	bad[0][0] ^= 0xff
	if merkle.VerifyInclusion(0, treeSize, leaves[0], root, bad) {
		return fmt.Errorf("CORRECTNESS FAILURE: tampered inclusion proof accepted at size %d", treeSize)
	}
	return nil
}

// checkTamperConsistency asserts a proof with one flipped hash is rejected.
func checkTamperConsistency(st *merkle.StoredTree, root []byte, treeSize int) error {
	m := treeSize / 2
	if m < 1 {
		m = 1
	}
	root1 := st.PrefixRoot(m)
	proof := st.ConsistencyProof(m)
	if len(proof) == 0 {
		return nil
	}
	bad := clonePath(proof)
	bad[len(bad)-1][0] ^= 0xff
	if merkle.VerifyConsistency(m, treeSize, root1, root, bad) {
		return fmt.Errorf("CORRECTNESS FAILURE: tampered consistency proof accepted at size %d", treeSize)
	}
	return nil
}

func clonePath(p [][]byte) [][]byte {
	out := make([][]byte, len(p))
	for i := range p {
		out[i] = append([]byte(nil), p[i]...)
	}
	return out
}

func proofSize(minHashes, maxHashes int, log2n float64) report.ProofSize {
	if minHashes < 0 {
		minHashes = 0
	}
	return report.ProofSize{
		Hashes:    maxHashes,
		MinHashes: minHashes,
		MaxHashes: maxHashes,
		Bytes:     maxHashes * 32, // SHA-256 output size
		Log2N:     log2n,
	}
}

// proofSummary converts a proof op's accumulator into a report.OpSummary. It
// mirrors Meter.summaries but leaves PercentOfPipeline at zero, since proofs are
// deliberately not part of the election pipeline total.
func proofSummary(name string, s *opStats) report.OpSummary {
	if s.count == 0 {
		return report.OpSummary{Name: name}
	}
	mean := s.sumNanos / float64(s.count)
	variance := s.sumSqNs/float64(s.count) - mean*mean
	if variance < 0 {
		variance = 0
	}
	res := append([]int64(nil), s.reservoir...)
	sort.Slice(res, func(a, b int) bool { return res[a] < res[b] })
	return report.OpSummary{
		Name:          name,
		Calls:         s.count,
		MedianNanos:   quantile(res, 50),
		MeanNanos:     mean,
		P95Nanos:      quantile(res, 95),
		P99Nanos:      quantile(res, 99),
		MinNanos:      float64(maxZero(s.min)),
		MaxNanos:      float64(s.max),
		StdDevNanos:   math.Sqrt(variance),
		TotalCPUNanos: s.sumNanos,
	}
}
