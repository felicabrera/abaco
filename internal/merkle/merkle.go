// Package merkle implements the append-only Merkle Tree of RFC 6962
// (Certificate Transparency) — the log format used by Tessera / tlog-tiles and
// therefore by FARO.
//
// Two things are provided:
//
//   - A streaming Tree that computes the tree head (root) as entries are
//     appended, using only O(log n) memory (a stack of perfect-subtree roots, a
//     Merkle Mountain Range). This is what lets the benchmark insert 10M entries
//     without holding the tree in memory.
//
//   - Reference proof generation/verification: inclusion proofs (an entry is in
//     the log) and consistency proofs (an old head is a prefix of a new head).
//     These are FARO's core auditing feature. They are not on the election hot
//     path, so they operate on a stored slice of leaf hashes and are measured
//     separately.
//
// Domain separation. Leaves are hashed with a 0x00 prefix and internal nodes
// with a 0x01 prefix (RFC 6962 §2.1). The prefixes are mandatory: they make it
// impossible to pass an internal node off as a leaf, defeating second-preimage
// attacks on the tree.
package merkle

import (
	"crypto/sha256"
	"math/bits"
)

const (
	leafPrefix = 0x00
	nodePrefix = 0x01
)

// LeafHash returns SHA-256(0x00 || entry), the RFC 6962 hash of a leaf.
func LeafHash(entry []byte) []byte {
	h := sha256.New()
	h.Write([]byte{leafPrefix})
	h.Write(entry)
	return h.Sum(nil)
}

// nodeHash returns SHA-256(0x01 || left || right), the RFC 6962 hash of an
// internal node.
func nodeHash(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{nodePrefix})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// emptyRoot is the Merkle Tree Hash of the empty tree: SHA-256 of the empty
// string (RFC 6962 §2.1).
func emptyRoot() []byte {
	h := sha256.Sum256(nil)
	return h[:]
}

// --- Streaming tree (hot path, O(log n) memory) ---

type peak struct {
	size int // number of leaves under this subtree; always a power of two
	hash []byte
}

// Tree is an append-only Merkle tree that maintains only the roots of the
// perfect subtrees seen so far. Appending is amortised O(1) hashes and the
// resident state is O(log n).
type Tree struct {
	peaks []peak
	size  int
}

// NewTree returns an empty streaming tree.
func NewTree() *Tree { return &Tree{} }

// Size reports the number of entries appended so far.
func (t *Tree) Size() int { return t.size }

// Append adds one entry to the log.
func (t *Tree) Append(entry []byte) {
	p := peak{size: 1, hash: LeafHash(entry)}
	// Merge equal-sized top subtrees, cascading upward. The earlier (deeper)
	// subtree is the left child, the new one the right child.
	for len(t.peaks) > 0 && t.peaks[len(t.peaks)-1].size == p.size {
		left := t.peaks[len(t.peaks)-1]
		t.peaks = t.peaks[:len(t.peaks)-1]
		p = peak{size: left.size * 2, hash: nodeHash(left.hash, p.hash)}
	}
	t.peaks = append(t.peaks, p)
	t.size++
}

// Root returns the current RFC 6962 tree head. The peaks (perfect subtrees of
// strictly decreasing size, left to right) are folded right-to-left with
// nodeHash, which reproduces the RFC's recursive definition for any n.
func (t *Tree) Root() []byte {
	if len(t.peaks) == 0 {
		return emptyRoot()
	}
	acc := t.peaks[len(t.peaks)-1].hash
	for i := len(t.peaks) - 2; i >= 0; i-- {
		acc = nodeHash(t.peaks[i].hash, acc)
	}
	return acc
}

// --- Reference tree over stored leaf hashes (proofs) ---

// largestPowerOfTwoLessThan returns the largest power of two strictly less than
// n, for n >= 2. This is the split point k in RFC 6962's recursive definitions.
func largestPowerOfTwoLessThan(n int) int {
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}

// rootFromLeafHashes computes MTH(D) for the given leaf hashes, per RFC 6962.
func rootFromLeafHashes(leaves [][]byte) []byte {
	n := len(leaves)
	if n == 0 {
		return emptyRoot()
	}
	if n == 1 {
		return leaves[0]
	}
	k := largestPowerOfTwoLessThan(n)
	return nodeHash(rootFromLeafHashes(leaves[:k]), rootFromLeafHashes(leaves[k:]))
}

// RootFromEntries hashes each entry and returns the tree head. Convenience for
// tests and the reference path.
func RootFromEntries(entries [][]byte) []byte {
	leaves := make([][]byte, len(entries))
	for i, e := range entries {
		leaves[i] = LeafHash(e)
	}
	return rootFromLeafHashes(leaves)
}

// InclusionProof returns the audit path proving that the leaf at index m is
// included in a tree of the given leaf hashes (RFC 6962 §2.1.1). The path is the
// list of sibling hashes from the leaf up to the root.
func InclusionProof(leaves [][]byte, m int) [][]byte {
	var path [][]byte
	var rec func(lo, hi, idx int)
	rec = func(lo, hi, idx int) {
		n := hi - lo
		if n == 1 {
			return
		}
		k := largestPowerOfTwoLessThan(n)
		if idx < k {
			rec(lo, lo+k, idx)                                       // descend left
			path = append(path, rootFromLeafHashes(leaves[lo+k:hi])) // right sibling
		} else {
			rec(lo+k, hi, idx-k)                                     // descend right
			path = append(path, rootFromLeafHashes(leaves[lo:lo+k])) // left sibling
		}
	}
	rec(0, len(leaves), m)
	return path
}

// VerifyInclusion recomputes the root from a leaf hash, its index m, the tree
// size, and the audit path, and reports whether it matches root.
func VerifyInclusion(m, size int, leafHash, root []byte, path [][]byte) bool {
	pos := 0
	var rec func(m, n int) []byte
	rec = func(m, n int) []byte {
		if n == 1 {
			return leafHash
		}
		k := largestPowerOfTwoLessThan(n)
		if pos >= len(path) {
			return nil
		}
		var got []byte
		if m < k {
			left := rec(m, k)
			sib := path[pos]
			pos++
			got = nodeHash(left, sib)
		} else {
			right := rec(m-k, n-k)
			sib := path[pos]
			pos++
			got = nodeHash(sib, right)
		}
		return got
	}
	if m < 0 || m >= size || size < 1 {
		return false
	}
	got := rec(m, size)
	return got != nil && pos == len(path) && equalHash(got, root)
}

// ConsistencyProof returns a proof that a tree of size m (0 < m < n) is a prefix
// of the tree of size n (RFC 6962 §2.1.2, PROOF = SUBPROOF(m, D[n], true)).
func ConsistencyProof(leaves [][]byte, m int) [][]byte {
	n := len(leaves)
	if m <= 0 || m >= n {
		return nil
	}
	var proof [][]byte
	var subproof func(lo, hi, m int, b bool)
	subproof = func(lo, hi, m int, b bool) {
		n := hi - lo
		if m == n {
			if !b {
				proof = append(proof, rootFromLeafHashes(leaves[lo:hi]))
			}
			return
		}
		k := largestPowerOfTwoLessThan(n)
		if m <= k {
			subproof(lo, lo+k, m, b)
			proof = append(proof, rootFromLeafHashes(leaves[lo+k:hi])) // MTH(D[k:n])
		} else {
			subproof(lo+k, hi, m-k, false)
			proof = append(proof, rootFromLeafHashes(leaves[lo:lo+k])) // MTH(D[0:k])
		}
	}
	subproof(0, n, m, true)
	return proof
}

// VerifyConsistency checks that root1 (a tree of size m) is consistent with
// root2 (a tree of size n) given a consistency proof. It reconstructs both the
// old and new heads from the proof, mirroring the SUBPROOF recursion, and
// requires both to match.
//
// The seed for the b==true base case is the claimed old head root1: that base is
// only reached when the old size is a power of two, in which case the old tree
// is itself the perfect subtree whose hash is root1 (and which is unchanged in
// the new tree).
func VerifyConsistency(m, n int, root1, root2 []byte, proof [][]byte) bool {
	switch {
	case m > n:
		return false
	case m == n:
		return len(proof) == 0 && equalHash(root1, root2)
	case m <= 0:
		return len(proof) == 0
	}

	pos := 0
	var ok = true
	// rec returns (oldHash, newHash) for a node covering n leaves whose first m
	// are "old". It consumes proof entries left to right.
	var rec func(m, n int, b bool) ([]byte, []byte)
	rec = func(m, n int, b bool) ([]byte, []byte) {
		if m == n {
			if b {
				return root1, root1 // seed
			}
			if pos >= len(proof) {
				ok = false
				return nil, nil
			}
			h := proof[pos]
			pos++
			return h, h
		}
		k := largestPowerOfTwoLessThan(n)
		if m <= k {
			lo, ln := rec(m, k, b)
			if pos >= len(proof) {
				ok = false
				return nil, nil
			}
			sib := proof[pos]
			pos++
			// Old head is the left child's old head; new head combines the full
			// left subtree with the right sibling.
			return lo, nodeHash(ln, sib)
		}
		lo, ln := rec(m-k, n-k, false)
		if pos >= len(proof) {
			ok = false
			return nil, nil
		}
		sib := proof[pos]
		pos++
		// Left k-subtree (sib) is complete and identical in both trees.
		return nodeHash(sib, lo), nodeHash(sib, ln)
	}

	oldRoot, newRoot := rec(m, n, true)
	if !ok || pos != len(proof) {
		return false
	}
	return equalHash(oldRoot, root1) && equalHash(newRoot, root2)
}

// --- Stored tree (O(log n) proof generation) ---
//
// The reference InclusionProof/ConsistencyProof above recompute every sibling
// subtree root from the raw leaf slice, so a single proof costs O(n) hashes.
// That is fine as a correctness oracle but not as a model of a real log server,
// which stores the tree and serves audit paths in O(log n). StoredTree keeps
// every level of the tree so a proof reads a handful of stored nodes instead of
// rehashing the log.
//
// The levels are the standard Certificate Transparency "left-full" form:
// levels[0] is the leaf hashes; each higher level combines adjacent pairs with
// nodeHash and carries a lone right node up unchanged. This reproduces RFC
// 6962's recursive Merkle Tree Hash exactly (the equivalence Trillian and other
// CT logs rely on), which the tests assert against the reference by byte-equality.

// StoredTree materialises every level of the RFC 6962 tree over a fixed set of
// leaf hashes. It is immutable once built.
type StoredTree struct {
	levels [][][]byte // levels[0] = leaves; levels[d] = nodes d up from the leaves
	size   int
}

// NewStoredTree builds the level structure over the given leaf hashes in O(n)
// hashes and O(n) memory. The caller's slice is not retained (the top level is
// copied), though the leaf hash bytes are shared read-only.
func NewStoredTree(leaves [][]byte) *StoredTree {
	st := &StoredTree{size: len(leaves)}
	if len(leaves) == 0 {
		return st
	}
	level := make([][]byte, len(leaves))
	copy(level, leaves)
	st.levels = append(st.levels, level)
	for len(level) > 1 {
		next := make([][]byte, 0, (len(level)+1)/2)
		for i := 0; i+1 < len(level); i += 2 {
			next = append(next, nodeHash(level[i], level[i+1]))
		}
		if len(level)%2 == 1 {
			next = append(next, level[len(level)-1]) // promote the lone right node
		}
		st.levels = append(st.levels, next)
		level = next
	}
	return st
}

// Size reports the number of leaves.
func (s *StoredTree) Size() int { return s.size }

// Root returns the RFC 6962 tree head. It is the single node at the top level.
func (s *StoredTree) Root() []byte {
	if s.size == 0 {
		return emptyRoot()
	}
	return s.levels[len(s.levels)-1][0]
}

// rangeRoot returns MTH(D[lo:hi]) for 0 <= lo < hi <= size, reading stored
// perfect subtrees where the range is aligned and recursing only down the right
// spine. It mirrors RFC 6962's recursive definition, so it is byte-identical to
// rootFromLeafHashes(leaves[lo:hi]) but costs O(log n) rather than O(hi-lo).
func (s *StoredTree) rangeRoot(lo, hi int) []byte {
	n := hi - lo
	if n == 1 {
		return s.levels[0][lo]
	}
	// A power-of-two range aligned to its own size is a perfect subtree whose
	// root is stored directly (its full leaf span fits within the tree, so it is
	// never a promoted partial node).
	if n&(n-1) == 0 && lo&(n-1) == 0 {
		level := bits.TrailingZeros(uint(n))
		return s.levels[level][lo>>level]
	}
	k := largestPowerOfTwoLessThan(n)
	return nodeHash(s.rangeRoot(lo, lo+k), s.rangeRoot(lo+k, hi))
}

// PrefixRoot returns MTH(D[0:m]), the tree head the log had at size m — the "old
// root" a consistency proof is checked against. O(log n).
func (s *StoredTree) PrefixRoot(m int) []byte {
	switch {
	case m <= 0:
		return emptyRoot()
	case m >= s.size:
		return s.Root()
	default:
		return s.rangeRoot(0, m)
	}
}

// InclusionProof returns the audit path for the leaf at index m. It follows the
// same recursion as the reference InclusionProof, so its output is byte-for-byte
// identical, but reads sibling subtree roots from storage in O(log n).
func (s *StoredTree) InclusionProof(m int) [][]byte {
	var path [][]byte
	var rec func(lo, hi, idx int)
	rec = func(lo, hi, idx int) {
		n := hi - lo
		if n == 1 {
			return
		}
		k := largestPowerOfTwoLessThan(n)
		if idx < k {
			rec(lo, lo+k, idx)
			path = append(path, s.rangeRoot(lo+k, hi)) // right sibling
		} else {
			rec(lo+k, hi, idx-k)
			path = append(path, s.rangeRoot(lo, lo+k)) // left sibling
		}
	}
	if m < 0 || m >= s.size {
		return nil
	}
	rec(0, s.size, m)
	return path
}

// ConsistencyProof proves that the tree at size m is a prefix of this tree. It
// follows the reference SUBPROOF recursion with stored range roots, so its
// output matches ConsistencyProof(leaves, m) byte-for-byte in O(log n).
func (s *StoredTree) ConsistencyProof(m int) [][]byte {
	n := s.size
	if m <= 0 || m >= n {
		return nil
	}
	var proof [][]byte
	var subproof func(lo, hi, m int, b bool)
	subproof = func(lo, hi, m int, b bool) {
		n := hi - lo
		if m == n {
			if !b {
				proof = append(proof, s.rangeRoot(lo, hi))
			}
			return
		}
		k := largestPowerOfTwoLessThan(n)
		if m <= k {
			subproof(lo, lo+k, m, b)
			proof = append(proof, s.rangeRoot(lo+k, hi)) // MTH(D[k:n])
		} else {
			subproof(lo+k, hi, m-k, false)
			proof = append(proof, s.rangeRoot(lo, lo+k)) // MTH(D[0:k])
		}
	}
	subproof(0, n, m, true)
	return proof
}

func equalHash(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
