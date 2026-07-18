package merkle

import (
	"encoding/hex"
	"testing"
)

func hexEntries(ss ...string) [][]byte {
	out := make([][]byte, len(ss))
	for i, s := range ss {
		b, err := hex.DecodeString(s)
		if err != nil {
			panic(err)
		}
		out[i] = b
	}
	return out
}

func TestEmptyRoot(t *testing.T) {
	// RFC 6962: MTH({}) = SHA-256("").
	const want = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got := hex.EncodeToString(NewTree().Root()); got != want {
		t.Fatalf("empty root = %s, want %s", got, want)
	}
	if got := hex.EncodeToString(RootFromEntries(nil)); got != want {
		t.Fatalf("reference empty root = %s, want %s", got, want)
	}
}

// TestRFC6962KnownVector checks the root of the 8 test entries from the
// Certificate Transparency reference test suite.
func TestRFC6962KnownVector(t *testing.T) {
	entries := hexEntries(
		"",
		"00",
		"10",
		"2021",
		"3031",
		"40414243",
		"5051525354555657",
		"606162636465666768696a6b6c6d6e6f",
	)
	const want = "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328"
	if got := hex.EncodeToString(RootFromEntries(entries)); got != want {
		t.Fatalf("8-entry root = %s, want %s", got, want)
	}
	// The streaming tree must agree with the reference.
	tr := NewTree()
	for _, e := range entries {
		tr.Append(e)
	}
	if got := hex.EncodeToString(tr.Root()); got != want {
		t.Fatalf("streaming 8-entry root = %s, want %s", got, want)
	}
}

func entriesN(n int) [][]byte {
	es := make([][]byte, n)
	for i := range es {
		es[i] = []byte{byte(i), byte(i >> 8), byte(i >> 16)}
	}
	return es
}

// TestStreamingMatchesReference checks the incremental root equals the recursive
// reference for every size across several power-of-two boundaries.
func TestStreamingMatchesReference(t *testing.T) {
	for n := 0; n <= 130; n++ {
		es := entriesN(n)
		tr := NewTree()
		for _, e := range es {
			tr.Append(e)
		}
		if !equalHash(tr.Root(), RootFromEntries(es)) {
			t.Fatalf("streaming root != reference root at n=%d", n)
		}
		if tr.Size() != n {
			t.Fatalf("size = %d, want %d", tr.Size(), n)
		}
	}
}

func leafHashes(entries [][]byte) [][]byte {
	ls := make([][]byte, len(entries))
	for i, e := range entries {
		ls[i] = LeafHash(e)
	}
	return ls
}

func TestInclusionProofAllLeaves(t *testing.T) {
	for _, n := range []int{1, 2, 3, 4, 5, 7, 8, 13, 16, 33} {
		es := entriesN(n)
		leaves := leafHashes(es)
		root := RootFromEntries(es)
		for m := 0; m < n; m++ {
			proof := InclusionProof(leaves, m)
			if !VerifyInclusion(m, n, leaves[m], root, proof) {
				t.Fatalf("inclusion proof failed for leaf %d of %d", m, n)
			}
			// Tampering with a proof node must break verification.
			if len(proof) > 0 {
				bad := make([][]byte, len(proof))
				copy(bad, proof)
				flipped := append([]byte(nil), bad[0]...)
				flipped[0] ^= 0xff
				bad[0] = flipped
				if VerifyInclusion(m, n, leaves[m], root, bad) {
					t.Fatalf("tampered inclusion proof accepted for leaf %d of %d", m, n)
				}
			}
			// A wrong leaf hash must not verify.
			wrong := append([]byte(nil), leaves[m]...)
			wrong[0] ^= 0xff
			if VerifyInclusion(m, n, wrong, root, proof) {
				t.Fatalf("inclusion proof accepted a wrong leaf hash (leaf %d of %d)", m, n)
			}
		}
	}
}

func TestConsistencyProofExhaustive(t *testing.T) {
	for n := 2; n <= 40; n++ {
		es := entriesN(n)
		leaves := leafHashes(es)
		root2 := RootFromEntries(es)
		for m := 1; m < n; m++ {
			root1 := RootFromEntries(es[:m])
			proof := ConsistencyProof(leaves, m)
			if !VerifyConsistency(m, n, root1, root2, proof) {
				t.Fatalf("consistency proof failed for m=%d n=%d", m, n)
			}
			// Wrong old root must fail.
			badRoot := append([]byte(nil), root1...)
			badRoot[0] ^= 0xff
			if VerifyConsistency(m, n, badRoot, root2, proof) {
				t.Fatalf("consistency accepted a wrong old root (m=%d n=%d)", m, n)
			}
			// Tampered proof must fail.
			if len(proof) > 0 {
				bad := make([][]byte, len(proof))
				copy(bad, proof)
				flipped := append([]byte(nil), bad[len(bad)-1]...)
				flipped[0] ^= 0xff
				bad[len(bad)-1] = flipped
				if VerifyConsistency(m, n, root1, root2, bad) {
					t.Fatalf("tampered consistency proof accepted (m=%d n=%d)", m, n)
				}
			}
		}
	}
}

func TestConsistencyEqualSize(t *testing.T) {
	es := entriesN(5)
	root := RootFromEntries(es)
	if !VerifyConsistency(5, 5, root, root, nil) {
		t.Fatal("equal-size consistency (empty proof) should verify")
	}
	if VerifyConsistency(5, 5, root, root, [][]byte{root}) {
		t.Fatal("equal-size consistency with a non-empty proof should fail")
	}
}
