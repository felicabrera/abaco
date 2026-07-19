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

// TestStoredTreeMatchesReference validates the O(log n) StoredTree prover
// against the trusted reference functions by byte-equality, exhaustively across
// sizes and every leaf/split. The reference is itself anchored to the RFC 6962
// known-answer root, so this transitively validates StoredTree without trusting
// its algorithm by inspection.
func TestStoredTreeMatchesReference(t *testing.T) {
	for n := 0; n <= 130; n++ {
		es := entriesN(n)
		leaves := leafHashes(es)
		st := NewStoredTree(leaves)
		if st.Size() != n {
			t.Fatalf("StoredTree size = %d, want %d", st.Size(), n)
		}
		if !equalHash(st.Root(), RootFromEntries(es)) {
			t.Fatalf("StoredTree root != reference root at n=%d", n)
		}
		for m := 0; m < n; m++ {
			ref := InclusionProof(leaves, m)
			got := st.InclusionProof(m)
			if !equalProof(got, ref) {
				t.Fatalf("StoredTree inclusion proof != reference at n=%d m=%d", n, m)
			}
		}
		for m := 0; m <= n; m++ {
			if !equalHash(st.PrefixRoot(m), RootFromEntries(es[:m])) {
				t.Fatalf("StoredTree prefix root != reference at n=%d m=%d", n, m)
			}
		}
		for m := 1; m < n; m++ {
			ref := ConsistencyProof(leaves, m)
			got := st.ConsistencyProof(m)
			if !equalProof(got, ref) {
				t.Fatalf("StoredTree consistency proof != reference at n=%d m=%d", n, m)
			}
			// The stored prover's output must verify against the reference roots.
			if !VerifyConsistency(m, n, RootFromEntries(es[:m]), st.Root(), got) {
				t.Fatalf("StoredTree consistency proof failed to verify at n=%d m=%d", n, m)
			}
		}
	}
}

func equalProof(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !equalHash(a[i], b[i]) {
			return false
		}
	}
	return true
}

// ctKATEntries is the canonical 8-entry Certificate Transparency reference tree
// (same as TestRFC6962KnownVector), whose root is the RFC 6962 known answer.
func ctKATEntries() [][]byte {
	return hexEntries(
		"",
		"00",
		"10",
		"2021",
		"3031",
		"40414243",
		"5051525354555657",
		"606162636465666768696a6b6c6d6e6f",
	)
}

// katRoot is the RFC 6962 known-answer root of the 8-entry CT reference tree.
const katRoot = "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328"

// TestInclusionProofKnownVectors pins the audit paths of the canonical 8-entry
// Certificate Transparency tree to their published hashes, for both the O(n)
// reference and the O(log n) StoredTree, and checks each reconstructs the RFC
// 6962 known-answer root. These are the Certificate Transparency reference
// vectors (RFC 6962 / transparency-dev merkle testonly).
func TestInclusionProofKnownVectors(t *testing.T) {
	es := ctKATEntries()
	leaves := leafHashes(es)
	st := NewStoredTree(leaves)
	root := hexEntries(katRoot)[0]
	if !equalHash(RootFromEntries(es), root) {
		t.Fatalf("KAT tree root mismatch: %s", hex.EncodeToString(RootFromEntries(es)))
	}
	cases := []struct {
		m    int
		path []string
	}{
		{0, []string{
			"96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
			"5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
			"6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
		}},
		{3, []string{
			"0298d122906dcfc10892cb53a73992fc5b9f493ea4c9badb27b791b4127a7fe7",
			"fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
			"6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
		}},
		{7, []string{
			"b08693ec2e721597130641e8211e7eedccb4c26413963eee6c1e2ed16ffb1a5f",
			"0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
			"d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
		}},
	}
	for _, tc := range cases {
		want := hexEntries(tc.path...)
		if got := InclusionProof(leaves, tc.m); !equalProof(got, want) {
			t.Fatalf("reference inclusion proof m=%d = %v, want vector", tc.m, got)
		}
		if got := st.InclusionProof(tc.m); !equalProof(got, want) {
			t.Fatalf("StoredTree inclusion proof m=%d = %v, want vector", tc.m, got)
		}
		if !VerifyInclusion(tc.m, len(es), leaves[tc.m], root, want) {
			t.Fatalf("KAT inclusion proof m=%d did not reconstruct the RFC root", tc.m)
		}
	}
}

// TestConsistencyProofKnownVectors pins the consistency proofs of the canonical
// 8-entry CT tree to their published hashes and checks each verifies against the
// RFC 6962 known-answer roots.
func TestConsistencyProofKnownVectors(t *testing.T) {
	es := ctKATEntries()
	leaves := leafHashes(es)
	st := NewStoredTree(leaves)
	root := hexEntries(katRoot)[0]
	cases := []struct {
		m     int
		proof []string
	}{
		{2, []string{
			"5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
			"6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
		}},
		{3, []string{
			"0298d122906dcfc10892cb53a73992fc5b9f493ea4c9badb27b791b4127a7fe7",
			"07506a85fd9dd2f120eb694f86011e5bb4662e5c415a62917033d4a9624487e7",
			"fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
			"6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
		}},
		{4, []string{
			"6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
		}},
		{6, []string{
			"0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
			"ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
			"d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
		}},
	}
	for _, tc := range cases {
		want := hexEntries(tc.proof...)
		if got := ConsistencyProof(leaves, tc.m); !equalProof(got, want) {
			t.Fatalf("reference consistency proof m=%d = %v, want vector", tc.m, got)
		}
		if got := st.ConsistencyProof(tc.m); !equalProof(got, want) {
			t.Fatalf("StoredTree consistency proof m=%d = %v, want vector", tc.m, got)
		}
		root1 := RootFromEntries(es[:tc.m])
		if !VerifyConsistency(tc.m, len(es), root1, root, want) {
			t.Fatalf("KAT consistency proof m=%d did not verify against RFC roots", tc.m)
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
