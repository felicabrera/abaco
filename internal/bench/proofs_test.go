package bench

import "testing"

func TestMeasureProofs(t *testing.T) {
	for _, tc := range []struct {
		size      int
		wantHashN int // ceil(log2 size), the expected max path length
	}{
		{1024, 10},
		{1000, 10},
		{2, 1},
		{100000, 17},
	} {
		pr, err := measureProofs(tc.size, 64, 42)
		if err != nil {
			t.Fatalf("measureProofs(%d): %v", tc.size, err)
		}
		if pr.TreeSize != tc.size {
			t.Fatalf("tree size = %d, want %d", pr.TreeSize, tc.size)
		}
		if len(pr.Ops) != numProofOps {
			t.Fatalf("got %d proof ops, want %d", len(pr.Ops), numProofOps)
		}
		for _, op := range pr.Ops {
			if op.Calls == 0 {
				t.Fatalf("size %d: proof op %q has zero calls", tc.size, op.Name)
			}
		}
		// Proof size is O(log n): the audit path never exceeds ceil(log2 n) hashes.
		if pr.InclusionSize.MaxHashes > tc.wantHashN {
			t.Fatalf("size %d: inclusion proof %d hashes exceeds ceil(log2 n)=%d",
				tc.size, pr.InclusionSize.MaxHashes, tc.wantHashN)
		}
		if pr.ConsistencySize.MaxHashes > tc.wantHashN+1 {
			t.Fatalf("size %d: consistency proof %d hashes far exceeds log2 n=%d",
				tc.size, pr.ConsistencySize.MaxHashes, tc.wantHashN)
		}
		if pr.InclusionSize.Bytes != pr.InclusionSize.MaxHashes*32 {
			t.Fatalf("inclusion bytes %d != hashes*32", pr.InclusionSize.Bytes)
		}
	}
}

// TestMeasureProofsDeterministic checks the same seed yields the same proof
// sizes, matching ÁBACO's reproducibility guarantee.
func TestMeasureProofsDeterministic(t *testing.T) {
	a, err := measureProofs(4096, 32, 7)
	if err != nil {
		t.Fatal(err)
	}
	b, err := measureProofs(4096, 32, 7)
	if err != nil {
		t.Fatal(err)
	}
	if a.InclusionSize != b.InclusionSize || a.ConsistencySize != b.ConsistencySize {
		t.Fatal("proof sizes not deterministic across identical seeds")
	}
}
