package bench

import (
	"testing"

	"github.com/felicabrera/abaco/internal/group"
)

func TestBSGSRecoversTally(t *testing.T) {
	g := group.NewRistretto255()
	for _, n := range []uint64{0, 1, 2, 100, 1000, 9999} {
		target := g.ScalarBaseMul(g.ScalarFromUint64(n))
		got, ok := BSGS(g, target, 10000)
		if !ok || got != n {
			t.Fatalf("BSGS(%d*G) = (%d, %v), want %d", n, got, ok, n)
		}
	}
}

// TestEndToEndTally runs a full small election and checks the decrypted tally
// matches the known vote distribution — the correctness gate the benchmark
// relies on at every scale.
func TestEndToEndTally(t *testing.T) {
	g := group.NewRistretto255()
	e, err := newElection(g, 42, 3, 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	const votes = 1000
	e.reservoirID = 0
	m := newMeter(0)
	acc, expected, root, err := e.runScale(votes, 128, 4, m, nil)
	if err != nil {
		t.Fatal(err)
	}
	tallies, err := e.finalizeTally(acc, votes, m)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkTally(votes, tallies, expected); err != nil {
		t.Fatal(err)
	}
	if len(root) != 32 {
		t.Fatalf("merkle root length = %d, want 32", len(root))
	}
	// Every candidate should have received some votes with a uniform draw.
	var sum uint64
	for _, v := range tallies {
		sum += v
	}
	if sum != votes {
		t.Fatalf("tallies sum to %d, want %d", sum, votes)
	}
}

// TestDeterministicAcrossCoreCounts checks that the seed fully determines the
// result: the same election tallied with different worker counts must produce
// identical per-candidate tallies and the identical Merkle head.
func TestDeterministicAcrossCoreCounts(t *testing.T) {
	g := group.NewRistretto255()
	run := func(cores int) ([]uint64, []byte) {
		e, err := newElection(g, 7, 4, 5, 3)
		if err != nil {
			t.Fatal(err)
		}
		e.reservoirID = 0
		m := newMeter(0)
		acc, _, root, err := e.runScale(500, 64, cores, m, nil)
		if err != nil {
			t.Fatal(err)
		}
		tallies, err := e.finalizeTally(acc, 500, m)
		if err != nil {
			t.Fatal(err)
		}
		return tallies, root
	}
	t1, r1 := run(1)
	t8, r8 := run(8)
	if len(t1) != len(t8) {
		t.Fatal("tally length differs across core counts")
	}
	for i := range t1 {
		if t1[i] != t8[i] {
			t.Fatalf("candidate %d: 1-core=%d, 8-core=%d (non-deterministic)", i, t1[i], t8[i])
		}
	}
	if string(r1) != string(r8) {
		t.Fatal("Merkle head differs across core counts (order not deterministic)")
	}
}

func TestRunSmoke(t *testing.T) {
	// The full Run entry point should complete and verify at small scales.
	rep, err := Run(Config{
		Group:       group.NewRistretto255(),
		Votes:       []int{200, 500},
		Candidates:  2,
		Authorities: 5,
		Threshold:   3,
		Cores:       2,
		Repeat:      2,
		Warmup:      10,
		Batch:       128,
		Seed:        123,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Scales) != 2 {
		t.Fatalf("got %d scales, want 2", len(rep.Scales))
	}
	for _, s := range rep.Scales {
		if !s.Correct {
			t.Fatalf("scale %d not marked correct", s.Votes)
		}
		if len(s.Ops) != int(numOps) {
			t.Fatalf("scale %d: got %d ops, want %d", s.Votes, len(s.Ops), numOps)
		}
		for _, op := range s.Ops {
			if op.Calls == 0 {
				t.Fatalf("scale %d op %s has zero calls", s.Votes, op.Name)
			}
		}
	}
}
