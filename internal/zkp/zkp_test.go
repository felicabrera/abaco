package zkp

import (
	"crypto/rand"
	"testing"

	"github.com/felicabrera/abaco/internal/elgamal"
	"github.com/felicabrera/abaco/internal/group"
)

func setup(t *testing.T) (group.Group, *elgamal.PublicKey) {
	t.Helper()
	g := group.NewRistretto255()
	_, pk, err := elgamal.GenerateKey(g, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return g, pk
}

func TestBallotProofValid(t *testing.T) {
	_, pk := setup(t)
	for _, b := range []uint64{0, 1} {
		ct, r, err := elgamal.EncryptRandom(pk, b, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		p, err := ProveBallot(pk, ct, b, r, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if !VerifyBallot(pk, ct, p) {
			t.Fatalf("valid proof for bit %d did not verify", b)
		}
	}
}

// TestBallotProofRejectsInvalidVote is the single most important test in the
// suite: a ciphertext encrypting an out-of-range value (m=2) must not have an
// accepting OR-proof, even when the prover knows the encryption randomness.
func TestBallotProofRejectsInvalidVote(t *testing.T) {
	g, pk := setup(t)
	r, _ := g.RandomScalar(rand.Reader)
	ct := elgamal.Encrypt(pk, 2, r) // an invalid ballot: votes "2"

	// The cheater tries to pass it off as a 0 and as a 1. Neither can verify.
	for _, claimed := range []uint64{0, 1} {
		p, err := ProveBallot(pk, ct, claimed, r, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if VerifyBallot(pk, ct, p) {
			t.Fatalf("forged proof for invalid vote (claimed=%d) was accepted", claimed)
		}
	}
}

func TestBallotProofRejectsTampering(t *testing.T) {
	g, pk := setup(t)
	ct, r, _ := elgamal.EncryptRandom(pk, 1, rand.Reader)
	p, _ := ProveBallot(pk, ct, 1, r, rand.Reader)

	// Flip one response scalar; the proof must no longer verify.
	tampered := &BallotProof{C0: p.C0, C1: p.C1, R0: p.R0.Add(g.ScalarFromUint64(1)), R1: p.R1}
	if VerifyBallot(pk, ct, tampered) {
		t.Fatal("tampered proof (R0+1) was accepted")
	}

	// Swapping the challenge shares must also fail.
	swapped := &BallotProof{C0: p.C1, C1: p.C0, R0: p.R0, R1: p.R1}
	if VerifyBallot(pk, ct, swapped) {
		t.Fatal("proof with swapped challenges was accepted")
	}
}

func TestBallotProofRejectsWrongCiphertext(t *testing.T) {
	// A valid proof for one ciphertext must not verify against a different one.
	_, pk := setup(t)
	ct1, r1, _ := elgamal.EncryptRandom(pk, 1, rand.Reader)
	ct2, _, _ := elgamal.EncryptRandom(pk, 0, rand.Reader)
	p, _ := ProveBallot(pk, ct1, 1, r1, rand.Reader)
	if VerifyBallot(pk, ct2, p) {
		t.Fatal("proof bound to ct1 verified against ct2")
	}
}

// buildBallot encrypts a 1-of-C selection and returns the aggregate ciphertext
// plus the summed randomness R (the witness for the 1-of-C proof).
func buildBallot(t *testing.T, g group.Group, pk *elgamal.PublicKey, selections []uint64) (*elgamal.Ciphertext, group.Scalar) {
	t.Helper()
	agg := elgamal.Identity(g)
	R := g.NewScalar()
	for _, v := range selections {
		ct, r, err := elgamal.EncryptRandom(pk, v, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		agg = elgamal.Add(agg, ct)
		R = R.Add(r)
	}
	return agg, R
}

func TestSumProofValid(t *testing.T) {
	g, pk := setup(t)
	// A legal ballot: exactly one candidate selected out of four.
	agg, R := buildBallot(t, g, pk, []uint64{0, 1, 0, 0})
	p, err := ProveSum(pk, agg, R, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifySum(pk, agg, p) {
		t.Fatal("valid 1-of-C proof did not verify")
	}
}

// TestSumProofRejectsDoubleVote ensures the ballot-validity proof rejects a
// ballot that selects two candidates (the per-ciphertext OR-proofs alone would
// not catch this, since each selection is a legal {0,1}).
func TestSumProofRejectsDoubleVote(t *testing.T) {
	g, pk := setup(t)
	agg, R := buildBallot(t, g, pk, []uint64{1, 1, 0, 0}) // sums to 2
	p, err := ProveSum(pk, agg, R, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if VerifySum(pk, agg, p) {
		t.Fatal("1-of-C proof accepted a ballot that selected two candidates")
	}
}

func TestSumProofRejectsEmptyBallot(t *testing.T) {
	g, pk := setup(t)
	agg, R := buildBallot(t, g, pk, []uint64{0, 0, 0, 0}) // sums to 0
	p, _ := ProveSum(pk, agg, R, rand.Reader)
	if VerifySum(pk, agg, p) {
		t.Fatal("1-of-C proof accepted an empty ballot")
	}
}

func TestSumProofRejectsTampering(t *testing.T) {
	g, pk := setup(t)
	agg, R := buildBallot(t, g, pk, []uint64{1, 0})
	p, _ := ProveSum(pk, agg, R, rand.Reader)
	tampered := &SumProof{C: p.C, S: p.S.Add(g.ScalarFromUint64(1))}
	if VerifySum(pk, agg, tampered) {
		t.Fatal("tampered 1-of-C proof was accepted")
	}
}
