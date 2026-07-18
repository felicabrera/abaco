// Package zkp implements the non-interactive zero-knowledge proofs that make a
// homomorphic ballot verifiable without revealing how anyone voted.
//
// Two proofs are provided:
//
//  1. BallotProof — a disjunctive ("OR") proof that a single ciphertext encrypts
//     0 or 1, without revealing which. It is the CDS OR-composition (Cramer,
//     Damgård, Schoenmakers, "Proofs of Partial Knowledge…", CRYPTO '94) of two
//     Chaum-Pedersen equality-of-discrete-log sigma protocols (Chaum, Pedersen,
//     CRYPTO '92), made non-interactive with the Fiat-Shamir transform (Fiat,
//     Shamir, CRYPTO '86).
//
//  2. SumProof — a plain Chaum-Pedersen proof that the *aggregate* of a ballot's
//     ciphertexts encrypts exactly 1. Together with the per-ciphertext OR-proofs
//     (each value in {0,1}) this enforces the 1-of-C rule of a real ballot: a
//     voter selects exactly one of the C candidates.
//
// Soundness hygiene. The Fiat-Shamir challenge hashes a fixed domain separator
// together with the public key Y and the full ciphertext (A, B). Omitting the
// public key or ciphertext from the transcript is a classic mistake that breaks
// soundness / enables cross-context replay, so it is done explicitly here.
package zkp

import (
	"crypto/sha512"
	"fmt"
	"io"

	"github.com/felicabrera/abaco/internal/elgamal"
	"github.com/felicabrera/abaco/internal/group"
)

const (
	domainBallot = "ABACO/v1/ballot-proof"
	domainSum    = "ABACO/v1/sum-proof"
)

// fiatShamir derives a challenge scalar by hashing the domain separator followed
// by every transcript component. SHA-512 yields 64 bytes, which are reduced mod
// q (the group order) into a uniform, unbiased scalar.
func fiatShamir(g group.Group, domain string, parts ...[]byte) group.Scalar {
	h := sha512.New()
	h.Write([]byte(domain))
	for _, p := range parts {
		h.Write(p)
	}
	return g.ScalarFromUniformBytes(h.Sum(nil))
}

// BallotProof is a proof that a ciphertext (A, B) encrypts 0 or 1.
//
// It is the tuple (c0, c1, r0, r1): one challenge share and one response per
// branch of the OR. The verifier recomputes the commitments and accepts iff
// c0 + c1 equals the Fiat-Shamir challenge.
type BallotProof struct {
	C0, C1 group.Scalar
	R0, R1 group.Scalar
}

// ProveBallot produces an OR-proof that ct encrypts the bit b, using the
// encryption randomness r as the witness (ct must equal Encrypt(pk, b, r)).
//
// The real branch is b; the other branch is simulated. Following CDS: commit
// honestly on the real branch, pick challenge+response at random on the
// simulated branch, derive the overall challenge by Fiat-Shamir, then split it
// so the two challenge shares sum to it.
func ProveBallot(pk *elgamal.PublicKey, ct *elgamal.Ciphertext, b uint64, r group.Scalar, rand io.Reader) (*BallotProof, error) {
	if b != 0 && b != 1 {
		return nil, fmt.Errorf("zkp: ProveBallot: bit must be 0 or 1, got %d", b)
	}
	g := pk.G

	// Per-branch commitments, indexed by branch so the transcript ordering
	// (a0, b0, a1, b1) is independent of which branch is real.
	var aCom, bCom [2]group.Element
	var c, resp [2]group.Scalar

	real := b
	sim := 1 - b

	// Real branch: honest commitment a = w*G, b = w*Y.
	w, err := g.RandomScalar(rand)
	if err != nil {
		return nil, err
	}
	aCom[real] = g.ScalarBaseMul(w)
	bCom[real] = pk.Y.ScalarMul(w)

	// Simulated branch: pick c_sim, r_sim at random and solve for the
	// commitments so verification will pass for this branch by construction.
	cSim, err := g.RandomScalar(rand)
	if err != nil {
		return nil, err
	}
	rSim, err := g.RandomScalar(rand)
	if err != nil {
		return nil, err
	}
	c[sim] = cSim
	resp[sim] = rSim
	// a_sim = r_sim*G - c_sim*A
	aCom[sim] = g.ScalarBaseMul(rSim).Sub(ct.A.ScalarMul(cSim))
	// b_sim = r_sim*Y - c_sim*(B - sim*G)
	bCom[sim] = pk.Y.ScalarMul(rSim).Sub(shiftedB(g, ct, sim).ScalarMul(cSim))

	// Fiat-Shamir challenge over the full transcript.
	ch := fiatShamir(g, domainBallot,
		pk.Y.Bytes(), ct.A.Bytes(), ct.B.Bytes(),
		aCom[0].Bytes(), bCom[0].Bytes(), aCom[1].Bytes(), bCom[1].Bytes())

	// Split: the real branch's challenge is whatever makes the shares sum to ch.
	c[real] = ch.Sub(c[sim])
	// Real response r = w + c_real * witness.
	resp[real] = w.Add(c[real].Mul(r))

	return &BallotProof{C0: c[0], C1: c[1], R0: resp[0], R1: resp[1]}, nil
}

// VerifyBallot checks an OR-proof: it recomputes the four commitments from the
// responses and challenge shares, and accepts iff c0 + c1 equals the
// Fiat-Shamir challenge over those commitments.
func VerifyBallot(pk *elgamal.PublicKey, ct *elgamal.Ciphertext, p *BallotProof) bool {
	g := pk.G

	// a_j = r_j*G - c_j*A ; b_j = r_j*Y - c_j*(B - j*G)
	a0 := g.ScalarBaseMul(p.R0).Sub(ct.A.ScalarMul(p.C0))
	b0 := pk.Y.ScalarMul(p.R0).Sub(shiftedB(g, ct, 0).ScalarMul(p.C0))
	a1 := g.ScalarBaseMul(p.R1).Sub(ct.A.ScalarMul(p.C1))
	b1 := pk.Y.ScalarMul(p.R1).Sub(shiftedB(g, ct, 1).ScalarMul(p.C1))

	ch := fiatShamir(g, domainBallot,
		pk.Y.Bytes(), ct.A.Bytes(), ct.B.Bytes(),
		a0.Bytes(), b0.Bytes(), a1.Bytes(), b1.Bytes())

	return p.C0.Add(p.C1).Equal(ch)
}

// shiftedB returns B - j*G, the value that must equal r*Y in branch j.
func shiftedB(g group.Group, ct *elgamal.Ciphertext, j uint64) group.Element {
	if j == 0 {
		return ct.B
	}
	return ct.B.Sub(g.ScalarBaseMul(g.ScalarFromUint64(j)))
}

// SumProof is a Chaum-Pedersen proof that an aggregate ciphertext encrypts
// exactly 1: it proves knowledge of R with A = R*G and (B - G) = R*Y.
type SumProof struct {
	C group.Scalar // Fiat-Shamir challenge
	S group.Scalar // response w + c*R
}

// ProveSum proves that agg (the homomorphic sum of a ballot's C ciphertexts)
// encrypts exactly 1. The witness R is the sum of the per-ciphertext encryption
// randomness, since Add of ciphertexts adds their randomness.
func ProveSum(pk *elgamal.PublicKey, agg *elgamal.Ciphertext, R group.Scalar, rand io.Reader) (*SumProof, error) {
	g := pk.G
	w, err := g.RandomScalar(rand)
	if err != nil {
		return nil, err
	}
	t1 := g.ScalarBaseMul(w) // commitment for A = R*G
	t2 := pk.Y.ScalarMul(w)  // commitment for (B - G) = R*Y

	c := fiatShamir(g, domainSum,
		pk.Y.Bytes(), agg.A.Bytes(), agg.B.Bytes(), t1.Bytes(), t2.Bytes())
	s := w.Add(c.Mul(R))
	return &SumProof{C: c, S: s}, nil
}

// VerifySum checks a 1-of-C aggregate proof.
func VerifySum(pk *elgamal.PublicKey, agg *elgamal.Ciphertext, p *SumProof) bool {
	g := pk.G
	// t1' = s*G - c*A
	t1 := g.ScalarBaseMul(p.S).Sub(agg.A.ScalarMul(p.C))
	// t2' = s*Y - c*(B - G)
	bMinusG := agg.B.Sub(g.Generator())
	t2 := pk.Y.ScalarMul(p.S).Sub(bMinusG.ScalarMul(p.C))

	c := fiatShamir(g, domainSum,
		pk.Y.Bytes(), agg.A.Bytes(), agg.B.Bytes(), t1.Bytes(), t2.Bytes())
	return p.C.Equal(c)
}
