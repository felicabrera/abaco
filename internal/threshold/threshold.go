// Package threshold implements (t, n) threshold decryption of exponential
// ElGamal via Shamir secret sharing (Shamir, "How to Share a Secret", CACM
// 1979) applied to the decryption key.
//
// The secret key x is shared among n authorities so that any t of them can
// jointly decrypt, but any t-1 learn nothing. Each authority i holds a share
// x_i = f(i) of a degree-(t-1) polynomial f with f(0) = x. To decrypt a
// ciphertext (A, B) the authorities publish partial decryptions D_i = x_i*A;
// Lagrange interpolation "in the exponent" recombines them into x*A, after which
// the plaintext point is B - x*A. No authority ever reconstructs x.
//
// This uses a trusted dealer (the polynomial is sampled in one place at setup).
// A dealerless variant (Pedersen, "A Threshold Cryptosystem without a Trusted
// Party", EUROCRYPT '91) removes that assumption; it is out of scope for a
// cost benchmark and would not change the per-operation timings measured here.
package threshold

import (
	"fmt"
	"io"

	"github.com/felicabrera/abaco/internal/group"
)

// Share is one authority's secret share x_i = f(i). Index is i (1-based; i=0 is
// the secret itself and is never handed out).
type Share struct {
	Index uint64
	Value group.Scalar
}

// PartialDecryption is D_i = x_i*A, an authority's contribution to decrypting a
// ciphertext with first component A.
type PartialDecryption struct {
	Index uint64
	D     group.Element
}

// Deal samples a fresh secret x and splits it into n shares with threshold t.
// It returns x (so the caller can form the public key Y = x*G) together with the
// shares. In a real deployment x would be discarded immediately after dealing.
func Deal(g group.Group, n, t int, rand io.Reader) (group.Scalar, []Share, error) {
	if t < 1 || t > n {
		return nil, nil, fmt.Errorf("threshold: need 1 <= t <= n, got t=%d n=%d", t, n)
	}
	x, err := g.RandomScalar(rand)
	if err != nil {
		return nil, nil, err
	}
	shares, err := SplitSecret(g, x, n, t, rand)
	if err != nil {
		return nil, nil, err
	}
	return x, shares, nil
}

// SplitSecret shares a given secret x into n shares with threshold t. The
// polynomial is f(z) = x + a_1 z + … + a_{t-1} z^{t-1} with random coefficients;
// share i is f(i).
func SplitSecret(g group.Group, x group.Scalar, n, t int, rand io.Reader) ([]Share, error) {
	if t < 1 || t > n {
		return nil, fmt.Errorf("threshold: need 1 <= t <= n, got t=%d n=%d", t, n)
	}
	// coeffs[0] is the secret; the remaining t-1 are random.
	coeffs := make([]group.Scalar, t)
	coeffs[0] = x
	for k := 1; k < t; k++ {
		c, err := g.RandomScalar(rand)
		if err != nil {
			return nil, err
		}
		coeffs[k] = c
	}

	shares := make([]Share, n)
	for idx := 1; idx <= n; idx++ {
		i := g.ScalarFromUint64(uint64(idx))
		// Horner evaluation: f(i) = ((…(c_{t-1})·i + c_{t-2})·i + …)·i + c_0.
		acc := coeffs[t-1]
		for k := t - 2; k >= 0; k-- {
			acc = acc.Mul(i).Add(coeffs[k])
		}
		shares[idx-1] = Share{Index: uint64(idx), Value: acc}
	}
	return shares, nil
}

// PartialDecrypt computes this authority's partial decryption D_i = x_i*A.
func (s Share) PartialDecrypt(A group.Element) PartialDecryption {
	return PartialDecryption{Index: s.Index, D: A.ScalarMul(s.Value)}
}

// lagrangeAtZero returns the Lagrange basis coefficient λ_i evaluated at 0 for
// the interpolation set `indices`:
//
//	λ_i = Π_{j≠i} (0 - j)/(i - j)
func lagrangeAtZero(g group.Group, indices []uint64, i uint64) group.Scalar {
	num := g.ScalarFromUint64(1)
	den := g.ScalarFromUint64(1)
	si := g.ScalarFromUint64(i)
	for _, j := range indices {
		if j == i {
			continue
		}
		sj := g.ScalarFromUint64(j)
		num = num.Mul(sj.Neg())   // × (0 - j)
		den = den.Mul(si.Sub(sj)) // × (i - j)
	}
	return num.Mul(den.Invert())
}

// Combine recombines t (or more) partial decryptions into x*A via Lagrange
// interpolation in the exponent:
//
//	Σ_i λ_i · D_i = Σ_i λ_i · x_i · A = f(0)·A = x·A
//
// The caller then recovers the plaintext point as B - Combine(...).
func Combine(g group.Group, partials []PartialDecryption) group.Element {
	indices := make([]uint64, len(partials))
	for k, p := range partials {
		indices[k] = p.Index
	}
	acc := g.Identity()
	for _, p := range partials {
		lambda := lagrangeAtZero(g, indices, p.Index)
		acc = acc.Add(p.D.ScalarMul(lambda))
	}
	return acc
}
