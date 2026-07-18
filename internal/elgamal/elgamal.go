// Package elgamal implements exponential (additively-homomorphic) ElGamal over
// an abstract prime-order group.
//
// This is the encryption scheme at the heart of homomorphic verifiable voting
// (Cramer, Gennaro, Schoenmakers, "A Secure and Optimally Efficient
// Multi-Authority Election Scheme", EUROCRYPT '97, building on ElGamal, IEEE
// Trans. Inf. Theory 1985). A vote m is encoded as m*G in the exponent, so that
// the group operation on ciphertexts adds the plaintexts. Because the tally
// lives "in the exponent", recovering it requires solving a small discrete log
// (see internal/bench, baby-step/giant-step); that is cheap because the tally
// is bounded by the number of votes.
package elgamal

import (
	"io"

	"github.com/felicabrera/abaco/internal/group"
)

// PublicKey is Y = x*G, where x is the (jointly held) secret key.
type PublicKey struct {
	G group.Group
	Y group.Element
}

// SecretKey is the scalar x with Y = x*G. In production x is never reconstructed
// in one place; see internal/threshold. It exists here for the single-authority
// demo path and for tests.
type SecretKey struct {
	G group.Group
	X group.Scalar
}

// Ciphertext is the pair (A, B) with A = r*G and B = r*Y + m*G.
type Ciphertext struct {
	A group.Element
	B group.Element
}

// GenerateKey samples a fresh key pair (x, Y=x*G).
func GenerateKey(g group.Group, rand io.Reader) (*SecretKey, *PublicKey, error) {
	x, err := g.RandomScalar(rand)
	if err != nil {
		return nil, nil, err
	}
	return &SecretKey{G: g, X: x}, &PublicKey{G: g, Y: g.ScalarBaseMul(x)}, nil
}

// PublicKeyFrom builds the public key that corresponds to a known secret x.
func PublicKeyFrom(g group.Group, x group.Scalar) *PublicKey {
	return &PublicKey{G: g, Y: g.ScalarBaseMul(x)}
}

// Encrypt encrypts the message m (an integer encoded as m*G) under pk using the
// supplied randomness r. Separating r out lets the caller reuse it as the ZKP
// witness. Callers that do not need the witness should use EncryptRandom.
//
//	A = r*G
//	B = r*Y + m*G
func Encrypt(pk *PublicKey, m uint64, r group.Scalar) *Ciphertext {
	g := pk.G
	A := g.ScalarBaseMul(r)
	B := pk.Y.ScalarMul(r).Add(g.ScalarBaseMul(g.ScalarFromUint64(m)))
	return &Ciphertext{A: A, B: B}
}

// EncryptRandom samples fresh randomness r and returns both the ciphertext and
// r. The freshness of r on every call is exactly what gives the scheme its
// semantic (IND-CPA) security: two encryptions of the same vote are
// indistinguishable, which is what allows the transparency log FARO to be public
// without leaking how anyone voted. The `abaco demo` command demonstrates this
// explicitly.
func EncryptRandom(pk *PublicKey, m uint64, rand io.Reader) (*Ciphertext, group.Scalar, error) {
	r, err := pk.G.RandomScalar(rand)
	if err != nil {
		return nil, nil, err
	}
	return Encrypt(pk, m, r), r, nil
}

// Add returns the homomorphic sum of two ciphertexts: (A1+A2, B1+B2), which
// decrypts to m1+m2. This is the aggregation step of the tally.
func Add(c1, c2 *Ciphertext) *Ciphertext {
	return &Ciphertext{
		A: c1.A.Add(c2.A),
		B: c1.B.Add(c2.B),
	}
}

// Identity returns the encryption-of-zero neutral element (A=0, B=0), the
// correct accumulator to start a homomorphic sum from.
func Identity(g group.Group) *Ciphertext {
	return &Ciphertext{A: g.Identity(), B: g.Identity()}
}

// DecryptToPoint performs the algebraic part of decryption and returns m*G:
//
//	m*G = B - x*A
//
// Recovering the integer m from m*G is a separate, bounded discrete-log step
// done by the caller (baby-step/giant-step), so that it can be measured on its
// own.
func DecryptToPoint(sk *SecretKey, c *Ciphertext) group.Element {
	return c.B.Sub(c.A.ScalarMul(sk.X))
}

// PointFromCount returns count*G, the expected decryption point for a known
// tally. Used to verify a recovered tally and as the target for discrete-log
// search.
func PointFromCount(g group.Group, count uint64) group.Element {
	return g.ScalarBaseMul(g.ScalarFromUint64(count))
}
