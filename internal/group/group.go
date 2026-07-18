// Package group abstracts the prime-order group and its scalar field used by
// every cryptographic primitive in ÁBACO (ElGamal, the Chaum-Pedersen sigma
// proofs, Shamir threshold decryption).
//
// Why an interface. ElGamal and Schnorr-style proofs need a group of *prime*
// order so that every non-identity element is a generator and there are no
// small-subgroup / cofactor pitfalls. ristretto255 (RFC 9496) provides exactly
// that on top of Curve25519. Hiding it behind an interface lets us drop in a
// second backend (e.g. NIST P-256) later and benchmark the two side by side,
// without touching the higher-level crypto. The P-256 backend, if added, must
// document that it relies on the deprecated crypto/elliptic.Curve methods
// (ScalarMult/Add, deprecated since Go 1.21).
//
// The interface is deliberately immutable-style: every operation returns a new
// value instead of mutating the receiver. This makes the higher-level code read
// like the mathematics ("B := r.Mul(...); ..."), at the cost of some allocation.
// For a benchmark whose headline result is *flat* memory under streaming, the
// garbage produced per ballot is collected between batches and does not grow
// with the number of votes.
package group

import "io"

// Scalar is an element of the scalar field Z_q, where q is the (prime) group
// order. All arithmetic is modulo q.
type Scalar interface {
	Add(Scalar) Scalar // (self + x) mod q
	Sub(Scalar) Scalar // (self - x) mod q
	Mul(Scalar) Scalar // (self * x) mod q
	Neg() Scalar       // (-self)  mod q
	Invert() Scalar    // self^-1  mod q (self must be non-zero)
	Equal(Scalar) bool
	IsZero() bool
	Bytes() []byte // canonical 32-byte little-endian encoding
}

// Element is an element of the prime-order group, written additively so that
// s*P is scalar multiplication and P+Q is the group operation.
type Element interface {
	Add(Element) Element      // self + Q
	Sub(Element) Element      // self - Q
	Neg() Element             // -self
	ScalarMul(Scalar) Element // s * self
	Equal(Element) bool
	Bytes() []byte // canonical 32-byte encoding
}

// Group bundles the group and its scalar field together with the constructors
// the rest of the code needs.
type Group interface {
	// Name identifies the backend, e.g. "ristretto255". Reported in output so a
	// measured number is unambiguous about which group produced it.
	Name() string

	// Generator returns the fixed base point G.
	Generator() Element
	// Identity returns the group identity (the "zero" point).
	Identity() Element
	// ScalarBaseMul returns s*G. Backends may implement this faster than the
	// generic ScalarMul on the generator.
	ScalarBaseMul(Scalar) Element

	// NewScalar returns the additive identity 0 of the scalar field.
	NewScalar() Scalar
	// ScalarFromUint64 lifts a small non-negative integer into Z_q. Used for
	// Shamir indices, Lagrange arithmetic and baby-step/giant-step tables.
	ScalarFromUint64(uint64) Scalar
	// RandomScalar samples a uniform scalar from rand. This is the fresh
	// randomness r that gives ElGamal its IND-CPA security, so rand must be a
	// cryptographically secure source (or a seeded CSPRNG for reproducibility).
	RandomScalar(rand io.Reader) (Scalar, error)
	// ScalarFromUniformBytes reduces >=64 uniformly-random bytes modulo q. This
	// is how a hash output becomes a Fiat-Shamir challenge without bias.
	ScalarFromUniformBytes([]byte) Scalar
	// ScalarFromCanonicalBytes decodes a 32-byte canonical scalar encoding.
	ScalarFromCanonicalBytes([]byte) (Scalar, error)

	// ElementFromBytes decodes a canonical element encoding.
	ElementFromBytes([]byte) (Element, error)
}
