package group

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/gtank/ristretto255"
)

// Ristretto255 is the default backend: the prime-order group of order
//
//	l = 2^252 + 27742317777372353535851937790883648493
//
// specified in RFC 9496. Every non-identity element is a generator, so there is
// no cofactor and no small-subgroup confinement to worry about — exactly the
// setting ElGamal and Chaum-Pedersen assume.
type Ristretto255 struct{}

// NewRistretto255 returns the default group backend.
func NewRistretto255() Group { return Ristretto255{} }

func (Ristretto255) Name() string { return "ristretto255" }

func (Ristretto255) Generator() Element {
	return rElement{ristretto255.NewGeneratorElement()}
}

func (Ristretto255) Identity() Element {
	return rElement{ristretto255.NewIdentityElement()}
}

func (Ristretto255) ScalarBaseMul(s Scalar) Element {
	return rElement{ristretto255.NewIdentityElement().ScalarBaseMult(scalarOf(s))}
}

func (Ristretto255) NewScalar() Scalar {
	return rScalar{ristretto255.NewScalar()}
}

func (Ristretto255) ScalarFromUint64(v uint64) Scalar {
	// Canonical scalar encoding is 32-byte little-endian; a uint64 fits in the
	// low 8 bytes and is always < l, hence canonical.
	var buf [32]byte
	binary.LittleEndian.PutUint64(buf[:8], v)
	s := ristretto255.NewScalar()
	if _, err := s.SetCanonicalBytes(buf[:]); err != nil {
		// Unreachable: any 32-byte little-endian value < l is canonical, and a
		// uint64 is always < l.
		panic(fmt.Sprintf("group: ScalarFromUint64(%d): %v", v, err))
	}
	return rScalar{s}
}

func (Ristretto255) RandomScalar(rand io.Reader) (Scalar, error) {
	// 64 uniform bytes reduced mod l yield a scalar with negligible bias
	// (RFC 9496 §4.4). This is the fresh ElGamal randomness r.
	var buf [64]byte
	if _, err := io.ReadFull(rand, buf[:]); err != nil {
		return nil, fmt.Errorf("group: reading randomness: %w", err)
	}
	s, err := ristretto255.NewScalar().SetUniformBytes(buf[:])
	if err != nil {
		return nil, fmt.Errorf("group: reducing randomness: %w", err)
	}
	return rScalar{s}, nil
}

func (Ristretto255) ScalarFromUniformBytes(b []byte) Scalar {
	if len(b) < 64 {
		panic(fmt.Sprintf("group: ScalarFromUniformBytes needs >=64 bytes, got %d", len(b)))
	}
	s, err := ristretto255.NewScalar().SetUniformBytes(b[:64])
	if err != nil {
		// Unreachable: length is exactly 64.
		panic("group: SetUniformBytes: " + err.Error())
	}
	return rScalar{s}
}

func (Ristretto255) ScalarFromCanonicalBytes(b []byte) (Scalar, error) {
	s := ristretto255.NewScalar()
	if _, err := s.SetCanonicalBytes(b); err != nil {
		return nil, fmt.Errorf("group: decoding scalar: %w", err)
	}
	return rScalar{s}, nil
}

func (Ristretto255) ElementFromBytes(b []byte) (Element, error) {
	e := ristretto255.NewIdentityElement()
	if _, err := e.SetCanonicalBytes(b); err != nil {
		return nil, fmt.Errorf("group: decoding element: %w", err)
	}
	return rElement{e}, nil
}

// --- Scalar wrapper ---

type rScalar struct{ s *ristretto255.Scalar }

func scalarOf(x Scalar) *ristretto255.Scalar {
	rs, ok := x.(rScalar)
	if !ok {
		panic(fmt.Sprintf("group: mixing scalar of type %T with ristretto255 backend", x))
	}
	return rs.s
}

func (a rScalar) Add(b Scalar) Scalar {
	return rScalar{ristretto255.NewScalar().Add(a.s, scalarOf(b))}
}
func (a rScalar) Sub(b Scalar) Scalar {
	return rScalar{ristretto255.NewScalar().Subtract(a.s, scalarOf(b))}
}
func (a rScalar) Mul(b Scalar) Scalar {
	return rScalar{ristretto255.NewScalar().Multiply(a.s, scalarOf(b))}
}
func (a rScalar) Neg() Scalar {
	return rScalar{ristretto255.NewScalar().Negate(a.s)}
}
func (a rScalar) Invert() Scalar {
	return rScalar{ristretto255.NewScalar().Invert(a.s)}
}
func (a rScalar) Equal(b Scalar) bool { return a.s.Equal(scalarOf(b)) == 1 }
func (a rScalar) IsZero() bool        { return a.s.Equal(ristretto255.NewScalar()) == 1 }
func (a rScalar) Bytes() []byte       { return a.s.Bytes() }

// --- Element wrapper ---

type rElement struct{ e *ristretto255.Element }

func elementOf(x Element) *ristretto255.Element {
	re, ok := x.(rElement)
	if !ok {
		panic(fmt.Sprintf("group: mixing element of type %T with ristretto255 backend", x))
	}
	return re.e
}

func (a rElement) Add(b Element) Element {
	return rElement{ristretto255.NewIdentityElement().Add(a.e, elementOf(b))}
}
func (a rElement) Sub(b Element) Element {
	return rElement{ristretto255.NewIdentityElement().Subtract(a.e, elementOf(b))}
}
func (a rElement) Neg() Element {
	return rElement{ristretto255.NewIdentityElement().Negate(a.e)}
}
func (a rElement) ScalarMul(s Scalar) Element {
	return rElement{ristretto255.NewIdentityElement().ScalarMult(scalarOf(s), a.e)}
}
func (a rElement) Equal(b Element) bool { return a.e.Equal(elementOf(b)) == 1 }
func (a rElement) Bytes() []byte        { return a.e.Bytes() }
