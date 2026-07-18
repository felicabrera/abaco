package group

import (
	"crypto/rand"
	"testing"
)

func TestGeneratorNotIdentity(t *testing.T) {
	g := NewRistretto255()
	if g.Generator().Equal(g.Identity()) {
		t.Fatal("generator must not be the identity")
	}
}

func TestScalarBaseMulMatchesScalarMul(t *testing.T) {
	g := NewRistretto255()
	s, err := g.RandomScalar(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if !g.ScalarBaseMul(s).Equal(g.Generator().ScalarMul(s)) {
		t.Fatal("s*G via ScalarBaseMul must equal s*G via ScalarMul")
	}
}

func TestScalarArithmeticIsHomomorphic(t *testing.T) {
	// (a+b)*G == a*G + b*G, the property the homomorphic tally relies on.
	g := NewRistretto255()
	a, _ := g.RandomScalar(rand.Reader)
	b, _ := g.RandomScalar(rand.Reader)

	left := g.ScalarBaseMul(a.Add(b))
	right := g.ScalarBaseMul(a).Add(g.ScalarBaseMul(b))
	if !left.Equal(right) {
		t.Fatal("(a+b)*G != a*G + b*G")
	}
}

func TestScalarFromUint64Adds(t *testing.T) {
	g := NewRistretto255()
	three := g.ScalarFromUint64(3)
	four := g.ScalarFromUint64(4)
	seven := g.ScalarFromUint64(7)
	if !three.Add(four).Equal(seven) {
		t.Fatal("3 + 4 != 7 in Z_q")
	}
	if !g.ScalarBaseMul(three.Add(four)).Equal(g.ScalarBaseMul(seven)) {
		t.Fatal("(3+4)*G != 7*G")
	}
}

func TestScalarInvert(t *testing.T) {
	g := NewRistretto255()
	s, _ := g.RandomScalar(rand.Reader)
	one := g.ScalarFromUint64(1)
	if !s.Mul(s.Invert()).Equal(one) {
		t.Fatal("s * s^-1 != 1")
	}
}

func TestScalarNegAndSub(t *testing.T) {
	g := NewRistretto255()
	a, _ := g.RandomScalar(rand.Reader)
	b, _ := g.RandomScalar(rand.Reader)
	if !a.Sub(b).Equal(a.Add(b.Neg())) {
		t.Fatal("a - b != a + (-b)")
	}
	if !a.Add(a.Neg()).IsZero() {
		t.Fatal("a + (-a) != 0")
	}
}

func TestElementEncodeDecodeRoundTrip(t *testing.T) {
	g := NewRistretto255()
	s, _ := g.RandomScalar(rand.Reader)
	p := g.ScalarBaseMul(s)
	back, err := g.ElementFromBytes(p.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !p.Equal(back) {
		t.Fatal("element did not survive encode/decode")
	}
}

func TestScalarEncodeDecodeRoundTrip(t *testing.T) {
	g := NewRistretto255()
	s, _ := g.RandomScalar(rand.Reader)
	back, err := g.ScalarFromCanonicalBytes(s.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !s.Equal(back) {
		t.Fatal("scalar did not survive encode/decode")
	}
}

func TestPointSubtraction(t *testing.T) {
	// (a*G) - (a*G) == identity, used when recovering mG = B - xA.
	g := NewRistretto255()
	a, _ := g.RandomScalar(rand.Reader)
	p := g.ScalarBaseMul(a)
	if !p.Sub(p).Equal(g.Identity()) {
		t.Fatal("P - P != identity")
	}
}
