package elgamal

import (
	"crypto/rand"
	"testing"

	"github.com/felicabrera/abaco/internal/group"
)

func TestDecryptRoundTrip(t *testing.T) {
	g := group.NewRistretto255()
	sk, pk, err := GenerateKey(g, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []uint64{0, 1} {
		ct, _, err := EncryptRandom(pk, m, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		got := DecryptToPoint(sk, ct)
		want := PointFromCount(g, m)
		if !got.Equal(want) {
			t.Fatalf("Decrypt(Encrypt(%d)) did not recover %d*G", m, m)
		}
	}
}

func TestHomomorphicAddition(t *testing.T) {
	// Decrypt(Enc(a) + Enc(b)) == (a+b)*G for a batch of {0,1} votes.
	g := group.NewRistretto255()
	sk, pk, err := GenerateKey(g, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	votes := []uint64{1, 0, 1, 1, 0, 1, 0, 0, 1, 1}
	var sum uint64
	acc := Identity(g)
	for _, v := range votes {
		ct, _, err := EncryptRandom(pk, v, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		acc = Add(acc, ct)
		sum += v
	}
	if !DecryptToPoint(sk, acc).Equal(PointFromCount(g, sum)) {
		t.Fatalf("homomorphic tally did not decrypt to %d", sum)
	}
}

func TestINDCPAFreshRandomness(t *testing.T) {
	// Two encryptions of the SAME message must differ, because r is fresh each
	// time. This is the semantic-security property that lets FARO be public.
	g := group.NewRistretto255()
	_, pk, err := GenerateKey(g, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c1, _, _ := EncryptRandom(pk, 1, rand.Reader)
	c2, _, _ := EncryptRandom(pk, 1, rand.Reader)
	if c1.A.Equal(c2.A) || c1.B.Equal(c2.B) {
		t.Fatal("two encryptions of the same vote were identical: randomness not fresh")
	}
}

func TestEncryptWithFixedRandomnessIsDeterministic(t *testing.T) {
	// Given the same r, Encrypt is a pure function — needed for reproducibility.
	g := group.NewRistretto255()
	_, pk, err := GenerateKey(g, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := g.RandomScalar(rand.Reader)
	c1 := Encrypt(pk, 1, r)
	c2 := Encrypt(pk, 1, r)
	if !c1.A.Equal(c2.A) || !c1.B.Equal(c2.B) {
		t.Fatal("Encrypt with fixed r was not deterministic")
	}
}
