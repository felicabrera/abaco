package threshold

import (
	"crypto/rand"
	"testing"

	"github.com/felicabrera/abaco/internal/elgamal"
	"github.com/felicabrera/abaco/internal/group"
)

// decryptWith recombines the given shares against ciphertext ct and returns the
// recovered plaintext point B - x*A.
func decryptWith(g group.Group, shares []Share, ct *elgamal.Ciphertext) group.Element {
	partials := make([]PartialDecryption, len(shares))
	for k, s := range shares {
		partials[k] = s.PartialDecrypt(ct.A)
	}
	xA := Combine(g, partials)
	return ct.B.Sub(xA)
}

func TestThresholdDecryptsWithQuorum(t *testing.T) {
	g := group.NewRistretto255()
	const n, thresh = 5, 3

	x, shares, err := Deal(g, n, thresh, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pk := elgamal.PublicKeyFrom(g, x)

	// Encrypt m=1 and recover it through a quorum of authorities.
	ct, _, err := elgamal.EncryptRandom(pk, 1, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	got := decryptWith(g, shares[:thresh], ct)
	want := elgamal.PointFromCount(g, 1)
	if !got.Equal(want) {
		t.Fatal("quorum of t shares failed to decrypt")
	}
}

func TestThresholdAnyQuorumAgrees(t *testing.T) {
	g := group.NewRistretto255()
	const n, thresh = 5, 3
	x, shares, _ := Deal(g, n, thresh, rand.Reader)
	pk := elgamal.PublicKeyFrom(g, x)
	ct, _, _ := elgamal.EncryptRandom(pk, 1, rand.Reader)

	// Two different quorums must recover the same plaintext point.
	a := decryptWith(g, []Share{shares[0], shares[1], shares[2]}, ct)
	b := decryptWith(g, []Share{shares[1], shares[3], shares[4]}, ct)
	if !a.Equal(b) {
		t.Fatal("different quorums disagreed on the decryption")
	}
	if !a.Equal(elgamal.PointFromCount(g, 1)) {
		t.Fatal("quorum decrypted to the wrong value")
	}
}

// TestSubThresholdCannotDecrypt is the safety property: t-1 shares must not
// recover the plaintext.
func TestSubThresholdCannotDecrypt(t *testing.T) {
	g := group.NewRistretto255()
	const n, thresh = 5, 3
	x, shares, _ := Deal(g, n, thresh, rand.Reader)
	pk := elgamal.PublicKeyFrom(g, x)
	ct, _, _ := elgamal.EncryptRandom(pk, 1, rand.Reader)

	got := decryptWith(g, shares[:thresh-1], ct) // only t-1 shares
	if got.Equal(elgamal.PointFromCount(g, 1)) {
		t.Fatal("t-1 shares recovered the plaintext: threshold is broken")
	}
}

func TestCombineRecoversKeyTimesA(t *testing.T) {
	// Combine of a quorum must equal x*A exactly.
	g := group.NewRistretto255()
	const n, thresh = 7, 4
	x, shares, _ := Deal(g, n, thresh, rand.Reader)

	a, _ := g.RandomScalar(rand.Reader)
	A := g.ScalarBaseMul(a)

	partials := make([]PartialDecryption, thresh)
	for k := 0; k < thresh; k++ {
		partials[k] = shares[k].PartialDecrypt(A)
	}
	if !Combine(g, partials).Equal(A.ScalarMul(x)) {
		t.Fatal("Lagrange recombination did not yield x*A")
	}
}
