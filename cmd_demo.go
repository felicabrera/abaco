package main

import (
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/felicabrera/abaco/internal/bench"
	"github.com/felicabrera/abaco/internal/elgamal"
	"github.com/felicabrera/abaco/internal/group"
	"github.com/felicabrera/abaco/internal/merkle"
	"github.com/felicabrera/abaco/internal/threshold"
	"github.com/felicabrera/abaco/internal/zkp"
)

func runDemo(args []string) {
	fs := flag.NewFlagSet("demo", flag.ExitOnError)
	candidates := fs.Int("candidates", 2, "candidate slots per ballot")
	authorities := fs.Int("authorities", 5, "number of decryption authorities (n)")
	thr := fs.Int("threshold", 3, "quorum needed to decrypt (t)")
	seedFlag := fs.Int64("seed", -1, "random seed (default: random, reported)")
	fs.Parse(args)

	C, n, t := *candidates, *authorities, *thr
	if t < 1 || t > n {
		fatalf("need 1 <= threshold <= authorities")
	}
	if C < 2 {
		fatalf("demo needs at least 2 candidates to illustrate 1-of-C")
	}
	seed := resolveSeed(*seedFlag)
	rd := bench.NewSeededReader(seed)
	g := group.NewRistretto255()

	fmt.Printf("ÁBACO demo — one ballot through the full verifiable pipeline\n")
	fmt.Printf("group=%s  candidates=%d  authorities=%d  threshold=%d  seed=%d\n\n",
		g.Name(), C, n, t, seed)

	// ---- 1. Key generation and threshold sharing ----
	head(1, "Key generation and threshold sharing")
	var x group.Scalar
	var shares []threshold.Share
	d := timeit(func() {
		var err error
		x, shares, err = threshold.Deal(g, n, t, rd)
		if err != nil {
			fatalf("dealing key: %v", err)
		}
	})
	pk := elgamal.PublicKeyFrom(g, x)
	fmt.Printf("  Public key  Y = xG : %s\n", trunc(pk.Y.Bytes()))
	for _, s := range shares {
		fmt.Printf("  Authority %d share x_%d : %s\n", s.Index, s.Index, trunc(s.Value.Bytes()))
	}
	fmt.Printf("  The secret x = f(0) is split across %d authorities; any %d can decrypt,\n", n, t)
	fmt.Printf("  but no single authority ever holds it.  %s\n\n", took(d))

	// ---- 2. The vote in the clear ----
	head(2, "The vote (in the clear)")
	sel := int(readU64(rd) % uint64(C))
	selVec := make([]int, C)
	selVec[sel] = 1
	fmt.Printf("  Voter selects candidate #%d  →  plaintext ballot %v\n\n", sel, selVec)

	// ---- 3. Encryption ----
	head(3, "Encryption (exponential ElGamal)")
	cts := make([]*elgamal.Ciphertext, C)
	rs := make([]group.Scalar, C)
	d = timeit(func() {
		for c := 0; c < C; c++ {
			v := uint64(0)
			if c == sel {
				v = 1
			}
			ct, r, err := elgamal.EncryptRandom(pk, v, rd)
			if err != nil {
				fatalf("encrypt: %v", err)
			}
			cts[c], rs[c] = ct, r
		}
	})
	fmt.Printf("  Ciphertext for slot #%d:\n", sel)
	fmt.Printf("    A = rG      : %s\n", trunc(cts[sel].A.Bytes()))
	fmt.Printf("    B = rY + mG : %s   %s\n\n", trunc(cts[sel].B.Bytes()), took(d))

	// ---- 3b. Semantic security (IND-CPA) ----
	head(0, "Semantic security: two encryptions of the same vote differ")
	a1, _, _ := elgamal.EncryptRandom(pk, 1, rd)
	a2, _, _ := elgamal.EncryptRandom(pk, 1, rd)
	fmt.Printf("  Enc(1) #1 · A : %s\n", trunc(a1.A.Bytes()))
	fmt.Printf("  Enc(1) #2 · A : %s\n", trunc(a2.A.Bytes()))
	fmt.Printf("  Same vote, different ciphertexts — fresh randomness r each time (IND-CPA).\n")
	fmt.Printf("  This is what lets FARO be public without revealing how anyone voted.\n\n")

	// ---- 4. Zero-knowledge proof of validity ----
	head(4, "Zero-knowledge proof: the ciphertext encrypts 0 or 1")
	var proof *zkp.BallotProof
	dp := timeit(func() {
		var err error
		proof, err = zkp.ProveBallot(pk, cts[sel], 1, rs[sel], rd)
		if err != nil {
			fatalf("prove: %v", err)
		}
	})
	fmt.Printf("  OR-proof (c0,c1,r0,r1):\n")
	fmt.Printf("    c0=%s c1=%s\n", trunc(proof.C0.Bytes()), trunc(proof.C1.Bytes()))
	fmt.Printf("    r0=%s r1=%s   %s\n", trunc(proof.R0.Bytes()), trunc(proof.R1.Bytes()), took(dp))
	var ok bool
	dv := timeit(func() { ok = zkp.VerifyBallot(pk, cts[sel], proof) })
	fmt.Printf("  Verify → %s   %s\n\n", okmark(ok), took(dv))

	// ---- 4b. An invalid vote is rejected ----
	head(0, "Soundness: an invalid vote (m=2) cannot be proven valid")
	rbad, _ := g.RandomScalar(rd)
	ctBad := elgamal.Encrypt(pk, 2, rbad)
	badProof, _ := zkp.ProveBallot(pk, ctBad, 1, rbad, rd) // cheater claims "1"
	badOK := zkp.VerifyBallot(pk, ctBad, badProof)
	fmt.Printf("  Encrypt m=2, forge a proof claiming it is 1, verify → %s\n", rejectmark(!badOK))
	fmt.Printf("  The proof genuinely constrains the vote; a benchmark of it is meaningful.\n\n")

	// ---- 5. 1-of-C ballot validity ----
	head(5, "Ballot validity: exactly one candidate selected (1-of-C)")
	agg := elgamal.Identity(g)
	R := g.NewScalar()
	for c := 0; c < C; c++ {
		agg = elgamal.Add(agg, cts[c])
		R = R.Add(rs[c])
	}
	var sumProof *zkp.SumProof
	ds := timeit(func() {
		var err error
		sumProof, err = zkp.ProveSum(pk, agg, R, rd)
		if err != nil {
			fatalf("prove sum: %v", err)
		}
	})
	sumOK := zkp.VerifySum(pk, agg, sumProof)
	fmt.Printf("  Aggregate of the %d slots proven to encrypt exactly 1 → %s   %s\n", C, okmark(sumOK), took(ds))

	// double vote rejected
	dv1, r1, _ := elgamal.EncryptRandom(pk, 1, rd)
	dv2, r2, _ := elgamal.EncryptRandom(pk, 1, rd)
	dAgg := elgamal.Add(dv1, dv2)
	dR := r1.Add(r2)
	dProof, _ := zkp.ProveSum(pk, dAgg, dR, rd)
	dOK := zkp.VerifySum(pk, dAgg, dProof)
	fmt.Printf("  A ballot selecting two candidates (sum=2) → %s\n\n", rejectmark(!dOK))

	// ---- 6. Homomorphic tally of several ballots ----
	head(6, "Homomorphic tally (adding encrypted votes)")
	const demoBallots = 8
	acc := make([]*elgamal.Ciphertext, C)
	for c := range acc {
		acc[c] = elgamal.Identity(g)
	}
	expected := make([]uint64, C)
	leaves := make([][]byte, 0, demoBallots)
	dh := timeit(func() {
		for b := 0; b < demoBallots; b++ {
			bsel := int(readU64(rd) % uint64(C))
			leaf := make([]byte, 0, C*64)
			for c := 0; c < C; c++ {
				v := uint64(0)
				if c == bsel {
					v = 1
				}
				ct, _, _ := elgamal.EncryptRandom(pk, v, rd)
				acc[c] = elgamal.Add(acc[c], ct)
				leaf = append(leaf, ct.A.Bytes()...)
				leaf = append(leaf, ct.B.Bytes()...)
			}
			expected[bsel]++
			leaves = append(leaves, leaf)
		}
	})
	fmt.Printf("  Added %d encrypted ballots into %d per-candidate accumulators\n", demoBallots, C)
	fmt.Printf("  without ever decrypting an individual vote.  %s\n\n", took(dh))

	// ---- 7. Merkle transparency log ----
	head(7, "Append-only Merkle log (RFC 6962)")
	tree := merkle.NewTree()
	fmt.Printf("  Root (empty tree)   : %s\n", trunc(tree.Root()))
	dm := timeit(func() {
		for _, leaf := range leaves {
			tree.Append(leaf)
		}
	})
	fmt.Printf("  Root after %d entries: %s   %s\n", demoBallots, trunc(tree.Root()), took(dm))
	leafHashes := make([][]byte, len(leaves))
	for i, l := range leaves {
		leafHashes[i] = merkle.LeafHash(l)
	}
	incl := merkle.InclusionProof(leafHashes, 0)
	inclOK := merkle.VerifyInclusion(0, len(leaves), leafHashes[0], tree.Root(), incl)
	fmt.Printf("  Inclusion proof for entry #0 (%d hashes) → %s\n\n", len(incl), okmark(inclOK))

	// ---- 8. Threshold decryption ----
	head(8, "Threshold decryption and tally recovery")
	// t-1 shares must fail.
	subPartials := make([]threshold.PartialDecryption, t-1)
	for k := 0; k < t-1; k++ {
		subPartials[k] = shares[k].PartialDecrypt(acc[0].A)
	}
	subPoint := acc[0].B.Sub(threshold.Combine(g, subPartials))
	truePoint := elgamal.PointFromCount(g, expected[0])
	fmt.Printf("  With t-1 = %d shares: recovered point %s tally → cannot decrypt %s\n",
		t-1, eqword(subPoint.Equal(truePoint)), rejectmark(!subPoint.Equal(truePoint)))

	// t shares succeed.
	tallies := make([]uint64, C)
	var dPart, dComb, dBsgs time.Duration
	for c := 0; c < C; c++ {
		partials := make([]threshold.PartialDecryption, t)
		dPart += timeit(func() {
			for k := 0; k < t; k++ {
				partials[k] = shares[k].PartialDecrypt(acc[c].A)
			}
		})
		var xA group.Element
		dComb += timeit(func() { xA = threshold.Combine(g, partials) })
		mPoint := acc[c].B.Sub(xA)
		var cnt uint64
		var found bool
		dBsgs += timeit(func() { cnt, found = bench.BSGS(g, mPoint, demoBallots) })
		if !found {
			fatalf("BSGS failed for candidate %d", c)
		}
		tallies[c] = cnt
	}
	fmt.Printf("  With t = %d shares: partial-decrypt %s · Lagrange %s · BSGS %s\n",
		t, dur(dPart), dur(dComb), dur(dBsgs))
	match := true
	for c := 0; c < C; c++ {
		if tallies[c] != expected[c] {
			match = false
		}
	}
	fmt.Printf("  Recovered tally: %v   (expected %v)  →  %s\n", tallies, expected, okmark(match))
	if !match {
		fatalf("CORRECTNESS FAILURE: decrypted tally does not match expected")
	}
	fmt.Printf("\nEverything checks out. The whole ballot flow above is what ÁBACO measures at scale.\n")
}

// --- small presentation helpers ---

func head(n int, title string) {
	if n == 0 {
		fmt.Printf("  · %s\n", title)
		return
	}
	fmt.Printf("[%d] %s\n", n, title)
}

func trunc(b []byte) string {
	const keep = 8
	if len(b) <= keep {
		return hex.EncodeToString(b)
	}
	return hex.EncodeToString(b[:keep]) + "…"
}

func timeit(fn func()) time.Duration {
	start := time.Now()
	fn()
	return time.Since(start)
}

func dur(d time.Duration) string {
	return fmtDurNs(d)
}

func took(d time.Duration) string { return "(" + fmtDurNs(d) + ")" }

func fmtDurNs(d time.Duration) string {
	ns := float64(d.Nanoseconds())
	switch {
	case ns < 1e3:
		return fmt.Sprintf("%.0f ns", ns)
	case ns < 1e6:
		return fmt.Sprintf("%.1f µs", ns/1e3)
	case ns < 1e9:
		return fmt.Sprintf("%.2f ms", ns/1e6)
	default:
		return fmt.Sprintf("%.2f s", ns/1e9)
	}
}

func okmark(ok bool) string {
	if ok {
		return "OK ✓"
	}
	return "FAILED ✗"
}

func rejectmark(rejected bool) string {
	if rejected {
		return "REJECTED ✓"
	}
	return "ACCEPTED ✗ (this is a bug!)"
}

func eqword(eq bool) string {
	if eq {
		return "=="
	}
	return "≠"
}

func readU64(r io.Reader) uint64 {
	var b [8]byte
	_, _ = io.ReadFull(r, b[:])
	return binary.LittleEndian.Uint64(b[:])
}
