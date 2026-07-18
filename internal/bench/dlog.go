package bench

import (
	"math"

	"github.com/felicabrera/abaco/internal/group"
)

// BSGS recovers the integer m in [0, maxN] from the point target = m*G using the
// baby-step/giant-step algorithm, in O(√maxN) time and space. This is how the
// homomorphic tally — which lives "in the exponent" — is read out after
// threshold decryption yields m*G.
//
// For maxN = 10,000,000 the table has ~3,163 entries: negligible. Building the
// table is included in the measured cost so the reported BSGS time reflects a
// standalone recovery.
func BSGS(g group.Group, target group.Element, maxN uint64) (uint64, bool) {
	m := uint64(math.Ceil(math.Sqrt(float64(maxN)))) + 1

	// Baby steps: table of j*G -> j for j in [0, m).
	table := make(map[string]uint64, m)
	cur := g.Identity()
	step := g.Generator()
	for j := uint64(0); j < m; j++ {
		table[string(cur.Bytes())] = j
		cur = cur.Add(step)
	}

	// Giant stride: -(m*G). We walk target - i*(m*G) and look each up.
	giant := g.ScalarBaseMul(g.ScalarFromUint64(m)).Neg()
	gamma := target
	for i := uint64(0); i <= m; i++ {
		if j, ok := table[string(gamma.Bytes())]; ok {
			v := i*m + j
			if v <= maxN {
				return v, true
			}
		}
		gamma = gamma.Add(giant)
	}
	return 0, false
}
