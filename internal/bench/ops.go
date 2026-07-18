package bench

// Op identifies one measured operation of the pipeline. The order here is the
// order operations occur in the pipeline and the order they appear in the
// breakdown table.
type Op int

const (
	OpEncrypt Op = iota
	OpProveBallot
	OpVerifyBallot
	OpProveSum
	OpVerifySum
	OpHomomorphicAdd
	OpMerkleAppend
	OpPartialDecrypt
	OpLagrangeCombine
	OpBSGS
	numOps
)

// opNames are the human-readable labels used in tables and JSON.
var opNames = [numOps]string{
	OpEncrypt:         "Encrypt",
	OpProveBallot:     "Prove ballot {0,1}",
	OpVerifyBallot:    "Verify ballot {0,1}",
	OpProveSum:        "Prove 1-of-C",
	OpVerifySum:       "Verify 1-of-C",
	OpHomomorphicAdd:  "Homomorphic add",
	OpMerkleAppend:    "Merkle append",
	OpPartialDecrypt:  "Partial decrypt",
	OpLagrangeCombine: "Lagrange combine",
	OpBSGS:            "BSGS recover tally",
}

// Name returns the label for an operation.
func (o Op) Name() string { return opNames[o] }
