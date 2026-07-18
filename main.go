// Command abaco is a benchmark suite for the ÁGORA verifiable-voting core:
// homomorphic ElGamal encryption, Schnorr/Chaum-Pedersen zero-knowledge proofs,
// an RFC 6962 Merkle transparency log, and Shamir threshold decryption —
// measured at real election scale.
//
// It has three subcommands:
//
//	abaco demo    a step-by-step, human-readable walkthrough of one ballot
//	abaco bench   the measured pipeline across one or more vote scales
//	abaco env     the detected host environment, for citation
//
// ÁBACO is a measurement instrument, not a voting system. See the README for its
// non-goals and the methodology behind the numbers.
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "demo":
		runDemo(os.Args[2:])
	case "bench":
		runBench(os.Args[2:])
	case "env":
		runEnv(os.Args[2:])
	case "-h", "--help", "help":
		usage(os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "abaco: unknown command %q\n\n", os.Args[1])
		usage(os.Stderr)
		os.Exit(2)
	}
}

func usage(w *os.File) {
	fmt.Fprint(w, `ÁBACO — benchmark suite for verifiable-voting cryptography

Usage:
  abaco <command> [flags]

Commands:
  demo    Walk through the full cryptographic pipeline for a single ballot.
  bench   Run and measure the pipeline across vote scales.
  env     Print the detected host environment (for citation).

Run "abaco <command> -h" for the flags of each command.
`)
}

// fatalf prints a loud error and exits non-zero. Used for correctness failures,
// which must never be silent.
func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "abaco: "+format+"\n", args...)
	os.Exit(1)
}
