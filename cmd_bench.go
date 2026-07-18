package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/felicabrera/abaco/internal/bench"
	"github.com/felicabrera/abaco/internal/group"
	"github.com/felicabrera/abaco/internal/report"
)

func runBench(args []string) {
	fs := flag.NewFlagSet("bench", flag.ExitOnError)
	votes := fs.String("votes", "1000,10000,100000", "comma-separated vote scales")
	candidates := fs.Int("candidates", 2, "candidate slots per ballot (ciphertexts+ZKPs per vote)")
	authorities := fs.Int("authorities", 5, "number of decryption authorities (n in Shamir)")
	threshold := fs.Int("threshold", 3, "quorum needed to decrypt (t in Shamir)")
	cores := fs.Int("cores", 0, "limit worker cores (0 = all)")
	mem := fs.String("mem", "", "soft memory limit, e.g. 1GiB, 512MiB (GOMEMLIMIT; see README)")
	repeat := fs.Int("repeat", 3, "repetitions per scale for statistics")
	warmup := fs.Int("warmup", 100, "warmup ballots before timing")
	seedFlag := fs.Int64("seed", -1, "random seed (default: random, always reported)")
	jsonPath := fs.String("json", "", "write full results to this JSON file")
	csvPath := fs.String("csv", "", "write per-operation results to this CSV file")
	batch := fs.Int("batch", 1000, "pipeline batch size")
	verbose := fs.Bool("verbose", false, "show live progress")
	fs.Parse(args)

	votesList, err := parseIntList(*votes)
	if err != nil {
		fatalf("--votes: %v", err)
	}
	memBytes, memLabel, err := parseSize(*mem)
	if err != nil {
		fatalf("--mem: %v", err)
	}
	seed := resolveSeed(*seedFlag)

	// Draw the live progress line on stderr when it is a terminal, or whenever
	// --verbose is set. Never into a redirected stream.
	var progress *os.File
	if *verbose || report.IsTTY(os.Stderr) {
		progress = os.Stderr
	}

	cfg := bench.Config{
		Group:         group.NewRistretto255(),
		Votes:         votesList,
		Candidates:    *candidates,
		Authorities:   *authorities,
		Threshold:     *threshold,
		Cores:         *cores,
		MemLimitBytes: memBytes,
		MemLimitLabel: memLabel,
		Repeat:        *repeat,
		Warmup:        *warmup,
		Batch:         *batch,
		Seed:          seed,
		Verbose:       *verbose,
	}
	if progress != nil {
		cfg.Progress = progress
	}

	rep, err := bench.Run(cfg)
	if err != nil {
		// Correctness failures and setup errors land here and must be loud.
		fatalf("%v", err)
	}

	report.RenderEnvironment(os.Stdout, rep)
	report.RenderScaleTable(os.Stdout, rep)
	report.RenderOpTables(os.Stdout, rep)

	if *jsonPath != "" {
		if err := report.WriteJSON(*jsonPath, rep); err != nil {
			fatalf("writing JSON: %v", err)
		}
		fmt.Printf("\nWrote JSON results to %s\n", *jsonPath)
	}
	if *csvPath != "" {
		if err := report.WriteCSV(*csvPath, rep); err != nil {
			fatalf("writing CSV: %v", err)
		}
		fmt.Printf("Wrote CSV results to %s\n", *csvPath)
	}
}
