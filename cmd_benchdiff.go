package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/felicabrera/abaco/internal/benchdiff"
	"github.com/felicabrera/abaco/internal/report"
)

// runBenchDiff compares two benchmark JSON files (as written by `bench --json`)
// and prints a markdown table of the tracked headline metrics to stdout, ready
// to append to a CI job summary. A missing/empty --old is the first-run case:
// current numbers are shown with no deltas and the command exits 0.
func runBenchDiff(args []string) {
	fs := flag.NewFlagSet("benchdiff", flag.ExitOnError)
	oldPath := fs.String("old", "", "baseline JSON (previous run); empty or missing = first run")
	newPath := fs.String("new", "", "current JSON (this run), required")
	threshold := fs.Float64("threshold", 10, "flag a metric that moves more than ±this percent")
	failOnRegression := fs.Bool("fail-on-regression", false, "exit non-zero if any tracked metric regressed past the threshold")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: abaco benchdiff --new cur.json [--old base.json] [--threshold 10] [--fail-on-regression]")
		fmt.Fprintln(os.Stderr, "Diffs the headline medians and audit-proof sizes of two benchmark runs.")
	}
	_ = fs.Parse(args)

	if *newPath == "" {
		fatalf("benchdiff: --new is required")
	}

	cur, err := report.ReadJSON(*newPath)
	if err != nil {
		fatalf("reading --new: %v", err)
	}

	// A missing baseline file is not an error: the first tracked run has nothing
	// to compare against. A present-but-unreadable file is a real error.
	var old *report.Report
	if *oldPath != "" {
		if _, statErr := os.Stat(*oldPath); statErr == nil {
			old, err = report.ReadJSON(*oldPath)
			if err != nil {
				fatalf("reading --old: %v", err)
			}
		}
	}

	res := benchdiff.Compute(old, cur, *threshold)
	benchdiff.RenderMarkdown(os.Stdout, res, *threshold)

	if *failOnRegression && res.Regressed(*threshold) {
		fatalf("benchdiff: a tracked metric regressed by more than %.0f%%", *threshold)
	}
}
