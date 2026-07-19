package benchdiff

import (
	"strings"
	"testing"

	"github.com/felicabrera/abaco/internal/report"
)

// makeReport builds a minimal report with one pipeline scale (Encrypt only) and
// one proof scale (Inclusion verify + sizes), so tests can dial the tracked
// values directly.
func makeReport(encryptNanos, inclVerifyNanos float64, inclBytes int) *report.Report {
	return &report.Report{
		Scales: []report.ScaleResult{{
			Votes: 1000,
			Ops:   []report.OpSummary{{Name: "Encrypt", MedianNanos: encryptNanos}},
		}},
		ProofScales: []report.ProofResult{{
			TreeSize:        100000,
			Ops:             []report.OpSummary{{Name: "Inclusion verify", MedianNanos: inclVerifyNanos}},
			InclusionSize:   report.ProofSize{Bytes: inclBytes},
			ConsistencySize: report.ProofSize{Bytes: inclBytes},
		}},
	}
}

func findRow(res Result, metric string) (Row, bool) {
	for _, r := range res.Rows {
		if r.Metric == metric {
			return r, true
		}
	}
	return Row{}, false
}

func TestComputeCleanRun(t *testing.T) {
	old := makeReport(1000, 2000, 544)
	cur := makeReport(1050, 2000, 544) // +5% Encrypt, within ±10%
	res := Compute(old, cur, 10)

	if !res.HasBaseline {
		t.Fatal("expected HasBaseline true")
	}
	row, ok := findRow(res, "Encrypt")
	if !ok {
		t.Fatal("Encrypt row missing")
	}
	if got := row.DeltaPct(); got < 4.9 || got > 5.1 {
		t.Fatalf("Encrypt delta = %.2f%%, want ~5%%", got)
	}
	if res.Regressed(10) {
		t.Fatal("a +5%% move must not count as a regression at ±10%%")
	}
}

func TestComputeRegression(t *testing.T) {
	old := makeReport(1000, 2000, 544)
	cur := makeReport(1200, 2000, 544) // +20% Encrypt
	res := Compute(old, cur, 10)

	if !res.Regressed(10) {
		t.Fatal("a +20%% median move must be flagged as a regression")
	}
	row, _ := findRow(res, "Encrypt")
	if s := status(row, 10); !strings.Contains(s, "regressed") {
		t.Fatalf("status = %q, want a regression marker", s)
	}
}

func TestComputeImprovement(t *testing.T) {
	old := makeReport(1000, 2000, 544)
	cur := makeReport(800, 2000, 544) // -20% Encrypt (faster)
	res := Compute(old, cur, 10)

	if res.Regressed(10) {
		t.Fatal("an improvement must not count as a regression")
	}
	row, _ := findRow(res, "Encrypt")
	if s := status(row, 10); !strings.Contains(s, "improved") {
		t.Fatalf("status = %q, want an improvement marker", s)
	}
}

func TestComputeFirstRun(t *testing.T) {
	cur := makeReport(1000, 2000, 544)
	res := Compute(nil, cur, 10)

	if res.HasBaseline {
		t.Fatal("expected HasBaseline false on first run")
	}
	if res.Regressed(10) {
		t.Fatal("first run cannot regress")
	}
	row, ok := findRow(res, "Encrypt")
	if !ok {
		t.Fatal("Encrypt row missing on first run")
	}
	if row.HasBaseline {
		t.Fatal("first-run row must not claim a baseline")
	}
	if row.Current != 1000 {
		t.Fatalf("Current = %v, want 1000", row.Current)
	}
}

func TestComputeTracksProofSizes(t *testing.T) {
	old := makeReport(1000, 2000, 544)
	cur := makeReport(1000, 2000, 576) // proof grew ~5.9%
	res := Compute(old, cur, 10)

	row, ok := findRow(res, "Inclusion proof size")
	if !ok {
		t.Fatal("Inclusion proof size row missing")
	}
	if row.Kind != KindBytes {
		t.Fatalf("proof size Kind = %v, want KindBytes", row.Kind)
	}
	if row.Baseline != 544 || row.Current != 576 {
		t.Fatalf("proof size baseline/current = %v/%v, want 544/576", row.Baseline, row.Current)
	}
}

func TestRenderMarkdownFirstRunNote(t *testing.T) {
	var b strings.Builder
	RenderMarkdown(&b, Compute(nil, makeReport(1000, 2000, 544), 10), 10)
	out := b.String()
	if !strings.Contains(out, "No baseline yet") {
		t.Fatalf("first-run markdown missing baseline note:\n%s", out)
	}
	if !strings.Contains(out, "| Encrypt |") {
		t.Fatalf("markdown missing Encrypt row:\n%s", out)
	}
}

func TestRenderMarkdownRegressionMarker(t *testing.T) {
	var b strings.Builder
	res := Compute(makeReport(1000, 2000, 544), makeReport(1200, 2000, 544), 10)
	RenderMarkdown(&b, res, 10)
	if out := b.String(); !strings.Contains(out, "⚠️") {
		t.Fatalf("regression markdown missing ⚠️ marker:\n%s", out)
	}
}
