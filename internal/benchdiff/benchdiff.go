// Package benchdiff compares two ÁBACO benchmark reports and renders the
// commit-to-commit change of a small set of headline metrics as a GitHub-flavored
// markdown table, suitable for a CI job summary.
//
// It intentionally tracks only the citable headlines — the ballot-path medians
// (Encrypt, Prove/Verify ballot) and the audit-proof verify latencies and sizes —
// rather than every operation, so a reviewer can eyeball a regression at a glance.
package benchdiff

import (
	"fmt"
	"io"

	"github.com/felicabrera/abaco/internal/report"
)

// Kind selects how a metric's value is formatted.
type Kind int

const (
	// KindDuration is a latency in nanoseconds.
	KindDuration Kind = iota
	// KindBytes is a size in bytes.
	KindBytes
)

// trackedPipelineOps are the ballot-path operations diffed from scales[].ops,
// in pipeline order. Names must match internal/bench/ops.go exactly.
var trackedPipelineOps = []string{
	"Encrypt",
	"Prove ballot {0,1}",
	"Verify ballot {0,1}",
}

// trackedProofOps are the audit-proof operations diffed from proof_scales[].ops.
// Names must match internal/bench/proofs.go exactly.
var trackedProofOps = []string{
	"Inclusion verify",
	"Consistency verify",
}

// Row is one tracked metric compared between the baseline and the current run.
// All tracked metrics are "lower is better", so a positive delta is a regression.
type Row struct {
	Metric      string
	Scale       string
	Kind        Kind
	Baseline    float64
	Current     float64
	HasBaseline bool
}

// DeltaPct is the percentage change from baseline to current, or 0 when there is
// no comparable baseline.
func (r Row) DeltaPct() float64 {
	if !r.HasBaseline || r.Baseline == 0 {
		return 0
	}
	return (r.Current - r.Baseline) / r.Baseline * 100
}

// Result is the full comparison across every tracked metric present in the
// current report.
type Result struct {
	HasBaseline bool
	Rows        []Row
}

// Regressed reports whether any tracked metric got worse by more than
// thresholdPct versus the baseline. Improvements never count as regressions.
func (res Result) Regressed(thresholdPct float64) bool {
	for _, row := range res.Rows {
		if row.HasBaseline && row.DeltaPct() > thresholdPct {
			return true
		}
	}
	return false
}

// Compute diffs the tracked metrics of cur against old, matching by scale (votes
// for the pipeline, tree size for proofs). A nil old means this is the first
// tracked run: rows carry current values with no baseline. thresholdPct is not
// applied here; it is used by callers (Regressed, RenderMarkdown) for flagging.
func Compute(old, cur *report.Report, thresholdPct float64) Result {
	res := Result{HasBaseline: old != nil}
	if cur == nil {
		return res
	}

	// Pipeline medians, per shared vote scale.
	for _, sc := range cur.Scales {
		base := findScale(old, sc.Votes)
		scale := fmt.Sprintf("%s votes", report.FormatCount(int64(sc.Votes)))
		for _, name := range trackedPipelineOps {
			op := findOp(sc.Ops, name)
			if op == nil {
				continue
			}
			row := Row{Metric: name, Scale: scale, Kind: KindDuration, Current: op.MedianNanos}
			if base != nil {
				if bop := findOp(base.Ops, name); bop != nil {
					row.Baseline, row.HasBaseline = bop.MedianNanos, true
				}
			}
			res.Rows = append(res.Rows, row)
		}
	}

	// Audit-proof verify latencies and proof sizes, per shared tree size.
	for _, ps := range cur.ProofScales {
		base := findProofScale(old, ps.TreeSize)
		scale := fmt.Sprintf("%s entries", report.FormatCount(int64(ps.TreeSize)))
		for _, name := range trackedProofOps {
			op := findOp(ps.Ops, name)
			if op == nil {
				continue
			}
			row := Row{Metric: name, Scale: scale, Kind: KindDuration, Current: op.MedianNanos}
			if base != nil {
				if bop := findOp(base.Ops, name); bop != nil {
					row.Baseline, row.HasBaseline = bop.MedianNanos, true
				}
			}
			res.Rows = append(res.Rows, row)
		}
		inc := Row{Metric: "Inclusion proof size", Scale: scale, Kind: KindBytes, Current: float64(ps.InclusionSize.Bytes)}
		con := Row{Metric: "Consistency proof size", Scale: scale, Kind: KindBytes, Current: float64(ps.ConsistencySize.Bytes)}
		if base != nil {
			inc.Baseline, inc.HasBaseline = float64(base.InclusionSize.Bytes), true
			con.Baseline, con.HasBaseline = float64(base.ConsistencySize.Bytes), true
		}
		res.Rows = append(res.Rows, inc, con)
	}
	return res
}

// RenderMarkdown writes res as a GitHub-flavored markdown table. A ⚠️ marks a
// tracked metric that regressed past thresholdPct; a ✅ marks one that improved
// past it; a blank cell means within noise.
func RenderMarkdown(w io.Writer, res Result, thresholdPct float64) {
	if !res.HasBaseline {
		fmt.Fprintf(w, "_No baseline yet — recording these numbers as the first baseline._\n\n")
	}
	if len(res.Rows) == 0 {
		fmt.Fprintln(w, "_No tracked metrics found in this report._")
		return
	}
	fmt.Fprintln(w, "| Metric | Scale | Baseline | Current | Δ% | Status |")
	fmt.Fprintln(w, "|---|---|--:|--:|--:|:--|")
	for _, row := range res.Rows {
		fmt.Fprintf(w, "| %s | %s | %s | %s | %s | %s |\n",
			row.Metric, row.Scale,
			formatValue(row.Kind, row.Baseline, row.HasBaseline),
			formatValue(row.Kind, row.Current, true),
			formatDelta(row),
			status(row, thresholdPct),
		)
	}
}

func formatValue(kind Kind, v float64, present bool) string {
	if !present {
		return "—"
	}
	switch kind {
	case KindBytes:
		return report.FormatBytes(uint64(v))
	default:
		return report.FormatDuration(v)
	}
}

func formatDelta(row Row) string {
	if !row.HasBaseline {
		return "—"
	}
	return fmt.Sprintf("%+.1f%%", row.DeltaPct())
}

func status(row Row, thresholdPct float64) string {
	if !row.HasBaseline {
		return ""
	}
	switch d := row.DeltaPct(); {
	case d > thresholdPct:
		return "⚠️ regressed"
	case d < -thresholdPct:
		return "✅ improved"
	default:
		return ""
	}
}

func findScale(r *report.Report, votes int) *report.ScaleResult {
	if r == nil {
		return nil
	}
	for i := range r.Scales {
		if r.Scales[i].Votes == votes {
			return &r.Scales[i]
		}
	}
	return nil
}

func findProofScale(r *report.Report, treeSize int) *report.ProofResult {
	if r == nil {
		return nil
	}
	for i := range r.ProofScales {
		if r.ProofScales[i].TreeSize == treeSize {
			return &r.ProofScales[i]
		}
	}
	return nil
}

func findOp(ops []report.OpSummary, name string) *report.OpSummary {
	for i := range ops {
		if ops[i].Name == name {
			return &ops[i]
		}
	}
	return nil
}
