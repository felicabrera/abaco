package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"text/tabwriter"
)

// FormatDuration renders a nanosecond count with an adaptive unit, so that a
// table can mix sub-microsecond and multi-second values legibly.
func FormatDuration(ns float64) string {
	switch {
	case ns < 1e3:
		return fmt.Sprintf("%.0f ns", ns)
	case ns < 1e6:
		return fmt.Sprintf("%.2f µs", ns/1e3)
	case ns < 1e9:
		return fmt.Sprintf("%.2f ms", ns/1e6)
	default:
		return fmt.Sprintf("%.3f s", ns/1e9)
	}
}

// FormatBytes renders a byte count in binary (IEC) units.
func FormatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

// FormatCount renders an integer with thousands separators.
func FormatCount(n int64) string {
	s := strconv.FormatInt(n, 10)
	neg := ""
	if n < 0 {
		neg, s = "-", s[1:]
	}
	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	return neg + string(out)
}

// IsTTY reports whether w is a terminal, so colour is only emitted interactively
// and never into a pipe or file.
func IsTTY(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

type palette struct{ bold, dim, green, red, reset string }

func newPalette(color bool) palette {
	if !color {
		return palette{}
	}
	return palette{
		bold:  "\x1b[1m",
		dim:   "\x1b[2m",
		green: "\x1b[32m",
		red:   "\x1b[31m",
		reset: "\x1b[0m",
	}
}

// RenderEnvironment prints the citable environment block.
func RenderEnvironment(w io.Writer, r *Report) {
	p := newPalette(IsTTY(w))
	env := r.Environment
	fmt.Fprintf(w, "%sEnvironment%s\n", p.bold, p.reset)
	fmt.Fprintf(w, "  CPU: %s | Cores used: %d of %d\n", env.CPU, env.CoresUsed, env.NumCPU)
	fmt.Fprintf(w, "  RAM: %s | GOMEMLIMIT: %s | Peak heap: %s\n",
		FormatBytes(env.TotalRAMByte), env.GoMemLimit, peakHeapAcrossScales(r))
	fmt.Fprintf(w, "  Go: %s | OS/Arch: %s/%s | Group: %s\n",
		env.GoVersion, env.OS, env.Arch, r.Params.Group)
	fmt.Fprintf(w, "  Commit: %s | Seed: %d | Date: %s\n",
		env.Commit, r.Params.Seed, r.GeneratedAt)
	fmt.Fprintf(w, "  Instrument overhead (time.Now pair): %s\n", FormatDuration(r.InstrumentOverheadNanos))
}

func peakHeapAcrossScales(r *Report) string {
	var max uint64
	for _, s := range r.Scales {
		if s.PeakHeapBytes > max {
			max = s.PeakHeapBytes
		}
	}
	return FormatBytes(max)
}

// RenderScaleTable prints Table 1: one row per scale.
func RenderScaleTable(w io.Writer, r *Report) {
	p := newPalette(IsTTY(w))
	fmt.Fprintf(w, "\n%sTable 1 — Summary per scale%s\n", p.bold, p.reset)
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "Votes\tWall (median)\tCPU work\tBallots/s\tCiphertexts/s\tPeak heap\tCorrect")
	for _, s := range r.Scales {
		correct := p.green + "yes" + p.reset
		if !s.Correct {
			correct = p.red + "NO" + p.reset
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			FormatCount(int64(s.Votes)),
			FormatDuration(s.WallNanos.Median),
			FormatDuration(s.CPUNanos.Median),
			FormatCount(int64(s.BallotsPerSec)),
			FormatCount(int64(s.CiphertextsPerSec)),
			FormatBytes(s.PeakHeapBytes),
			correct,
		)
	}
	tw.Flush()
}

// RenderOpTables prints Table 2: the per-operation breakdown, one table per
// scale. This is the table that goes into the report.
func RenderOpTables(w io.Writer, r *Report) {
	p := newPalette(IsTTY(w))
	for _, s := range r.Scales {
		fmt.Fprintf(w, "\n%sTable 2 — Operation breakdown @ %s votes (%d candidates)%s\n",
			p.bold, FormatCount(int64(s.Votes)), s.Candidates, p.reset)
		tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "Operation\tCalls\tMedian\tMean\tp95\tTotal CPU\t% pipeline")
		for _, op := range s.Ops {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%.1f%%\n",
				op.Name,
				FormatCount(op.Calls),
				FormatDuration(op.MedianNanos),
				FormatDuration(op.MeanNanos),
				FormatDuration(op.P95Nanos),
				FormatDuration(op.TotalCPUNanos),
				op.PercentOfPipeline,
			)
		}
		tw.Flush()
	}
}

// RenderProofTables prints the audit-proof breakdown, one block per proof scale.
// It slots into the Table 2 family: the four proof operations with their latency
// distribution, plus the proof sizes — the headline being that both verify time
// and proof size stay ~log2(n) as the log grows.
func RenderProofTables(w io.Writer, r *Report) {
	p := newPalette(IsTTY(w))
	for _, pr := range r.ProofScales {
		fmt.Fprintf(w, "\n%sTable 2 — Audit proofs @ %s entries%s\n",
			p.bold, FormatCount(int64(pr.TreeSize)), p.reset)
		tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "Operation\tCalls\tMedian\tMean\tp95\tTotal CPU")
		for _, op := range pr.Ops {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
				op.Name,
				FormatCount(op.Calls),
				FormatDuration(op.MedianNanos),
				FormatDuration(op.MeanNanos),
				FormatDuration(op.P95Nanos),
				FormatDuration(op.TotalCPUNanos),
			)
		}
		tw.Flush()
		fmt.Fprintf(w, "  Inclusion proof:   %s   (log2 n = %.1f)\n",
			formatProofSize(pr.InclusionSize), pr.InclusionSize.Log2N)
		fmt.Fprintf(w, "  Consistency proof: %s   (log2 n = %.1f)\n",
			formatProofSize(pr.ConsistencySize), pr.ConsistencySize.Log2N)
	}
}

// formatProofSize renders a proof's hash count and byte size, noting the range
// across sampled leaves/splits when it varies.
func formatProofSize(s ProofSize) string {
	base := fmt.Sprintf("%d hashes / %s", s.Hashes, FormatBytes(uint64(s.Bytes)))
	if s.MinHashes != s.MaxHashes {
		return fmt.Sprintf("%s (%d–%d across samples)", base, s.MinHashes, s.MaxHashes)
	}
	return base
}

// WriteJSON writes the full report as indented JSON.
func WriteJSON(path string, r *Report) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// ReadJSON loads a report previously written by WriteJSON. It is the inverse of
// WriteJSON, used by tools (e.g. benchdiff) that compare two runs.
func ReadJSON(path string) (*Report, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r Report
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return &r, nil
}

// WriteCSV writes a flat per-(scale, operation) CSV, convenient for spreadsheets
// and plotting.
func WriteCSV(path string, r *Report) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	cw := csv.NewWriter(f)
	defer cw.Flush()

	header := []string{
		"votes", "candidates", "operation", "calls",
		"median_ns", "mean_ns", "p95_ns", "p99_ns", "min_ns", "max_ns", "stddev_ns",
		"total_cpu_ns", "percent_of_pipeline",
		"wall_median_ns", "cpu_work_median_ns", "ballots_per_sec", "ciphertexts_per_sec",
		"peak_heap_bytes", "correct",
	}
	if err := cw.Write(header); err != nil {
		return err
	}
	for _, s := range r.Scales {
		for _, op := range s.Ops {
			row := []string{
				strconv.Itoa(s.Votes), strconv.Itoa(s.Candidates), op.Name,
				strconv.FormatInt(op.Calls, 10),
				f2(op.MedianNanos), f2(op.MeanNanos), f2(op.P95Nanos), f2(op.P99Nanos),
				f2(op.MinNanos), f2(op.MaxNanos), f2(op.StdDevNanos),
				f2(op.TotalCPUNanos), f2(op.PercentOfPipeline),
				f2(s.WallNanos.Median), f2(s.CPUNanos.Median),
				f2(s.BallotsPerSec), f2(s.CiphertextsPerSec),
				strconv.FormatUint(s.PeakHeapBytes, 10),
				strconv.FormatBool(s.Correct),
			}
			if err := cw.Write(row); err != nil {
				return err
			}
		}
	}
	// Audit-proof operations. The scale-level pipeline columns do not apply, so
	// they are left blank; "votes" carries the proof tree size. Proof sizes live
	// in the JSON and table output, not the CSV, to keep the column shape stable.
	for _, pr := range r.ProofScales {
		for _, op := range pr.Ops {
			row := []string{
				strconv.Itoa(pr.TreeSize), "", op.Name,
				strconv.FormatInt(op.Calls, 10),
				f2(op.MedianNanos), f2(op.MeanNanos), f2(op.P95Nanos), f2(op.P99Nanos),
				f2(op.MinNanos), f2(op.MaxNanos), f2(op.StdDevNanos),
				f2(op.TotalCPUNanos), f2(op.PercentOfPipeline),
				"", "", "", "", "", "",
			}
			if err := cw.Write(row); err != nil {
				return err
			}
		}
	}
	return nil
}

func f2(v float64) string { return strconv.FormatFloat(v, 'f', 2, 64) }
