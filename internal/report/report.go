// Package report defines the versioned result model produced by a benchmark run
// and renders it as human-readable tables, JSON and CSV.
//
// The JSON schema is stable and self-contained: it records the environment, the
// exact parameters (including the random seed) and every per-operation statistic
// for every scale, so that a third party can reproduce and cite a run without
// any other artifact.
package report

import (
	"math"
	"sort"
)

// SchemaVersion is the version of the JSON result schema. Bump on any
// breaking change to the shape below.
//
// v2 adds the top-level "proof_scales" section (audit inclusion/consistency
// proof timings and sizes). It is purely additive: v1 consumers ignore the new
// field, and it is omitted entirely when no proof scales are measured.
const SchemaVersion = 2

// Report is the top-level result document.
type Report struct {
	SchemaVersion           int           `json:"schema_version"`
	Tool                    string        `json:"tool"`
	GeneratedAt             string        `json:"generated_at"`
	Environment             Environment   `json:"environment"`
	Params                  Params        `json:"params"`
	InstrumentOverheadNanos float64       `json:"instrument_overhead_nanos"`
	Scales                  []ScaleResult `json:"scales"`
	ProofScales             []ProofResult `json:"proof_scales,omitempty"`
}

// ProofResult holds the audit-proof measurements for one log size. Proofs
// (inclusion and consistency) are FARO's core auditing feature but are off the
// election hot path, so they are measured in a separate phase at their own
// scales and reported here rather than in the pipeline breakdown.
type ProofResult struct {
	TreeSize        int         `json:"tree_size"`
	Samples         int         `json:"samples"` // random leaves/splits sampled
	Ops             []OpSummary `json:"ops"`     // the four proof-op latency summaries
	InclusionSize   ProofSize   `json:"inclusion_size"`
	ConsistencySize ProofSize   `json:"consistency_size"`
}

// ProofSize records how large a proof is — the headline alongside verify time,
// since proofs are downloaded and checked on the verifier's own machine. Hashes
// is a representative path length; Min/Max bound it across the sampled
// leaves/splits. Bytes is Hashes*32. Log2N is ceil(log2 TreeSize), the O(log n)
// reference the measured sizes should track.
type ProofSize struct {
	Hashes    int     `json:"hashes"`
	MinHashes int     `json:"min_hashes"`
	MaxHashes int     `json:"max_hashes"`
	Bytes     int     `json:"bytes"`
	Log2N     float64 `json:"log2_n"`
}

// Environment captures where a run happened, for citation and reproducibility.
type Environment struct {
	CPU          string `json:"cpu"`
	NumCPU       int    `json:"num_cpu"`
	CoresUsed    int    `json:"cores_used"`
	TotalRAMByte uint64 `json:"total_ram_bytes"`
	GoVersion    string `json:"go_version"`
	OS           string `json:"os"`
	Arch         string `json:"arch"`
	Commit       string `json:"commit"`
	GoMemLimit   string `json:"go_mem_limit"`
}

// Params records the knobs a run was invoked with.
type Params struct {
	Group       string `json:"group"`
	Votes       []int  `json:"votes"`
	Candidates  int    `json:"candidates"`
	Authorities int    `json:"authorities"`
	Threshold   int    `json:"threshold"`
	Cores       int    `json:"cores"`
	MemLimit    string `json:"mem_limit"`
	Repeat      int    `json:"repeat"`
	Warmup      int    `json:"warmup"`
	Batch       int    `json:"batch"`
	Seed        uint64 `json:"seed"`
}

// ScaleResult holds every measurement for one scale (one --votes value).
type ScaleResult struct {
	Votes             int         `json:"votes"`
	Candidates        int         `json:"candidates"`
	Repeats           int         `json:"repeats"`
	Ciphertexts       int         `json:"ciphertexts"` // votes * candidates
	WallNanos         AggStat     `json:"wall_nanos"`
	CPUNanos          AggStat     `json:"cpu_work_nanos"`
	BallotsPerSec     float64     `json:"ballots_per_sec"`
	CiphertextsPerSec float64     `json:"ciphertexts_per_sec"`
	PeakHeapBytes     uint64      `json:"peak_heap_bytes"`
	PeakSysBytes      uint64      `json:"peak_sys_bytes"`
	Correct           bool        `json:"correct"`
	Ops               []OpSummary `json:"ops"`
}

// OpSummary is the distribution of one operation's per-call latency plus its
// share of total work, aggregated across all repeats of a scale.
type OpSummary struct {
	Name              string  `json:"name"`
	Calls             int64   `json:"calls"`
	MedianNanos       float64 `json:"median_nanos"`
	MeanNanos         float64 `json:"mean_nanos"`
	P95Nanos          float64 `json:"p95_nanos"`
	P99Nanos          float64 `json:"p99_nanos"`
	MinNanos          float64 `json:"min_nanos"`
	MaxNanos          float64 `json:"max_nanos"`
	StdDevNanos       float64 `json:"stddev_nanos"`
	TotalCPUNanos     float64 `json:"total_cpu_nanos"`
	PercentOfPipeline float64 `json:"percent_of_pipeline"`
}

// AggStat summarises a set of samples (e.g. the wall time over repeats).
type AggStat struct {
	Median float64 `json:"median"`
	Mean   float64 `json:"mean"`
	P95    float64 `json:"p95"`
	P99    float64 `json:"p99"`
	Min    float64 `json:"min"`
	Max    float64 `json:"max"`
	StdDev float64 `json:"stddev"`
}

// Summarize computes an AggStat from raw samples. The median is the headline
// statistic because it resists outliers (a stray page fault or scheduler hiccup
// skews the mean but not the median).
func Summarize(samples []float64) AggStat {
	if len(samples) == 0 {
		return AggStat{}
	}
	sorted := append([]float64(nil), samples...)
	sort.Float64s(sorted)

	var sum float64
	for _, v := range sorted {
		sum += v
	}
	mean := sum / float64(len(sorted))

	var sq float64
	for _, v := range sorted {
		d := v - mean
		sq += d * d
	}
	std := math.Sqrt(sq / float64(len(sorted)))

	return AggStat{
		Median: percentile(sorted, 50),
		Mean:   mean,
		P95:    percentile(sorted, 95),
		P99:    percentile(sorted, 99),
		Min:    sorted[0],
		Max:    sorted[len(sorted)-1],
		StdDev: std,
	}
}

// percentile returns the p-th percentile of a sorted slice using linear
// interpolation between closest ranks.
func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 1 {
		return sorted[0]
	}
	rank := (p / 100) * float64(len(sorted)-1)
	lo := int(math.Floor(rank))
	hi := int(math.Ceil(rank))
	if lo == hi {
		return sorted[lo]
	}
	frac := rank - float64(lo)
	return sorted[lo]*(1-frac) + sorted[hi]*frac
}

// Percentile is the exported form used by callers that already hold sorted data.
func Percentile(sorted []float64, p float64) float64 { return percentile(sorted, p) }
