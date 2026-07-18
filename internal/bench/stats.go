package bench

import (
	"math"
	"math/rand"
	"sort"
	"time"

	"github.com/felicabrera/abaco/internal/report"
)

// reservoirSize bounds how many latency samples we keep per operation. Exact
// count, sum and sum-of-squares are tracked in O(1), giving exact call counts,
// totals, means and standard deviations at any scale. Percentiles (median, p95,
// p99) are estimated from a uniform reservoir sample (Vitter's Algorithm R),
// which keeps memory flat even at 10M votes — the whole point of the streaming
// design. 8192 samples is ample for stable quantile estimates.
const reservoirSize = 8192

// opStats accumulates the latency distribution of a single operation. It is not
// safe for concurrent use; each worker keeps its own and they are merged.
type opStats struct {
	count     int64
	sumNanos  float64
	sumSqNs   float64
	min       int64
	max       int64
	reservoir []int64
	seen      int64
	rng       *rand.Rand
}

func newOpStats(seed int64) *opStats {
	return &opStats{min: -1, rng: rand.New(rand.NewSource(seed))}
}

// record adds one latency observation.
func (s *opStats) record(d time.Duration) {
	n := int64(d)
	s.count++
	fn := float64(n)
	s.sumNanos += fn
	s.sumSqNs += fn * fn
	if s.min < 0 || n < s.min {
		s.min = n
	}
	if n > s.max {
		s.max = n
	}
	s.seen++
	if len(s.reservoir) < reservoirSize {
		s.reservoir = append(s.reservoir, n)
	} else {
		// Replace a random element with probability reservoirSize/seen.
		j := s.rng.Int63n(s.seen)
		if j < reservoirSize {
			s.reservoir[j] = n
		}
	}
}

// merge folds another opStats (e.g. a worker's) into s.
func (s *opStats) merge(o *opStats) {
	if o.count == 0 {
		return
	}
	s.count += o.count
	s.sumNanos += o.sumNanos
	s.sumSqNs += o.sumSqNs
	if o.min >= 0 && (s.min < 0 || o.min < s.min) {
		s.min = o.min
	}
	if o.max > s.max {
		s.max = o.max
	}
	// Merge reservoirs by streaming the other's samples through Algorithm R so
	// the combined reservoir stays uniform over everything seen.
	for _, v := range o.reservoir {
		s.seen++
		if len(s.reservoir) < reservoirSize {
			s.reservoir = append(s.reservoir, v)
		} else {
			j := s.rng.Int63n(s.seen)
			if j < reservoirSize {
				s.reservoir[j] = v
			}
		}
	}
}

// Meter is the full set of per-operation accumulators for one pipeline run.
type Meter [numOps]*opStats

// newMeter builds a Meter with per-op reservoirs seeded deterministically from
// base so that runs are reproducible.
func newMeter(base int64) *Meter {
	var m Meter
	for i := range m {
		m[i] = newOpStats(base + int64(i))
	}
	return &m
}

// time measures fn and records its duration under op. It returns fn's result so
// callers can keep the measurement inline. The two time.Now calls are the
// instrument overhead measured separately by measureInstrumentOverhead.
func (m *Meter) time(op Op, fn func()) {
	start := time.Now()
	fn()
	m[op].record(time.Since(start))
}

func (m *Meter) merge(o *Meter) {
	for i := range m {
		m[i].merge(o[i])
	}
}

// summaries converts the meter into report.OpSummary values. totalCPU is the sum
// of every operation's total time, used for the "% of pipeline" column.
func (m *Meter) summaries() []report.OpSummary {
	var totalCPU float64
	for _, s := range m {
		totalCPU += s.sumNanos
	}
	out := make([]report.OpSummary, 0, numOps)
	for i, s := range m {
		if s.count == 0 {
			continue
		}
		mean := s.sumNanos / float64(s.count)
		variance := s.sumSqNs/float64(s.count) - mean*mean
		if variance < 0 {
			variance = 0
		}
		res := append([]int64(nil), s.reservoir...)
		sort.Slice(res, func(a, b int) bool { return res[a] < res[b] })
		pct := 0.0
		if totalCPU > 0 {
			pct = 100 * s.sumNanos / totalCPU
		}
		out = append(out, report.OpSummary{
			Name:              Op(i).Name(),
			Calls:             s.count,
			MedianNanos:       quantile(res, 50),
			MeanNanos:         mean,
			P95Nanos:          quantile(res, 95),
			P99Nanos:          quantile(res, 99),
			MinNanos:          float64(maxZero(s.min)),
			MaxNanos:          float64(s.max),
			StdDevNanos:       math.Sqrt(variance),
			TotalCPUNanos:     s.sumNanos,
			PercentOfPipeline: pct,
		})
	}
	return out
}

// totalCPUNanos is the aggregate measured work across all operations, used as
// the "CPU work" figure that is ~cores× the wall time under parallelism.
func (m *Meter) totalCPUNanos() float64 {
	var t float64
	for _, s := range m {
		t += s.sumNanos
	}
	return t
}

func quantile(sortedNs []int64, p float64) float64 {
	if len(sortedNs) == 0 {
		return 0
	}
	f := make([]float64, len(sortedNs))
	for i, v := range sortedNs {
		f[i] = float64(v)
	}
	return report.Percentile(f, p)
}

func maxZero(v int64) int64 {
	if v < 0 {
		return 0
	}
	return v
}
