package bench

import (
	"fmt"
	"io"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/felicabrera/abaco/internal/group"
	"github.com/felicabrera/abaco/internal/report"
)

// Config is a fully-resolved benchmark request (the CLI parses flags into this).
type Config struct {
	Group         group.Group
	Votes         []int
	Candidates    int
	Authorities   int
	Threshold     int
	Cores         int   // 0 = all available
	MemLimitBytes int64 // 0 = no soft limit
	MemLimitLabel string
	Repeat        int
	Warmup        int
	Batch         int
	Seed          uint64
	Verbose       bool
	Progress      io.Writer // where to draw the live progress line; nil = silent

	// Audit-proof measurement (off the hot path, so scaled independently of Votes).
	ProofVotes   []int // tree sizes at which to measure inclusion/consistency proofs
	ProofSamples int   // random leaves/splits sampled per proof scale
}

// Run executes the whole benchmark and returns a populated report.
func Run(cfg Config) (*report.Report, error) {
	if cfg.Threshold < 1 || cfg.Threshold > cfg.Authorities {
		return nil, fmt.Errorf("need 1 <= threshold <= authorities, got t=%d n=%d", cfg.Threshold, cfg.Authorities)
	}
	if cfg.Batch < 1 {
		return nil, fmt.Errorf("batch must be >= 1")
	}

	cores := cfg.Cores
	if cores <= 0 {
		cores = runtime.NumCPU()
	}
	runtime.GOMAXPROCS(cores)
	if cfg.MemLimitBytes > 0 {
		// GOMEMLIMIT is a soft target that pressures the GC; it is NOT a hard cap.
		// A defensible "1 GB machine" result requires cgroups (docker --memory).
		debug.SetMemoryLimit(cfg.MemLimitBytes)
	}

	overhead := measureInstrumentOverhead()

	e, err := newElection(cfg.Group, cfg.Seed, cfg.Candidates, cfg.Authorities, cfg.Threshold)
	if err != nil {
		return nil, err
	}

	if cfg.Warmup > 0 {
		if err := e.warmup(cfg.Warmup, cfg.Batch, cores); err != nil {
			return nil, fmt.Errorf("warmup failed: %w", err)
		}
	}

	rep := &report.Report{
		SchemaVersion:           report.SchemaVersion,
		Tool:                    "abaco",
		GeneratedAt:             time.Now().UTC().Format(time.RFC3339),
		Environment:             DetectEnvironment(cores),
		InstrumentOverheadNanos: overhead,
		Params: report.Params{
			Group:       cfg.Group.Name(),
			Votes:       cfg.Votes,
			Candidates:  cfg.Candidates,
			Authorities: cfg.Authorities,
			Threshold:   cfg.Threshold,
			Cores:       cores,
			MemLimit:    cfg.MemLimitLabel,
			Repeat:      cfg.Repeat,
			Warmup:      cfg.Warmup,
			Batch:       cfg.Batch,
			Seed:        cfg.Seed,
		},
	}

	for _, votes := range cfg.Votes {
		sr, err := runOneScale(e, cfg, votes, cores)
		if err != nil {
			return nil, err
		}
		rep.Scales = append(rep.Scales, sr)
	}

	// Audit proofs: inclusion and consistency, measured at their own scales.
	for _, n := range cfg.ProofVotes {
		pr, err := measureProofs(n, cfg.ProofSamples, int64(cfg.Seed))
		if err != nil {
			return nil, err
		}
		rep.ProofScales = append(rep.ProofScales, pr)
	}
	return rep, nil
}

func runOneScale(e *election, cfg Config, votes, cores int) (report.ScaleResult, error) {
	repeat := cfg.Repeat
	if repeat < 1 {
		repeat = 1
	}
	scaleMeter := newMeter(1 << 20) // merged across repeats for the op breakdown
	wallSamples := make([]float64, 0, repeat)
	cpuSamples := make([]float64, 0, repeat)
	var peakHeap, peakSys uint64

	for rep := 0; rep < repeat; rep++ {
		e.reservoirID = int64(rep) << 32 // deterministic, distinct per repeat
		meter := newMeter(int64(rep) << 40)

		sampler := newMemSampler(50 * time.Millisecond)
		sampler.start()

		prog := newProgress(cfg.Progress, votes, rep, repeat)
		t0 := time.Now()
		acc, expected, _, err := e.runScale(votes, cfg.Batch, cores, meter, prog.update)
		if err != nil {
			sampler.stopAndReport()
			return report.ScaleResult{}, err
		}
		tallies, err := e.finalizeTally(acc, votes, meter)
		wall := time.Since(t0)
		ph, ps := sampler.stopAndReport()
		prog.finish()
		if err != nil {
			return report.ScaleResult{}, err
		}

		// Correctness gate: the decrypted tally MUST match the expected counts.
		// A benchmark of the wrong computation is worthless, so this fails loudly.
		if err := checkTally(votes, tallies, expected); err != nil {
			return report.ScaleResult{}, err
		}

		wallSamples = append(wallSamples, float64(wall.Nanoseconds()))
		cpuSamples = append(cpuSamples, meter.totalCPUNanos())
		scaleMeter.merge(meter)
		if ph > peakHeap {
			peakHeap = ph
		}
		if ps > peakSys {
			peakSys = ps
		}
	}

	wallAgg := report.Summarize(wallSamples)
	cpuAgg := report.Summarize(cpuSamples)
	ballotsPerSec := 0.0
	if wallAgg.Median > 0 {
		ballotsPerSec = float64(votes) / (wallAgg.Median / 1e9)
	}

	return report.ScaleResult{
		Votes:             votes,
		Candidates:        cfg.Candidates,
		Repeats:           repeat,
		Ciphertexts:       votes * cfg.Candidates,
		WallNanos:         wallAgg,
		CPUNanos:          cpuAgg,
		BallotsPerSec:     ballotsPerSec,
		CiphertextsPerSec: ballotsPerSec * float64(cfg.Candidates),
		PeakHeapBytes:     peakHeap,
		PeakSysBytes:      peakSys,
		Correct:           true,
		Ops:               scaleMeter.summaries(),
	}, nil
}

// warmup runs a throwaway scale to warm caches, the branch predictor and the
// allocator before any timed work, then discards its measurements.
func (e *election) warmup(n, batch, cores int) error {
	e.reservoirID = 0
	m := newMeter(0)
	acc, expected, _, err := e.runScale(n, batch, cores, m, nil)
	if err != nil {
		return err
	}
	tallies, err := e.finalizeTally(acc, n, m)
	if err != nil {
		return err
	}
	return checkTally(n, tallies, expected)
}

func checkTally(votes int, got, want []uint64) error {
	if len(got) != len(want) {
		return fmt.Errorf("tally length mismatch: got %d candidates, want %d", len(got), len(want))
	}
	var total uint64
	for c := range got {
		if got[c] != want[c] {
			return fmt.Errorf("CORRECTNESS FAILURE: candidate %d decrypted to %d, expected %d", c, got[c], want[c])
		}
		total += got[c]
	}
	if total != uint64(votes) {
		return fmt.Errorf("CORRECTNESS FAILURE: tallies sum to %d, expected %d votes", total, votes)
	}
	return nil
}

// measureInstrumentOverhead estimates the cost of one time.Now()/time.Since
// pair, so the report can state how much the instrument perturbs each timed
// operation (negligible for ~µs operations, but measured, not assumed).
func measureInstrumentOverhead() float64 {
	const n = 500000
	var sink time.Duration
	start := time.Now()
	for i := 0; i < n; i++ {
		t := time.Now()
		sink += time.Since(t)
	}
	elapsed := time.Since(start)
	runtime.KeepAlive(sink)
	return float64(elapsed.Nanoseconds()) / float64(n)
}
