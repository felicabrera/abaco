package bench

import (
	"runtime"
	"sync"
	"time"
)

// memSampler polls runtime.MemStats on a fixed interval and tracks the peak
// HeapAlloc and Sys seen. Sampling (rather than reading once at the end) is what
// lets us report the true *peak* resident heap during a run — the number that
// backs the "flat memory" claim. 50ms is frequent enough to catch batch spikes
// while adding negligible load.
type memSampler struct {
	interval time.Duration
	stop     chan struct{}
	done     chan struct{}

	mu       sync.Mutex
	peakHeap uint64
	peakSys  uint64
}

func newMemSampler(interval time.Duration) *memSampler {
	return &memSampler{
		interval: interval,
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
}

func (s *memSampler) start() {
	go func() {
		defer close(s.done)
		t := time.NewTicker(s.interval)
		defer t.Stop()
		s.sample() // take an immediate reading
		for {
			select {
			case <-s.stop:
				s.sample() // final reading
				return
			case <-t.C:
				s.sample()
			}
		}
	}()
}

func (s *memSampler) sample() {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	s.mu.Lock()
	if ms.HeapAlloc > s.peakHeap {
		s.peakHeap = ms.HeapAlloc
	}
	if ms.Sys > s.peakSys {
		s.peakSys = ms.Sys
	}
	s.mu.Unlock()
}

// stopAndReport halts sampling and returns (peakHeap, peakSys) in bytes.
func (s *memSampler) stopAndReport() (uint64, uint64) {
	close(s.stop)
	<-s.done
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.peakHeap, s.peakSys
}
