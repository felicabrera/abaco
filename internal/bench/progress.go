package bench

import (
	"fmt"
	"io"
	"time"

	"github.com/felicabrera/abaco/internal/report"
)

// progress draws a single live status line for one scale/repeat. A long run
// (10M votes can take minutes) needs to show it is advancing. Updates are
// throttled so the terminal is not spammed.
type progress struct {
	w        io.Writer
	total    int
	rep      int
	repeats  int
	start    time.Time
	lastDraw time.Time
}

func newProgress(w io.Writer, total, rep, repeats int) *progress {
	return &progress{w: w, total: total, rep: rep, repeats: repeats, start: time.Now()}
}

func (p *progress) update(done int) {
	if p.w == nil {
		return
	}
	now := time.Now()
	if done < p.total && now.Sub(p.lastDraw) < 100*time.Millisecond {
		return
	}
	p.lastDraw = now
	pct := 100 * float64(done) / float64(p.total)
	rate := float64(done) / now.Sub(p.start).Seconds()
	fmt.Fprintf(p.w, "\r  scale %s  rep %d/%d  %s/%s (%.1f%%)  %s ballots/s   ",
		report.FormatCount(int64(p.total)), p.rep+1, p.repeats,
		report.FormatCount(int64(done)), report.FormatCount(int64(p.total)),
		pct, report.FormatCount(int64(rate)))
}

func (p *progress) finish() {
	if p.w == nil {
		return
	}
	elapsed := time.Since(p.start)
	fmt.Fprintf(p.w, "\r  scale %s  rep %d/%d  done in %s%s\n",
		report.FormatCount(int64(p.total)), p.rep+1, p.repeats,
		report.FormatDuration(float64(elapsed.Nanoseconds())),
		"                                        ")
}
