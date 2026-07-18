package report

import (
	"bytes"
	"encoding/json"
	"math"
	"testing"
)

func TestSummarizeBasic(t *testing.T) {
	s := Summarize([]float64{1, 2, 3, 4, 5})
	if s.Min != 1 || s.Max != 5 {
		t.Fatalf("min/max = %v/%v, want 1/5", s.Min, s.Max)
	}
	if s.Median != 3 {
		t.Fatalf("median = %v, want 3", s.Median)
	}
	if s.Mean != 3 {
		t.Fatalf("mean = %v, want 3", s.Mean)
	}
}

func TestSummarizeSingle(t *testing.T) {
	s := Summarize([]float64{42})
	if s.Median != 42 || s.P95 != 42 || s.P99 != 42 || s.StdDev != 0 {
		t.Fatalf("single-sample summary wrong: %+v", s)
	}
}

func TestPercentileMonotone(t *testing.T) {
	data := []float64{10, 20, 30, 40, 50, 60, 70, 80, 90, 100}
	p50 := Percentile(data, 50)
	p95 := Percentile(data, 95)
	if p50 > p95 {
		t.Fatalf("p50 (%v) should be <= p95 (%v)", p50, p95)
	}
}

func TestFormatDuration(t *testing.T) {
	cases := map[float64]string{
		500:       "500 ns",
		1500:      "1.50 µs",
		1_500_000: "1.50 ms",
		2e9:       "2.000 s",
	}
	for ns, want := range cases {
		if got := FormatDuration(ns); got != want {
			t.Errorf("FormatDuration(%v) = %q, want %q", ns, got, want)
		}
	}
}

func TestFormatBytes(t *testing.T) {
	if got := FormatBytes(1 << 30); got != "1.0 GiB" {
		t.Errorf("FormatBytes(1GiB) = %q", got)
	}
	if got := FormatBytes(512); got != "512 B" {
		t.Errorf("FormatBytes(512) = %q", got)
	}
}

func TestFormatCount(t *testing.T) {
	if got := FormatCount(1234567); got != "1,234,567" {
		t.Errorf("FormatCount = %q", got)
	}
}

func TestJSONRoundTrip(t *testing.T) {
	in := &Report{
		SchemaVersion: SchemaVersion,
		Tool:          "abaco",
		Scales: []ScaleResult{{
			Votes: 1000, Candidates: 2, Correct: true,
			Ops: []OpSummary{{Name: "Encrypt", Calls: 2000, MedianNanos: 95000}},
		}},
	}
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(in); err != nil {
		t.Fatal(err)
	}
	var out Report
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.SchemaVersion != SchemaVersion || len(out.Scales) != 1 || out.Scales[0].Votes != 1000 {
		t.Fatalf("round-trip mismatch: %+v", out)
	}
	if math.Abs(out.Scales[0].Ops[0].MedianNanos-95000) > 1e-9 {
		t.Fatalf("op median lost in round-trip")
	}
}
