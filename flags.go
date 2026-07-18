package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

// parseIntList parses a comma-separated list of positive integers, e.g.
// "1000,10000,100000". Underscores are allowed as digit separators (1_000_000).
func parseIntList(s string) ([]int, error) {
	parts := strings.Split(s, ",")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(strings.ReplaceAll(p, "_", ""))
		if p == "" {
			continue
		}
		v, err := strconv.Atoi(p)
		if err != nil || v < 0 {
			return nil, fmt.Errorf("invalid count %q", p)
		}
		out = append(out, v)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no counts given")
	}
	return out, nil
}

// parseSize parses a byte size with an optional unit. Both IEC/binary (KiB, MiB,
// GiB) and SI/decimal (KB, MB, GB) suffixes are accepted, as is a bare byte
// count. Returns (bytes, canonicalLabel).
func parseSize(s string) (int64, string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, "none", nil
	}
	up := strings.ToUpper(s)
	type unit struct {
		suffix string
		mult   int64
	}
	// Longest suffixes first so "GiB" matches before "B".
	units := []unit{
		{"KIB", 1 << 10}, {"MIB", 1 << 20}, {"GIB", 1 << 30}, {"TIB", 1 << 40},
		{"KB", 1000}, {"MB", 1000 * 1000}, {"GB", 1000 * 1000 * 1000}, {"TB", 1000 * 1000 * 1000 * 1000},
		{"K", 1 << 10}, {"M", 1 << 20}, {"G", 1 << 30}, {"T", 1 << 40},
		{"B", 1},
	}
	for _, u := range units {
		if strings.HasSuffix(up, u.suffix) {
			num := strings.TrimSpace(up[:len(up)-len(u.suffix)])
			v, err := strconv.ParseFloat(num, 64)
			if err != nil {
				return 0, "", fmt.Errorf("invalid size %q", s)
			}
			return int64(v * float64(u.mult)), s, nil
		}
	}
	v, err := strconv.ParseInt(up, 10, 64)
	if err != nil {
		return 0, "", fmt.Errorf("invalid size %q", s)
	}
	return v, s, nil
}

// resolveSeed returns the run seed: the user's value if >= 0, otherwise a fresh
// random seed. Either way the caller reports it so the run is reproducible.
func resolveSeed(flagVal int64) uint64 {
	if flagVal >= 0 {
		return uint64(flagVal)
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	return binary.LittleEndian.Uint64(b[:])
}
