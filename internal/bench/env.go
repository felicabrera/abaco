package bench

import (
	"os/exec"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/felicabrera/abaco/internal/report"
)

// DetectEnvironment gathers the citable facts about the host: CPU model, core
// count, RAM, Go version, OS/arch and the build commit. Anything it cannot read
// is reported as "unknown" rather than guessed.
func DetectEnvironment(coresUsed int) report.Environment {
	env := report.Environment{
		CPU:          detectCPU(),
		NumCPU:       runtime.NumCPU(),
		CoresUsed:    coresUsed,
		TotalRAMByte: detectRAM(),
		GoVersion:    runtime.Version(),
		OS:           runtime.GOOS,
		Arch:         runtime.GOARCH,
		Commit:       detectCommit(),
		GoMemLimit:   memLimitString(),
	}
	return env
}

func detectCPU() string {
	switch runtime.GOOS {
	case "darwin":
		if out, err := exec.Command("sysctl", "-n", "machdep.cpu.brand_string").Output(); err == nil {
			if s := strings.TrimSpace(string(out)); s != "" {
				return s
			}
		}
	case "linux":
		if out, err := exec.Command("sh", "-c", "grep -m1 'model name' /proc/cpuinfo | cut -d: -f2").Output(); err == nil {
			if s := strings.TrimSpace(string(out)); s != "" {
				return s
			}
		}
	}
	return "unknown (" + runtime.GOARCH + ")"
}

func detectRAM() uint64 {
	switch runtime.GOOS {
	case "darwin":
		if out, err := exec.Command("sysctl", "-n", "hw.memsize").Output(); err == nil {
			if v, err := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 64); err == nil {
				return v
			}
		}
	case "linux":
		if out, err := exec.Command("sh", "-c", "grep MemTotal /proc/meminfo | awk '{print $2}'").Output(); err == nil {
			if kb, err := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 64); err == nil {
				return kb * 1024
			}
		}
	}
	return 0
}

// detectCommit reads the VCS revision embedded by the Go toolchain at build
// time (available when built from a Git checkout).
func detectCommit() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	rev, dirty := "", ""
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			if s.Value == "true" {
				dirty = "-dirty"
			}
		}
	}
	if rev == "" {
		return "unknown"
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	return rev + dirty
}

func memLimitString() string {
	limit := debug.SetMemoryLimit(-1) // read without changing
	if limit == math_MaxInt64 {
		return "none"
	}
	return report.FormatBytes(uint64(limit))
}

// math.MaxInt64 without importing math for one constant.
const math_MaxInt64 = 1<<63 - 1
