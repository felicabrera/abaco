package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/felicabrera/abaco/internal/bench"
	"github.com/felicabrera/abaco/internal/report"
)

func runEnv(args []string) {
	fs := flag.NewFlagSet("env", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: abaco env")
		fmt.Fprintln(os.Stderr, "Prints the detected host environment for citation in a report.")
	}
	_ = fs.Parse(args)

	env := bench.DetectEnvironment(0)
	fmt.Printf("CPU:        %s\n", env.CPU)
	fmt.Printf("Cores:      %d logical\n", env.NumCPU)
	fmt.Printf("RAM:        %s\n", report.FormatBytes(env.TotalRAMByte))
	fmt.Printf("Go:         %s\n", env.GoVersion)
	fmt.Printf("OS/Arch:    %s/%s\n", env.OS, env.Arch)
	fmt.Printf("GOMEMLIMIT: %s\n", env.GoMemLimit)
	fmt.Printf("Commit:     %s\n", env.Commit)
}
