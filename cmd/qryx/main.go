// Command qryx scans a target for cryptographic assets and reports risk.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/report"
	"github.com/TAIPANBOX/qryx/internal/scan"
	"github.com/TAIPANBOX/qryx/internal/scan/detectors"
)

// version is overridden at build time via -ldflags.
var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "qryx:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("qryx", flag.ContinueOnError)
	var (
		format = fs.String("format", "human", "output format: human|cbom")
		failOn = fs.String("fail-on", "", "exit non-zero if a finding at or above this severity exists: low|medium|high|critical")
	)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: qryx scan [flags] <path>\n\nflags:\n")
		fs.PrintDefaults()
	}

	if len(args) == 0 {
		fs.Usage()
		return fmt.Errorf("no command given")
	}
	if args[0] != "scan" {
		fs.Usage()
		return fmt.Errorf("unknown command %q", args[0])
	}
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return fmt.Errorf("scan requires exactly one path")
	}
	root := fs.Arg(0)

	scanner := scan.New(
		detectors.NewCertFile(),
		detectors.NewCryptoCall(),
		detectors.NewTLSConfig(),
		detectors.NewHardcoded(),
		detectors.NewDeps(),
	)
	res, err := scanner.Scan(root)
	if err != nil {
		return err
	}

	switch *format {
	case "human":
		report.Human(os.Stdout, res)
	case "cbom":
		if err := report.CBOM(os.Stdout, res, version); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown format %q", *format)
	}

	if *failOn != "" {
		threshold, ok := parseSeverity(*failOn)
		if !ok {
			return fmt.Errorf("invalid --fail-on value %q", *failOn)
		}
		for _, f := range res.Findings {
			if f.Risk.Severity >= threshold && f.Risk.Class != model.RiskNone {
				os.Exit(2)
			}
		}
	}
	return nil
}

func parseSeverity(s string) (model.Severity, bool) {
	switch s {
	case "low":
		return model.SeverityLow, true
	case "medium":
		return model.SeverityMedium, true
	case "high":
		return model.SeverityHigh, true
	case "critical":
		return model.SeverityCritical, true
	default:
		return model.SeverityNone, false
	}
}
