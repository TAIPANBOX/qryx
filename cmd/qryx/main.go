// Command qryx scans a target for cryptographic assets and reports risk.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/probe"
	"github.com/TAIPANBOX/qryx/internal/report"
	"github.com/TAIPANBOX/qryx/internal/risk"
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
		format  = fs.String("format", "human", "output format: human|cbom")
		failOn  = fs.String("fail-on", "", "exit non-zero if a finding at or above this severity exists: low|medium|high|critical")
		timeout = fs.Duration("timeout", 5*time.Second, "per-endpoint connect timeout (tls)")
	)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage:\n  qryx scan [flags] <path>\n  qryx tls [flags] <host:port>...\n\nflags:\n")
		fs.PrintDefaults()
	}

	if len(args) == 0 {
		fs.Usage()
		return fmt.Errorf("no command given")
	}
	cmd := args[0]
	if cmd != "scan" && cmd != "tls" {
		fs.Usage()
		return fmt.Errorf("unknown command %q", cmd)
	}
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	var (
		res *scan.Result
		err error
	)
	switch cmd {
	case "scan":
		if fs.NArg() != 1 {
			fs.Usage()
			return fmt.Errorf("scan requires exactly one path")
		}
		res, err = runScan(fs.Arg(0))
	case "tls":
		if fs.NArg() == 0 {
			fs.Usage()
			return fmt.Errorf("tls requires at least one host:port target")
		}
		res, err = runTLS(fs.Args(), *timeout)
	}
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

func runScan(root string) (*scan.Result, error) {
	scanner := scan.New(
		detectors.NewCertFile(),
		detectors.NewGoAST(),
		detectors.NewCryptoCall(),
		detectors.NewTLSConfig(),
		detectors.NewHardcoded(),
		detectors.NewDeps(),
	)
	return scanner.Scan(root)
}

// runTLS probes each target endpoint and aggregates the findings into a single
// Result. A failed dial to one target is reported to stderr but does not abort
// the others.
func runTLS(targets []string, timeout time.Duration) (*scan.Result, error) {
	res := &scan.Result{Root: "tls://" + strings.Join(targets, ",")}
	for _, t := range targets {
		findings, err := probe.Endpoint(t, timeout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "qryx: %s: %v\n", t, err)
			continue
		}
		res.FilesWalked++
		res.Findings = append(res.Findings, findings...)
	}
	res.Findings = risk.Apply(res.Findings)
	return res, nil
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
