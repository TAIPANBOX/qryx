// Command qryx scans a target for cryptographic assets and reports risk.
package main

import (
	"errors"
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
	"github.com/TAIPANBOX/qryx/internal/store"
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
		format    = fs.String("format", "human", "output format: human|cbom")
		failOn    = fs.String("fail-on", "", "exit 2 if any finding is at or above this severity: low|medium|high|critical")
		failOnNew = fs.String("fail-on-new", "", "exit 2 if a NEW asset (vs --baseline) is at or above this severity")
		timeout   = fs.Duration("timeout", 5*time.Second, "per-endpoint connect timeout (tls)")
		save      = fs.String("save", "", "write the asset graph as a snapshot to this file")
		baseline  = fs.String("baseline", "", "compare the asset graph against this snapshot and report drift")
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

	if *save != "" {
		if err := openStore(*save).Save(store.Snap(res)); err != nil {
			return fmt.Errorf("save snapshot: %w", err)
		}
	}

	// Compute drift against the baseline, if one is given and exists.
	var delta store.Delta
	if *baseline != "" {
		base, err := openStore(*baseline).Load()
		switch {
		case errors.Is(err, store.ErrNotFound):
			fmt.Fprintf(os.Stderr, "qryx: baseline %s not found; skipping drift\n", *baseline)
		case err != nil:
			return fmt.Errorf("load baseline: %w", err)
		default:
			delta = store.Diff(base, store.Snap(res))
		}
	}

	switch *format {
	case "human":
		report.Human(os.Stdout, res)
		if *baseline != "" {
			report.Drift(os.Stdout, delta)
		}
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
	if *failOnNew != "" {
		threshold, ok := parseSeverity(*failOnNew)
		if !ok {
			return fmt.Errorf("invalid --fail-on-new value %q", *failOnNew)
		}
		for _, n := range delta.Added {
			if n.Risk.Severity >= threshold && n.Risk.Class != model.RiskNone {
				os.Exit(2)
			}
		}
	}
	return nil
}

// openStore selects a snapshot backend by target: a postgres:// or postgresql://
// URL uses Postgres, anything else is treated as a JSON file path.
func openStore(target string) store.Store {
	if strings.HasPrefix(target, "postgres://") || strings.HasPrefix(target, "postgresql://") {
		return store.PostgresStore{ConnString: target}
	}
	return store.JSONStore{Path: target}
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
