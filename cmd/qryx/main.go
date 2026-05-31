// Command qryx scans a target for cryptographic assets and reports risk.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/TAIPANBOX/qryx/internal/binscan"
	awscloud "github.com/TAIPANBOX/qryx/internal/cloud/aws"
	azurecloud "github.com/TAIPANBOX/qryx/internal/cloud/azure"
	gcpcloud "github.com/TAIPANBOX/qryx/internal/cloud/gcp"
	"github.com/TAIPANBOX/qryx/internal/graph"
	"github.com/TAIPANBOX/qryx/internal/imagescan"
	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/policy"
	"github.com/TAIPANBOX/qryx/internal/probe"
	"github.com/TAIPANBOX/qryx/internal/remediate"
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
		format    = fs.String("format", "human", "output format: human|cbom|html|cnsa|cnsa-html|migration")
		failOn    = fs.String("fail-on", "", "exit 2 if any finding is at or above this severity: low|medium|high|critical")
		failOnNew = fs.String("fail-on-new", "", "exit 2 if a NEW asset (vs --baseline) is at or above this severity")
		timeout   = fs.Duration("timeout", 5*time.Second, "per-endpoint connect timeout (tls)")
		save      = fs.String("save", "", "write the asset graph as a snapshot to this file")
		baseline  = fs.String("baseline", "", "compare the asset graph against this snapshot and report drift")
		region    = fs.String("region", "", "AWS region (aws)")
		profile   = fs.String("profile", "", "AWS shared-config profile (aws)")
		project   = fs.String("project", "", "GCP project ID (gcp)")
		location  = fs.String("location", "global", "GCP KMS location (gcp)")
		vaultURL  = fs.String("vault-url", "", "Azure Key Vault URL, e.g. https://myvault.vault.azure.net/ (azure)")
		write     = fs.Bool("write", false, "apply fixes in place (fix); default prints a unified diff")
		minRSA    = fs.Int("min-rsa-bits", 3072, "raise RSA keys below this size when fixing (fix)")
		openPR    = fs.Bool("open-pr", false, "apply fixes and open a GitHub PR via git+gh (fix)")
		branch    = fs.String("branch", "", "branch name for --open-pr (default qryx/fix-<rule>-<timestamp>)")
		policyArg = fs.String("policy", "", "evaluate against a policy (builtin name e.g. cnsa, or a JSON file); exit 3 on violation")
	)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage:\n  qryx scan [flags] <path>\n  qryx fix [--write] [--open-pr [--branch NAME]] [--min-rsa-bits N] <path>\n  qryx tls [flags] <host:port>...\n  qryx bin [flags] <file|dir>...\n  qryx image [flags] <image.tar>...\n  qryx aws [flags]\n  qryx gcp --project <id> [flags]\n  qryx azure --vault-url <url> [flags]\n\nflags:\n")
		fs.PrintDefaults()
	}

	if len(args) == 0 {
		fs.Usage()
		return fmt.Errorf("no command given")
	}
	cmd := args[0]
	if cmd != "scan" && cmd != "fix" && cmd != "tls" && cmd != "bin" && cmd != "image" && cmd != "aws" && cmd != "gcp" && cmd != "azure" {
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
	case "fix":
		if fs.NArg() != 1 {
			fs.Usage()
			return fmt.Errorf("fix requires exactly one path")
		}
		res, err = runScan(fs.Arg(0))
	case "tls":
		if fs.NArg() == 0 {
			fs.Usage()
			return fmt.Errorf("tls requires at least one host:port target")
		}
		res, err = runTLS(fs.Args(), *timeout)
	case "bin":
		if fs.NArg() == 0 {
			fs.Usage()
			return fmt.Errorf("bin requires at least one file or directory")
		}
		res, err = runBin(fs.Args())
	case "image":
		if fs.NArg() == 0 {
			fs.Usage()
			return fmt.Errorf("image requires at least one image tarball")
		}
		res, err = runImage(fs.Args())
	case "aws":
		res, err = runAWS(*region, *profile)
	case "gcp":
		if *project == "" {
			fs.Usage()
			return fmt.Errorf("gcp requires --project")
		}
		res, err = runGCP(*project, *location)
	case "azure":
		if *vaultURL == "" {
			fs.Usage()
			return fmt.Errorf("azure requires --vault-url")
		}
		res, err = runAzure(*vaultURL)
	}
	if err != nil {
		return err
	}

	if cmd == "fix" {
		return runFix(res, fixOptions{minRSABits: *minRSA, write: *write, openPR: *openPR, branch: *branch})
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
	case "html":
		if err := report.HTML(os.Stdout, res); err != nil {
			return err
		}
	case "cnsa":
		if err := report.CNSA(os.Stdout, res); err != nil {
			return err
		}
	case "cnsa-html":
		if err := report.CNSAHTML(os.Stdout, res); err != nil {
			return err
		}
	case "migration":
		if err := report.Migration(os.Stdout, res); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown format %q", *format)
	}

	if *policyArg != "" {
		pol, err := policy.Load(*policyArg)
		if err != nil {
			return err
		}
		violations := policy.Evaluate(pol, graph.Build(res.Findings))
		report.Violations(os.Stderr, policyName(*policyArg, pol), violations)
		if len(violations) > 0 {
			os.Exit(3)
		}
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

type fixOptions struct {
	minRSABits int
	write      bool
	openPR     bool
	branch     string
}

// runFix derives safe source patches from a scan. By default it prints unified
// diffs; --write applies them in place; --open-pr applies them and opens a
// GitHub PR via git+gh.
func runFix(res *scan.Result, opts fixOptions) error {
	if opts.minRSABits < 2048 {
		return fmt.Errorf("--min-rsa-bits must be >= 2048")
	}
	patches, err := remediate.Plan(res, opts.minRSABits)
	if err != nil {
		return err
	}
	if len(patches) == 0 {
		fmt.Fprintln(os.Stderr, "qryx: no safe automatic fixes found")
		return nil
	}

	// --open-pr writes via OpenPR (on a fresh branch, after a clean-tree check),
	// so it must not pre-write here.
	if opts.openPR {
		url, err := remediate.OpenPR(res.Root, patches, remediate.PROptions{Branch: opts.branch}, remediate.GitCLI{})
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "qryx: changed %d file(s); opened PR %s\n", len(patches), url)
		return nil
	}

	if !opts.write {
		for _, p := range patches {
			fmt.Print(p.Diff)
		}
		fmt.Fprintf(os.Stderr, "qryx: would change %d file(s)\n", len(patches))
		return nil
	}
	for _, p := range patches {
		if err := os.WriteFile(filepath.Join(res.Root, p.File), []byte(p.NewContent), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", p.File, err)
		}
		fmt.Fprintf(os.Stderr, "fixed %s (%s)\n", p.File, p.Rule)
	}
	fmt.Fprintf(os.Stderr, "qryx: changed %d file(s)\n", len(patches))
	return nil
}

// runBin scans each path for ELF binaries and aggregates their crypto findings.
func runBin(paths []string) (*scan.Result, error) {
	findings, err := binscan.Scan(paths)
	if err != nil {
		return nil, err
	}
	res := &scan.Result{Root: "bin://" + strings.Join(paths, ","), FilesWalked: len(paths)}
	res.Findings = risk.Apply(findings)
	return res, nil
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
	return scan.New(detectors.Default()...).Scan(root)
}

// runAWS inventories KMS keys and ACM certificates in an AWS account.
func runAWS(region, profile string) (*scan.Result, error) {
	findings, err := awscloud.Scan(context.Background(), region, profile)
	if err != nil {
		return nil, err
	}
	root := "aws://" + region
	if region == "" {
		root = "aws://default"
	}
	res := &scan.Result{Root: root, FilesWalked: 1}
	res.Findings = risk.Apply(findings)
	return res, nil
}

// runAzure inventories keys in an Azure Key Vault.
func runAzure(vaultURL string) (*scan.Result, error) {
	findings, err := azurecloud.Scan(context.Background(), vaultURL)
	if err != nil {
		return nil, err
	}
	res := &scan.Result{Root: "azure://" + vaultURL, FilesWalked: 1}
	res.Findings = risk.Apply(findings)
	return res, nil
}

// runGCP inventories Cloud KMS key versions in a GCP project/location.
func runGCP(project, location string) (*scan.Result, error) {
	findings, err := gcpcloud.Scan(context.Background(), project, location)
	if err != nil {
		return nil, err
	}
	res := &scan.Result{Root: fmt.Sprintf("gcp://%s/%s", project, location), FilesWalked: 1}
	res.Findings = risk.Apply(findings)
	return res, nil
}

// runImage extracts each container image tarball and scans its layers.
func runImage(tars []string) (*scan.Result, error) {
	findings, err := imagescan.Scan(tars)
	if err != nil {
		return nil, err
	}
	res := &scan.Result{Root: "image://" + strings.Join(tars, ","), FilesWalked: len(tars)}
	res.Findings = risk.Apply(findings)
	return res, nil
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

// policyName is the label shown in the violations report: the policy's own name
// when set, otherwise the file/builtin argument.
func policyName(arg string, p policy.Policy) string {
	if p.Name != "" {
		return p.Name
	}
	return arg
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
