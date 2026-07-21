// Command qryx scans a target for cryptographic assets and reports risk.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/TAIPANBOX/qryx/internal/agentstack"
	"github.com/TAIPANBOX/qryx/internal/attest"
	"github.com/TAIPANBOX/qryx/internal/binscan"
	awscloud "github.com/TAIPANBOX/qryx/internal/cloud/aws"
	azurecloud "github.com/TAIPANBOX/qryx/internal/cloud/azure"
	gcpcloud "github.com/TAIPANBOX/qryx/internal/cloud/gcp"
	"github.com/TAIPANBOX/qryx/internal/exporter"
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
		format    = fs.String("format", "human", "output format: human|cbom|html|cnsa|cnsa-html|migration|evidence|dashboard|ncsc|ncsc-html")
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
		policyNew = fs.Bool("policy-new-only", false, "with --policy and --baseline, fail only on NEW violations vs the baseline")
		saveEvid  = fs.String("save-evidence", "", "append a compliance evidence record to this trail file (JSON Lines)")
		signKey   = fs.String("sign-key", "", "sign --format evidence with this PKCS#8 PEM key (ed25519, ECDSA P-256, or ML-DSA -- for ML-DSA, generate with: openssl genpkey -algorithm ML-DSA-44 -provparam ml-dsa.output_formats=seed-only)")
		failRegr  = fs.Bool("fail-on-regression", false, "with trend: exit 3 if the latest compliance score is below the previous (CI)")
		htmlOut   = fs.Bool("html", false, "with trend: render a self-contained HTML chart instead of a text table")
		eventsArg = fs.String("events", "", "append findings/drift/violations/signed-evidence as agent-event NDJSON to this file, for subjects with a real agent_id (agents source only; see agent-passport SPEC.md §6)")
		withTests = fs.Bool("include-tests", false, "count crypto found in test code (_test.go, testdata/, conftest.py, ...) as part of the production inventory; by default it is reported on stderr and excluded from the graph, the verdict and every format")
	)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage:\n  qryx scan [flags] <path>\n  qryx fix [--write] [--open-pr [--branch NAME]] [--min-rsa-bits N] <path>\n  qryx trend <evidence-trail.jsonl>\n  qryx verify-evidence <evidence.json>\n  qryx tls [flags] <host:port>...\n  qryx bin [flags] <file|dir>...\n  qryx image [flags] <image.tar>...\n  qryx aws [flags]\n  qryx gcp --project <id> [flags]\n  qryx azure --vault-url <url> [flags]\n  qryx agents [flags] <path>\n\nflags:\n")
		fs.PrintDefaults()
	}

	if len(args) == 0 {
		fs.Usage()
		return fmt.Errorf("no command given")
	}
	cmd := args[0]
	if cmd != "scan" && cmd != "fix" && cmd != "trend" && cmd != "verify-evidence" && cmd != "tls" && cmd != "bin" && cmd != "image" && cmd != "aws" && cmd != "gcp" && cmd != "azure" && cmd != "agents" {
		fs.Usage()
		return fmt.Errorf("unknown command %q", cmd)
	}
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	// trend reads an evidence trail instead of scanning a target.
	if cmd == "trend" {
		if fs.NArg() != 1 {
			fs.Usage()
			return fmt.Errorf("trend requires exactly one evidence-trail file")
		}
		records, err := openTrail(fs.Arg(0)).History()
		if err != nil {
			return err
		}
		if *htmlOut {
			if err := report.TrendHTML(os.Stdout, records); err != nil {
				return err
			}
		} else {
			report.Trend(os.Stdout, records)
		}
		if *failRegr && len(records) >= 2 &&
			records[len(records)-1].ScorePct < records[len(records)-2].ScorePct {
			os.Exit(3)
		}
		return nil
	}

	// verify-evidence checks a signed evidence document instead of scanning.
	if cmd == "verify-evidence" {
		if fs.NArg() != 1 {
			fs.Usage()
			return fmt.Errorf("verify-evidence requires exactly one evidence file")
		}
		data, err := os.ReadFile(fs.Arg(0))
		if err != nil {
			return err
		}
		alg, fp, err := report.VerifyEvidence(data)
		if err != nil {
			return fmt.Errorf("verify-evidence: %w", err)
		}
		fmt.Fprintf(os.Stdout, "evidence: VERIFIED (%s, key %s)\n", alg, fp)
		return nil
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
	case "agents":
		if fs.NArg() != 1 {
			fs.Usage()
			return fmt.Errorf("agents requires exactly one path")
		}
		res, err = runAgents(fs.Arg(0))
	}
	if err != nil {
		return err
	}

	if cmd == "fix" {
		return runFix(res, fixOptions{minRSABits: *minRSA, write: *write, openPR: *openPR, branch: *branch})
	}

	// Split test code out ONCE, here, before anything downstream reads
	// res.Findings: the --save snapshot, --events, the policy gate, the
	// compliance verdict and every --format then agree on what production
	// means, instead of each reporter deciding for itself. A baseline that
	// included fixtures would also make --fail-on-new fire on a new test, which
	// is not what a drift gate is for.
	//
	// Never silently: findings set aside are counted and named on stderr, so
	// nothing disappears without the operator being told where it went, and
	// stdout stays clean for the machine formats.
	if !*withTests {
		var setAside []model.Finding
		res.Findings, setAside = scan.PartitionTests(res.Findings)
		reportSetAside(os.Stderr, setAside, res.Findings)
	}

	// Opt-in agent-event emission: only ever fires for findings/nodes/
	// violations carrying a real agent_id, which today means the agents
	// source (internal/agentstack); every other source's Tags has no
	// agent concept, so events.EmitFindings et al. correctly emit nothing
	// for a code/tls/bin/image/cloud scan even with --events set.
	var events *exporter.Exporter
	if *eventsArg != "" {
		events, err = exporter.Open(*eventsArg)
		if err != nil {
			return fmt.Errorf("open events log: %w", err)
		}
		defer events.Close()
		if err := events.EmitFindings(res.Findings); err != nil {
			return err
		}
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
	if events != nil && !delta.Empty() {
		if err := events.EmitDrift(delta.Added); err != nil {
			return err
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
	case "evidence":
		var signer *attest.Signer
		if *signKey != "" {
			signer, err = attest.LoadSigner(*signKey)
			if err != nil {
				return fmt.Errorf("load sign key: %w", err)
			}
		}
		sig, err := report.Evidence(os.Stdout, res, version, signer)
		if err != nil {
			return err
		}
		if events != nil && sig != nil {
			if err := events.EmitEvidenceSigned(res.Findings, sig.Alg, attest.Fingerprint(*sig)); err != nil {
				return err
			}
		}
	case "dashboard":
		if err := report.Dashboard(os.Stdout, res, version); err != nil {
			return err
		}
	case "ncsc":
		if err := report.NCSC(os.Stdout, res); err != nil {
			return err
		}
	case "ncsc-html":
		if err := report.NCSCHTML(os.Stdout, res); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown format %q", *format)
	}

	if *saveEvid != "" {
		att, err := report.Attest(res, version)
		if err != nil {
			return err
		}
		rec := store.EvidenceRecord{
			CreatedAt:    time.Now().UTC(),
			Root:         res.Root,
			Version:      version,
			ScorePct:     att.ScorePct,
			Compliant:    att.Compliant,
			NonCompliant: att.NonCompliant,
			Issues:       att.Issues,
			Total:        att.Total,
			Digest:       att.Digest,
		}
		if err := openTrail(*saveEvid).Append(rec); err != nil {
			return fmt.Errorf("save evidence: %w", err)
		}
	}

	if *policyArg != "" {
		pol, err := policy.Load(*policyArg)
		if err != nil {
			return err
		}
		nodes := graph.Build(res.Findings)
		label := policyName(*policyArg, pol)
		if *policyNew {
			if *baseline == "" {
				return fmt.Errorf("--policy-new-only requires --baseline")
			}
			// delta.Added is empty when the baseline is missing or unchanged, so
			// only genuinely new assets are gated.
			nodes = delta.Added
			label += " (new vs baseline)"
		}
		violations := policy.Evaluate(pol, nodes)
		report.Violations(os.Stderr, label, violations)
		if events != nil {
			// Before os.Exit below: os.Exit skips deferred calls, including
			// defer events.Close() above, so the emit itself must happen
			// first regardless of the exit code that follows.
			if err := events.EmitViolations(violations); err != nil {
				return err
			}
		}
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
		if err := os.WriteFile(filepath.Join(res.Root, p.File), []byte(p.NewContent), 0o600); err != nil {
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
// reportSetAside tells the operator, on stderr, what was excluded as test code
// and how much of it exists nowhere else.
//
// The "only in test code" count is the one that changes a decision: an asset
// that also appears in production is still on the migration list and merely had
// its occurrence count corrected, whereas one that exists ONLY in fixtures was
// never production crypto debt at all and would have been inflating the number
// an operator is trying to drive to zero.
//
// Identity comes from graph.AssetKey, never a locally invented key: that
// identity deliberately includes risk class, and a hand-rolled one that omitted
// it would fold two distinct assets into one and undercount.
func reportSetAside(w io.Writer, setAside, production []model.Finding) {
	if len(setAside) == 0 {
		return
	}
	inProduction := map[string]bool{}
	for _, n := range graph.Build(production) {
		inProduction[graph.AssetKey(n.Asset, n.Risk.Class)] = true
	}
	onlyTest := 0
	for _, n := range graph.Build(setAside) {
		if !inProduction[graph.AssetKey(n.Asset, n.Risk.Class)] {
			onlyTest++
		}
	}
	fmt.Fprintf(w, "qryx: %d finding(s) in test code excluded from the production inventory", len(setAside))
	if onlyTest > 0 {
		fmt.Fprintf(w, "; %d asset(s) exist only there", onlyTest)
	}
	fmt.Fprintln(w, ". Pass --include-tests to count them.")
}

func openStore(target string) store.Store {
	if strings.HasPrefix(target, "postgres://") || strings.HasPrefix(target, "postgresql://") {
		return store.PostgresStore{ConnString: target}
	}
	return store.JSONStore{Path: target}
}

// openTrail selects an evidence-trail backend by target: a postgres:// URL uses
// Postgres, anything else is a JSON Lines file path.
func openTrail(target string) store.Trail {
	if strings.HasPrefix(target, "postgres://") || strings.HasPrefix(target, "postgresql://") {
		return store.PostgresTrail{ConnString: target}
	}
	return store.JSONLTrail{Path: target}
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

// runAgents inventories the cryptography of AI-agent infrastructure: Agent
// Passport attestation methods and agent-event NDJSON hash-chain integrity, so
// the agent-governance stack's own trust surface lands in the same asset graph
// as everything else. path is a directory (walked recursively), a glob
// pattern, or a single file.
func runAgents(path string) (*scan.Result, error) {
	findings, err := agentstack.Scan(path)
	if err != nil {
		return nil, err
	}
	res := &scan.Result{Root: "agents://" + path, FilesWalked: 1}
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
