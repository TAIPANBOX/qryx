# Compatibility

`TAIPANBOX/qryx` promises the surface below from its 1.0 (`compat/1.0.json`, held by `scripts/compat-surface.sh` on every push). A frozen name is not removed or renamed within a major; an additive thing may appear as a minor; an experimental thing may change in any release.

Status: proposed: this repository is at 0.x, and the surface named here is what its 1.0 will freeze; the gate holds it from today so that 1.0 is a tag and not a rewrite

## Frozen

### cli.subcommands (12)

- `scan`
- `fix`
- `trend`
- `verify-evidence`
- `tls`
- `bin`
- `image`
- `aws`
- `gcp`
- `azure`
- `agents`
- `version`
- held in: `cmd/qryx/main.go`

### events.emitted (4)

- `crypto_finding`
- `crypto_drift`
- `policy_violation`
- `evidence_signed`
- held in: `internal/exporter/exporter.go`

### events.schemas_accepted (3)

- `taipanbox.dev/agent-event/v0.1`
- `taipanbox.dev/agent-event/v0.2`
- `taipanbox.dev/agent-passport/v0.1`
- held in: `internal/agentstack/agentstack.go`

### formats.cbom (2)

- `CycloneDX`
- `1.6`
- held in: `internal/report/cbom.go`

### formats.evidence_trail (10)

- `createdAt`
- `root`
- `version`
- `scorePct`
- `compliant`
- `nonCompliant`
- `issues`
- `notAssessed`
- `total`
- `digest`
- held in: `internal/store/evidence.go`

## Additive within a major

- a detector registered in internal/scan/detectors: a new one is a new finding, never a removed one
- a new CLI subcommand behind a connector that does not fit the file walker, the pattern already behind tls, bin, image, aws, gcp, azure and agents
- a CLI flag on an existing subcommand
- an output format added to --format
- a schema version added to what internal/agentstack accepts on read
- the agent-event schema version this repository emits, which moves in its own release (agent-passport SPEC 6.4.1)
- an environment variable, since none exists today (components.json's reads_no_environment claim)
- an HTTP surface, since qryx serves none today: no listen address, no health path, a one-shot CLI

## Experimental

- the dashboard HTML (--format dashboard)
- the html, cnsa-html and ncsc-html report pages, and the trend --html chart

## Support

The newest minor gets every fix; the previous minor gets security-relevant fixes for 90 days after the newer one is tagged. Before this repository's 1.0, only `main` is supported.
