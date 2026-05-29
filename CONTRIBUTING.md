# Contributing to qryx

## Development
```
make build   # build bin/qryx
make test    # run tests
make lint    # gofmt + go vet
make scan    # run against testdata/sample
```

## Conventions
- Conventional Commits: `feat:`, `fix:`, `refactor:`, `chore:`, `docs:`, `test:`.
- One logical change per commit.
- `make lint` and `make test` must pass before a PR.
- Detectors: algorithm-based detectors leave `Risk` unset (the scanner classifies
  uniformly); only context-based detectors (TLS misconfig, hardcoded keys,
  expiry) assert their own `Risk`.

## Adding a detector
1. Implement `scan.Detector` in `internal/scan/detectors/`.
2. Register it in `cmd/qryx/main.go`.
3. Add a fixture under `testdata/` and assert it in `internal/scan/scan_test.go`.
