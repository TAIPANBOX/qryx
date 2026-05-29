// Package scan walks a target tree and runs detectors to produce findings.
package scan

import "github.com/TAIPANBOX/qryx/internal/model"

// File is a single readable unit handed to detectors.
type File struct {
	Path    string // path relative to scan root
	Content []byte
}

// Detector inspects a file and returns any cryptographic findings in it.
// Algorithm-based detectors leave Risk unset and let the scanner classify
// uniformly. Context-based detectors (TLS misconfig, hardcoded keys) may set
// Risk themselves, since their risk does not follow from the algorithm alone.
type Detector interface {
	// Name identifies the detector in findings and reports.
	Name() string
	// Wants reports whether this detector should run on the given path.
	Wants(path string) bool
	// Detect returns findings for the file.
	Detect(f File) []model.Finding
}
