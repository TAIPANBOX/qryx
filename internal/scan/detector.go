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

// UnparsedReporter is implemented by detectors that can be handed a file they
// cannot read: goast on Go source with a syntax error, certfile on a PEM block
// x509 rejects. Both return no findings for it, which is indistinguishable from
// finding nothing in it, and the walker is the only place that can tell an
// operator the difference.
//
// The count is cumulative over the detector's lifetime; the walker takes the
// difference across one walk, so a Scanner used twice does not inherit the
// first scan's total. Optional by design: nothing in Detector changes, and a
// detector that cannot fail to parse simply does not implement this.
type UnparsedReporter interface {
	// Unparsed reports how many files this detector was given and could not
	// parse.
	Unparsed() int
}
