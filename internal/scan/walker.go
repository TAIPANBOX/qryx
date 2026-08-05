package scan

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/risk"
)

// MaxFileSize caps how large a file we read into memory (4 MiB). Larger files
// are skipped; crypto findings in multi-megabyte blobs are not the Phase 0 case.
// It is exported because a skipped file is counted and reported, and the report
// has to be able to name the cap it hit.
const MaxFileSize = 4 << 20

// skipDirs are never descended into.
var skipDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"vendor":       true,
	"target":       true, // rust
	"dist":         true,
	"build":        true,
	".venv":        true,
	"venv":         true,
	"__pycache__":  true,
}

// Scanner walks a root directory and applies detectors to each eligible file.
type Scanner struct {
	detectors []Detector
}

// New returns a Scanner with the given detectors.
func New(detectors ...Detector) *Scanner {
	return &Scanner{detectors: detectors}
}

// Result is the outcome of a scan.
type Result struct {
	Root        string
	FilesWalked int
	Findings    []model.Finding

	// What the scan could NOT look at. FilesWalked counts only files that were
	// read successfully, so on its own it cannot tell a tree with no crypto in
	// it from a tree qryx never opened: both report zero findings. These three
	// are that difference, and they are reported to the operator rather than
	// dropped.
	Unreadable int // a directory entry, stat or read that failed
	Oversize   int // wanted by a detector, but larger than MaxFileSize
	Unparsed   int // read, but a detector could not parse it
}

// Scan walks root, runs detectors, classifies risk, and returns findings.
func (s *Scanner) Scan(root string) (*Result, error) {
	res := &Result{Root: root}

	// Root-scope file reads to the walked directory: os.Root rejects any
	// resolved path that would land outside root (including via a symlink
	// swapped in between the walk's stat and the read), closing the
	// TOCTOU/traversal window a plain os.ReadFile(path) would leave open.
	rootDir, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	defer rootDir.Close()

	// The detectors carry their own unparsed counts and outlive a single walk,
	// so this scan's share is the difference across it, not the total.
	unparsedBefore := s.unparsed()

	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Keep walking, but never silently: one unreadable directory can
			// hide a whole subtree, and this is the only place that knows.
			res.Unreadable++
			return nil
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}

		wanted := false
		for _, det := range s.detectors {
			if det.Wants(rel) {
				wanted = true
				break
			}
		}
		if !wanted {
			return nil
		}

		// From here on the file is one a detector asked for, so every way of
		// not examining it is a gap in the result and is counted as one.
		info, statErr := d.Info()
		if statErr != nil {
			res.Unreadable++
			return nil
		}
		if info.Size() > MaxFileSize {
			res.Oversize++
			return nil
		}

		content, readErr := rootDir.ReadFile(rel)
		if readErr != nil {
			res.Unreadable++
			return nil
		}
		res.FilesWalked++

		file := File{Path: rel, Content: content}
		isTest := IsTestPath(rel)
		// Rust hides its tests inside the production file (`#[cfg(test)] mod
		// tests { ... }`), so a path check alone leaves fixture crypto in the
		// production inventory. For a `.rs` that is not already test-by-path,
		// find the test line ranges once and judge each finding by its line.
		var rustTest map[int]bool
		if !isTest && strings.HasSuffix(rel, ".rs") {
			rustTest = rustTestLines(content)
		}
		for _, det := range s.detectors {
			if !det.Wants(rel) {
				continue
			}
			found := det.Detect(file)
			// Stamped here rather than in each detector: the walker is the one
			// place that knows the path every finding in this batch came from,
			// so no detector can forget to set it and quietly leak test
			// findings into the production inventory.
			for i := range found {
				found[i].Location.IsTest = isTest || rustTest[found[i].Location.Line]
			}
			res.Findings = append(res.Findings, found...)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	res.Unparsed = s.unparsed() - unparsedBefore

	// Asset-level dedup happens in package graph, which the reporters build
	// from the raw findings; the walker keeps findings flat.
	res.Findings = risk.Apply(res.Findings)
	return res, nil
}

// unparsed totals the files this Scanner's detectors have reported themselves
// unable to parse. A detector that cannot fail to parse does not implement
// UnparsedReporter and contributes nothing.
func (s *Scanner) unparsed() int {
	n := 0
	for _, det := range s.detectors {
		if u, ok := det.(UnparsedReporter); ok {
			n += u.Unparsed()
		}
	}
	return n
}
