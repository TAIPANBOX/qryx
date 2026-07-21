package scan

import (
	"io/fs"
	"os"
	"path/filepath"

	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/risk"
)

// maxFileSize caps how large a file we read into memory (4 MiB). Larger files
// are skipped; crypto findings in multi-megabyte blobs are not the Phase 0 case.
const maxFileSize = 4 << 20

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

	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries, keep walking
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

		info, statErr := d.Info()
		if statErr != nil || info.Size() > maxFileSize {
			return nil
		}

		content, readErr := rootDir.ReadFile(rel)
		if readErr != nil {
			return nil
		}
		res.FilesWalked++

		file := File{Path: rel, Content: content}
		isTest := IsTestPath(rel)
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
				found[i].Location.IsTest = isTest
			}
			res.Findings = append(res.Findings, found...)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Asset-level dedup happens in package graph, which the reporters build
	// from the raw findings; the walker keeps findings flat.
	res.Findings = risk.Apply(res.Findings)
	return res, nil
}
