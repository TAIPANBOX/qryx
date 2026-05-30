package scan

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

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

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
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

		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		res.FilesWalked++

		file := File{Path: rel, Content: content}
		for _, det := range s.detectors {
			if !det.Wants(rel) {
				continue
			}
			res.Findings = append(res.Findings, det.Detect(file)...)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	res.Findings = dedup(risk.Apply(res.Findings))
	return res, nil
}

// dedup collapses findings that describe the same asset at the same location,
// keeping the one with the highest severity.
func dedup(findings []model.Finding) []model.Finding {
	type key struct {
		algo string
		file string
		line int
	}
	best := make(map[key]model.Finding)
	order := []key{}

	for _, f := range findings {
		k := key{
			algo: strings.ToUpper(f.Asset.Algorithm),
			file: f.Location.File,
			line: f.Location.Line,
		}
		cur, ok := best[k]
		if !ok {
			best[k] = f
			order = append(order, k)
			continue
		}
		if f.Risk.Severity > cur.Risk.Severity {
			best[k] = f
		}
	}

	out := make([]model.Finding, 0, len(order))
	for _, k := range order {
		out = append(out, best[k])
	}
	return out
}
