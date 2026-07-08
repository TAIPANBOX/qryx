// Package remediate turns scan findings into concrete, reviewable source
// patches. It only emits transforms that are provably safe — currently raising
// a sub-floor RSA key size, a single integer-literal change that always
// compiles. Algorithm swaps (MD5->SHA-256) and hybrid schemes change semantics
// and break downstream consumers, so they stay as migration guidance and are
// never auto-applied.
package remediate

import (
	"os"
	"sort"
	"strings"

	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/scan"
)

// Patch is a proposed change to one file.
type Patch struct {
	File       string // path relative to the scan root
	Rule       string // rule(s) that produced it
	Rationale  string // why, human-readable
	OldContent string
	NewContent string
	Diff       string // unified diff (old -> new)
}

// Config tunes the rules.
type Config struct {
	MinRSABits int
}

// rule rewrites a single file given its findings. It returns the rewritten
// content, a rationale, and ok=false when it has nothing safe to change.
type rule interface {
	name() string
	apply(content string, findings []model.Finding, cfg Config) (out, rationale string, ok bool)
}

// rules is the ordered registry. Add safe, semantics-preserving rules here.
var rules = []rule{rsaKeySize{}, tfRSABits{}}

// Plan derives safe patches from a scan result. minRSABits is the floor that
// sub-floor RSA keys are raised to. Unreadable files are skipped, not fatal.
func Plan(res *scan.Result, minRSABits int) ([]Patch, error) {
	cfg := Config{MinRSABits: minRSABits}

	byFile := map[string][]model.Finding{}
	for _, f := range res.Findings {
		byFile[f.Location.File] = append(byFile[f.Location.File], f)
	}
	files := make([]string, 0, len(byFile))
	for f := range byFile {
		files = append(files, f)
	}
	sort.Strings(files)

	// Root-scope reads to the scan root: file is a scan-relative path off the
	// findings we generated, but os.Root still closes the traversal/TOCTOU
	// window a raw filepath.Join+os.ReadFile leaves open.
	rootDir, err := os.OpenRoot(res.Root)
	if err != nil {
		return nil, err
	}
	defer rootDir.Close()

	var patches []Patch
	for _, file := range files {
		raw, err := rootDir.ReadFile(file)
		if err != nil {
			continue
		}
		orig := string(raw)
		content := orig
		var ruleNames, rationales []string
		for _, r := range rules {
			out, rationale, ok := r.apply(content, byFile[file], cfg)
			if !ok {
				continue
			}
			content = out
			ruleNames = append(ruleNames, r.name())
			rationales = append(rationales, rationale)
		}
		if content == orig {
			continue
		}
		patches = append(patches, Patch{
			File:       file,
			Rule:       strings.Join(ruleNames, ","),
			Rationale:  strings.Join(rationales, "; "),
			OldContent: orig,
			NewContent: content,
			Diff:       unifiedDiff(file, orig, content),
		})
	}
	return patches, nil
}
