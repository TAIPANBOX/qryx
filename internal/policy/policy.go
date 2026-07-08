// Package policy evaluates a cryptographic asset graph against a declarative
// policy so CI can block on crypto-hygiene violations (forbidden algorithms,
// weak key sizes, hardcoded keys, ...). It is the enforcement half of
// governance: discovery and risk classification happen elsewhere; policy turns
// them into a pass/fail gate.
package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/TAIPANBOX/qryx/internal/graph"
	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/risk"
)

// Policy is a declarative crypto policy. A zero value forbids nothing.
type Policy struct {
	Name                    string   `json:"name"`
	ForbidAlgorithms        []string `json:"forbidAlgorithms"`
	MinRSABits              int      `json:"minRsaBits"`
	ForbidQuantumVulnerable bool     `json:"forbidQuantumVulnerable"`
	ForbidHardcoded         bool     `json:"forbidHardcoded"`
	ForbidExpired           bool     `json:"forbidExpired"`
	ForbidMisconfig         bool     `json:"forbidMisconfig"`
	MaxSeverity             string   `json:"maxSeverity"`
}

// Violation is one asset breaching one policy rule.
type Violation struct {
	Rule      string
	Asset     string
	Severity  model.Severity
	Message   string
	Locations []string
}

// builtins are named policies usable without a config file.
var builtins = map[string]Policy{
	"cnsa": {
		Name:             "cnsa",
		ForbidAlgorithms: []string{"MD5", "MD4", "SHA-1", "DES", "3DES", "RC4", "RC2", "DSA"},
		MinRSABits:       3072,
		ForbidHardcoded:  true,
		ForbidExpired:    true,
		ForbidMisconfig:  true,
		// Quantum-vulnerable assets have a 2030 CNSA deadline, so they are not an
		// immediate hard gate by default; opt in with forbidQuantumVulnerable.
	},
}

// Load returns a builtin policy by name, or reads and parses a JSON policy file.
func Load(nameOrPath string) (Policy, error) {
	if p, ok := builtins[nameOrPath]; ok {
		return p, nil
	}
	raw, err := os.ReadFile(nameOrPath) // #nosec G304 -- nameOrPath is the operator's own --policy CLI argument, same trust model as any local config file the invoking user names
	if err != nil {
		return Policy{}, fmt.Errorf("load policy %q: not a builtin and %w", nameOrPath, err)
	}
	var p Policy
	if err := json.Unmarshal(raw, &p); err != nil {
		return Policy{}, fmt.Errorf("parse policy %q: %w", nameOrPath, err)
	}
	if p.MaxSeverity != "" {
		if _, ok := parseSeverity(p.MaxSeverity); !ok {
			return Policy{}, fmt.Errorf("policy %q: invalid maxSeverity %q", nameOrPath, p.MaxSeverity)
		}
	}
	return p, nil
}

// Evaluate returns every violation of p across the deduped asset graph. The
// result is sorted by severity (desc) then asset name for stable output.
func Evaluate(p Policy, nodes []graph.AssetNode) []Violation {
	forbidden := map[string]bool{}
	for _, a := range p.ForbidAlgorithms {
		forbidden[risk.NormalizeAlgorithm(a)] = true
	}
	maxSev, hasMax := parseSeverity(p.MaxSeverity)

	var out []Violation
	for _, n := range nodes {
		name := assetName(n.Asset)
		algo := risk.NormalizeAlgorithm(n.Asset.Algorithm)
		locs := locations(n)

		if forbidden[algo] {
			out = append(out, Violation{
				Rule: "forbidden-algorithm", Asset: name, Severity: model.SeverityCritical,
				Message: fmt.Sprintf("%s is forbidden by policy", name), Locations: locs,
			})
		}
		if p.MinRSABits > 0 && algo == "RSA" && n.Asset.KeySize > 0 && n.Asset.KeySize < p.MinRSABits {
			out = append(out, Violation{
				Rule: "min-rsa-bits", Asset: name, Severity: model.SeverityCritical,
				Message: fmt.Sprintf("RSA-%d is below the policy minimum of %d bits", n.Asset.KeySize, p.MinRSABits), Locations: locs,
			})
		}
		if p.ForbidQuantumVulnerable && n.Risk.Class == model.RiskQuantumVulnerable {
			out = append(out, Violation{
				Rule: "quantum-vulnerable", Asset: name, Severity: model.SeverityHigh,
				Message: fmt.Sprintf("%s is quantum-vulnerable and forbidden by policy", name), Locations: locs,
			})
		}
		if p.ForbidHardcoded && n.Risk.Class == model.RiskHardcoded {
			out = append(out, Violation{
				Rule: "hardcoded", Asset: name, Severity: model.SeverityCritical,
				Message: "hardcoded key material is forbidden by policy", Locations: locs,
			})
		}
		if p.ForbidExpired && n.Risk.Class == model.RiskExpired {
			out = append(out, Violation{
				Rule: "expired", Asset: name, Severity: model.SeverityHigh,
				Message: fmt.Sprintf("%s is expired", name), Locations: locs,
			})
		}
		if p.ForbidMisconfig && n.Risk.Class == model.RiskMisconfig {
			out = append(out, Violation{
				Rule: "misconfig", Asset: name, Severity: n.Risk.Severity,
				Message: fmt.Sprintf("%s is a misconfiguration forbidden by policy", name), Locations: locs,
			})
		}
		if hasMax && n.Risk.Class != model.RiskNone && n.Risk.Severity > maxSev {
			out = append(out, Violation{
				Rule: "max-severity", Asset: name, Severity: n.Risk.Severity,
				Message: fmt.Sprintf("%s severity %s exceeds policy maximum %s", name, n.Risk.Severity, p.MaxSeverity), Locations: locs,
			})
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return out[i].Severity > out[j].Severity
		}
		return out[i].Asset < out[j].Asset
	})
	return out
}

func locations(n graph.AssetNode) []string {
	out := make([]string, 0, len(n.Occurrences))
	for _, o := range n.Occurrences {
		loc := o.Location.File
		if o.Location.Line > 0 {
			loc = fmt.Sprintf("%s:%d", loc, o.Location.Line)
		}
		out = append(out, loc)
	}
	return out
}

func assetName(a model.Asset) string {
	if a.KeySize > 0 {
		return fmt.Sprintf("%s-%d", a.Algorithm, a.KeySize)
	}
	return a.Algorithm
}

// parseSeverity maps a policy severity word to model.Severity.
func parseSeverity(s string) (model.Severity, bool) {
	switch strings.ToLower(s) {
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
