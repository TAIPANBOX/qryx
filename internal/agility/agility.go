// Package agility scores how easily a cryptographic asset can be migrated and
// recommends a post-quantum or strong replacement target. It is pure and
// reusable: the migration-plan report and (later) PR remediation both consume it.
package agility

import (
	"fmt"
	"strings"

	"github.com/TAIPANBOX/qryx/internal/graph"
	"github.com/TAIPANBOX/qryx/internal/model"
)

// Level is how easily an asset can be swapped.
type Level string

const (
	High   Level = "high"   // managed key store — rotate via API/console
	Medium Level = "medium" // config / cert / dependency — config change
	Low    Level = "low"    // code or binary — code change + redeploy
)

// Assessment is the agility verdict for one asset.
type Assessment struct {
	Target    string // recommended migration target
	Agility   Level
	Effort    string
	Rationale string
}

// sourceAgility maps a finding Source to how agile assets from it are.
var sourceAgility = map[string]Level{
	"aws-kms":        High,
	"gcp-kms":        High,
	"azure-keyvault": High,

	"aws-acm":   Medium,
	"tls-probe": Medium,
	"tlsconfig": Medium,
	"certfile":  Medium,
	"deps":      Medium,

	"goast":      Low,
	"cryptocall": Low,
	"hardcoded":  Low,
	"binary":     Low,
}

// levelRank orders agility for "least agile wins" and for sorting (higher rank
// = more agile).
var levelRank = map[Level]int{Low: 0, Medium: 1, High: 2}

// Assess returns a migration assessment for a node, or ok=false when the asset
// already meets the bar (no migration needed).
func Assess(n graph.AssetNode) (Assessment, bool) {
	tgt := target(n.Asset)
	if tgt == "" {
		return Assessment{}, false
	}

	level, sources := dominantAgility(n)
	occ := len(n.Occurrences)

	a := Assessment{
		Target:    tgt,
		Agility:   level,
		Effort:    effortNote(level, occ, sources),
		Rationale: rationale(n.Asset),
	}
	return a, true
}

// dominantAgility returns the least-agile (most conservative) level across all
// occurrence sources, plus the distinct sources seen.
func dominantAgility(n graph.AssetNode) (Level, []string) {
	level := High
	seen := map[string]bool{}
	var sources []string
	found := false
	for _, o := range n.Occurrences {
		l, ok := sourceAgility[o.Source]
		if !ok {
			continue
		}
		if !seen[o.Source] {
			seen[o.Source] = true
			sources = append(sources, o.Source)
		}
		if !found || levelRank[l] < levelRank[level] {
			level = l
			found = true
		}
	}
	if !found {
		return Low, sources // unknown source → assume hardest
	}
	return level, sources
}

func effortNote(level Level, occ int, sources []string) string {
	src := strings.Join(sources, ", ")
	switch level {
	case High:
		return fmt.Sprintf("rotate via managed key store (%s); %d occurrence(s)", src, occ)
	case Medium:
		return fmt.Sprintf("config/dependency change (%s); %d occurrence(s)", src, occ)
	default:
		return fmt.Sprintf("code change + redeploy (%s); %d occurrence(s)", src, occ)
	}
}

// target returns the recommended migration target for an asset. Empty means no
// migration needed.
func target(a model.Asset) string {
	algo := strings.ToUpper(strings.ReplaceAll(a.Algorithm, "-", ""))

	switch algo {
	case "RSA":
		if dominantPrimitive(a) == model.PrimitiveSignature {
			return "ML-DSA (FIPS 204)"
		}
		return "ML-KEM (FIPS 203)"
	case "ECDSA", "DSA", "ED25519":
		return "ML-DSA (FIPS 204)"
	case "ECDH", "DH", "ECC":
		return "ML-KEM (FIPS 203)"
	case "MD5", "SHA1":
		return "SHA-256 / SHA-384"
	case "DES", "3DES", "RC4":
		return "AES-256-GCM"
	case "AES":
		// Only sub-256 AES needs migration.
		if a.KeySize > 0 && a.KeySize < 256 {
			return "AES-256-GCM"
		}
		return ""
	default:
		return ""
	}
}

func dominantPrimitive(a model.Asset) model.Primitive {
	if a.Primitive != "" && a.Primitive != model.PrimitiveUnknown {
		return a.Primitive
	}
	return model.PrimitiveSignature // RSA/EC default lean
}

func rationale(a model.Asset) string {
	algo := strings.ToUpper(strings.ReplaceAll(a.Algorithm, "-", ""))
	switch algo {
	case "RSA":
		if a.KeySize > 0 && a.KeySize < 2048 {
			return fmt.Sprintf("RSA-%d is weak today and quantum-vulnerable; if PQC is not yet viable, raise to RSA-3072 as an interim step before migrating to a lattice scheme", a.KeySize)
		}
		return "RSA is quantum-vulnerable (Shor); migrate to a NIST PQC algorithm"
	case "ECDSA", "DSA", "ECDH", "DH", "ECC", "ED25519":
		return fmt.Sprintf("%s relies on discrete-log/ECDLP hardness, broken by a quantum computer", a.Algorithm)
	case "MD5", "SHA1":
		return fmt.Sprintf("%s is collision-broken; replace with a SHA-2 family hash", a.Algorithm)
	case "DES", "3DES", "RC4":
		return fmt.Sprintf("%s is a broken/deprecated cipher; replace with an authenticated AES mode", a.Algorithm)
	case "AES":
		return "AES below 256 bits is below the CNSA 2.0 minimum"
	default:
		return "asset requires migration"
	}
}
