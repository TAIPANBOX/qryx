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
//
// Every source in the tree needs a row. A missing one is not a neutral
// default: the asset silently scores Low and its source name never reaches the
// effort note. sources_test.go holds both halves of that list (the detector
// registry, and the string literals the connectors stamp on findings) against
// this map, because this is a second copy of a list kept by hand, and it has
// already drifted once.
var sourceAgility = map[string]Level{
	"aws-kms":        High,
	"gcp-kms":        High,
	"azure-keyvault": High,

	"aws-acm":   Medium,
	"tls-probe": Medium,
	"tlsconfig": Medium,
	"certfile":  Medium,
	"deps":      Medium,
	// A key declared in HCL is migrated by editing an argument and running
	// `apply`, which is this row. The same key read back through the AWS, GCP
	// or Azure connector is High, so scoring the declaration Low also made one
	// physical key's difficulty depend on which connector happened to see it.
	"terraform": Medium,
	// A passport or event document is configuration. No asset agentstack
	// currently emits (X509, enclave-key, OIDC, no-attestation, SHA-256,
	// no-hash-chain) is one target() maps, so this row is unexercised today
	// and is here to keep the lists reconciled.
	"agentstack": Medium,

	"goast":      Low,
	"cryptocall": Low,
	"rust":       Low,
	"hardcoded":  Low,
	"binary":     Low,
	// aiusage emits model.TypeAIModel carrying a provider or model label,
	// which target() never maps, so this row is unexercised too. Low is the
	// conservative reading of a detector that reads source and manifests.
	"aiusage": Low,
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
//
// A source with no row in sourceAgility is still named, and still counts as
// Low. Skipping it dropped it from both answers at once: the level came back
// as though the occurrence did not exist, and the effort note said nothing
// about where the asset was seen. "Assume hardest" also has to hold whatever
// the occurrence's company is, or the same unrankable sighting would mean
// Low on its own and nothing at all beside a KMS.
func dominantAgility(n graph.AssetNode) (Level, []string) {
	level := Low // the answer for a node with no occurrences at all
	seen := map[string]bool{}
	var sources []string
	first := true
	for _, o := range n.Occurrences {
		if o.Source != "" && !seen[o.Source] {
			seen[o.Source] = true
			sources = append(sources, o.Source)
		}
		l, ok := sourceAgility[o.Source]
		if !ok {
			l = Low
		}
		if first || levelRank[l] < levelRank[level] {
			level = l
			first = false
		}
	}
	return level, sources
}

func effortNote(level Level, occ int, sources []string) string {
	var src string
	if len(sources) > 0 {
		src = " (" + strings.Join(sources, ", ") + ")"
	}
	switch level {
	case High:
		return fmt.Sprintf("rotate via managed key store%s; %d occurrence(s)", src, occ)
	case Medium:
		return fmt.Sprintf("config/dependency change%s; %d occurrence(s)", src, occ)
	default:
		return fmt.Sprintf("code change + redeploy%s; %d occurrence(s)", src, occ)
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
