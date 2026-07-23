// Package model defines the core data types of the qryx cryptography graph.
package model

// AssetType is the kind of asset discovered. Most values are cryptographic
// assets in the strict sense (an algorithm, key, certificate, protocol, or
// crypto library); TypeAIModel is a deliberate exception (see its doc comment
// and IsCryptographic below).
type AssetType string

const (
	TypeAlgorithm   AssetType = "algorithm"
	TypeKey         AssetType = "key"
	TypeCertificate AssetType = "certificate"
	TypeProtocol    AssetType = "protocol"
	TypeLibrary     AssetType = "library"

	// TypeAIModel marks an AI/LLM usage inventory finding: an operator's own
	// code declaring, importing, or calling out to an LLM SDK/provider
	// (detected by internal/scan/detectors/aiusage.go). This is NOT a
	// cryptographic asset: it shares the finding/graph/report pipeline for
	// visibility (so an operator gets one inventory of their own code, not two
	// tools), but it is deliberately kept off the parts of that pipeline that
	// are specifically a cryptography grade (see IsCryptographic).
	TypeAIModel AssetType = "ai-usage"
)

// IsCryptographic reports whether t is itself a cryptographic artifact, as
// opposed to a non-cryptographic inventory fact (currently only TypeAIModel)
// that rides the same finding/graph pipeline for visibility.
//
// Crypto-specific reports key on this to stay honest: a CycloneDX CBOM (a
// "Cryptography Bill of Materials"), a CNSA 2.0 audit, and an NCSC PQC
// migration readiness verdict are all specifically about cryptography, so
// folding a non-cryptographic fact into them (an AI-SDK dependency rendering
// as a CycloneDX "cryptographic-asset" component, or inflating a CNSA
// "compliant" count, or flipping an NCSC discovery verdict from not-started
// to on-track) would misrepresent both the finding and the report. See
// internal/report/cbom.go's CBOM, cnsa.go's buildEntries, and ncsc.go's
// buildNCSC. The general-purpose views (human, html, the raw JSON findings,
// --save/--baseline drift) are unaffected: they show every asset type in the
// graph and are not scoped to cryptography.
//
// New asset types default to non-cryptographic (false) until deliberately
// reviewed and added to the switch below: the safer direction for a
// compliance report is to under-include, not over-include, what it grades.
func (t AssetType) IsCryptographic() bool {
	switch t {
	case TypeAlgorithm, TypeKey, TypeCertificate, TypeProtocol, TypeLibrary:
		return true
	default:
		return false
	}
}

// Primitive is what the asset is used for.
type Primitive string

const (
	PrimitiveSignature  Primitive = "signature"
	PrimitiveEncryption Primitive = "encryption"
	PrimitiveHash       Primitive = "hash"
	PrimitiveKeyExch    Primitive = "key-exchange"
	PrimitiveTLS        Primitive = "tls"
	PrimitiveUnknown    Primitive = "unknown"
)

// Asset is a single cryptographic primitive, key, certificate, protocol or
// library identified in the scanned target, or (when Type is TypeAIModel) an
// AI/LLM usage inventory fact riding the same shape for visibility; see
// AssetType.IsCryptographic for how the two are told apart downstream.
type Asset struct {
	Type      AssetType
	Algorithm string // normalized, e.g. "RSA", "AES", "SHA-1"
	KeySize   int    // bits; 0 if unknown or not applicable
	Primitive Primitive
}

// Location is where a finding was observed.
type Location struct {
	File string
	Line int // 0 if not line-specific
	// IsTest marks a location that is test code (a `_test.go`, a `testdata/`
	// tree, a `conftest.py`), as decided by scan.IsTestPath. Findings here are
	// reported, but kept out of the production inventory and out of the
	// compliance verdict: counting a fixture key as production cryptography
	// inflates the number an operator is trying to drive down, and buries the
	// findings they actually have to migrate.
	//
	// False for every source that has no filesystem path to judge (a TLS probe,
	// a cloud KMS inventory, a binary or image scan), which is the honest
	// default: those are all production surfaces.
	IsTest bool
}

// RiskClass categorizes why an asset is a concern.
type RiskClass string

const (
	RiskQuantumVulnerable RiskClass = "quantum-vulnerable"
	RiskWeak              RiskClass = "weak"
	RiskMisconfig         RiskClass = "misconfig"
	RiskExpired           RiskClass = "expired"
	RiskHardcoded         RiskClass = "hardcoded"
	RiskNone              RiskClass = "none"
)

// Severity ranks the urgency of a risk.
type Severity int

const (
	SeverityNone Severity = iota
	SeverityInfo
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityCritical:
		return "critical"
	case SeverityHigh:
		return "high"
	case SeverityMedium:
		return "medium"
	case SeverityLow:
		return "low"
	case SeverityInfo:
		return "info"
	default:
		return "none"
	}
}

// Risk is the assessment attached to a finding.
type Risk struct {
	Class    RiskClass
	Severity Severity
	Reason   string
}

// Finding is one observation: an asset at a location, with its risk and the raw
// evidence that produced it.
type Finding struct {
	Asset    Asset
	Location Location
	Evidence string
	Source   string // detector name
	Risk     Risk
	Tags     map[string]string // provider tags/labels; nil for non-cloud sources
}
