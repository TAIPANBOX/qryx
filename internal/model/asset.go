// Package model defines the core data types of the qryx cryptography graph.
package model

// AssetType is the kind of cryptographic asset discovered.
type AssetType string

const (
	TypeAlgorithm   AssetType = "algorithm"
	TypeKey         AssetType = "key"
	TypeCertificate AssetType = "certificate"
	TypeProtocol    AssetType = "protocol"
	TypeLibrary     AssetType = "library"
)

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
// library identified in the scanned target.
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
}
