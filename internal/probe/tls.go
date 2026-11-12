// Package probe actively connects to network endpoints to discover the
// cryptography they negotiate: TLS version, cipher suite, key exchange group
// and certificate chain, and what an SSH server offers in its KEXINIT. Unlike
// the static detectors it observes real deployed crypto.
//
// It probes only the explicit targets it is given: no port ranges, no host
// discovery. Callers must be authorized to connect to the targets.
package probe

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"

	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/x509util"
)

// Endpoint connects to addr (host:port), completes a TLS handshake, and returns
// findings for the negotiated version, cipher suite, and leaf certificate.
func Endpoint(addr string, timeout time.Duration) ([]model.Finding, error) {
	// This is a posture scanner, so the Config is deliberately permissive:
	//   - InsecureSkipVerify: we inspect the presented chain and derive
	//     validation findings ourselves; a self-signed/expired cert must not
	//     abort the dial.
	//   - MinVersion TLS 1.0: we must be willing to negotiate down to observe
	//     and report a legacy server. The default (1.2) would refuse to connect
	//     to exactly the misconfigured endpoints we exist to flag.
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: timeout},
		"tcp", addr,
		&tls.Config{
			InsecureSkipVerify: true, // #nosec G402 -- inspection, not trust; see comment above
			MinVersion:         tls.VersionTLS10,
		},
	)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	var out []model.Finding

	out = append(out, versionFinding(addr, state.Version))
	if cf, ok := cipherFinding(addr, state.CipherSuite); ok {
		out = append(out, cf)
	}
	if kf, ok := kexGroupFinding(addr, state.CurveID); ok {
		out = append(out, kf)
	}
	if len(state.PeerCertificates) > 0 {
		out = append(out, certFindings(addr, state.PeerCertificates[0])...)
	}
	return out, nil
}

// kexGroups names a key exchange group by its IANA code point. It does not ask
// the toolchain: a hybrid this Go release cannot name would print as
// "CurveID(4587)" and read as classical, which is the one wrong answer a
// post-quantum inventory cannot give.
var kexGroups = map[tls.CurveID]struct {
	name   string
	hybrid bool
}{
	0x11EC: {"X25519MLKEM768", true},
	0x11EB: {"SecP256r1MLKEM768", true},
	0x11ED: {"SecP384r1MLKEM1024", true},
	0x001D: {"X25519", false},
	0x001E: {"X448", false},
	0x0017: {"P-256", false},
	0x0018: {"P-384", false},
	0x0019: {"P-521", false},
}

// kexGroupFinding reports the group the session key was agreed with. It sets
// its own verdict: the central classifier knows no "X25519" and would grade a
// classical group as carrying no risk.
func kexGroupFinding(addr string, id tls.CurveID) (model.Finding, bool) {
	if id == 0 {
		return model.Finding{}, false
	}
	f := model.Finding{
		Asset:    model.Asset{Type: model.TypeAlgorithm, Primitive: model.PrimitiveKeyExch},
		Location: model.Location{File: addr},
		Source:   "tls-probe",
	}
	g, known := kexGroups[id]
	switch {
	case !known:
		f.Asset.Algorithm = fmt.Sprintf("group 0x%04x", uint16(id))
		f.Evidence = "session key agreed with a group qryx has no entry for"
	case g.hybrid:
		f.Asset.Algorithm = g.name
		f.Evidence = "session key agreed with the hybrid post-quantum group " + g.name
		f.Risk = model.Risk{Class: model.RiskNone, Severity: model.SeverityNone}
	default:
		f.Asset.Algorithm = g.name
		f.Evidence = "session key agreed with " + g.name + " alone"
		f.Risk = model.Risk{Class: model.RiskQuantumVulnerable, Severity: model.SeverityHigh,
			Reason: "classical elliptic-curve key agreement is broken by Shor, so traffic recorded today can be decrypted later; qryx offered X25519MLKEM768 first and the server did not take it"}
	}
	return f, true
}

// insecureSuites is the set of cipher-suite IDs the standard library considers
// insecure, looked up once.
var insecureSuites = func() map[uint16]string {
	m := map[uint16]string{}
	for _, s := range tls.InsecureCipherSuites() {
		m[s.ID] = s.Name
	}
	return m
}()

func versionFinding(addr string, v uint16) model.Finding {
	f := model.Finding{
		Asset:    model.Asset{Type: model.TypeProtocol, Algorithm: "TLS", Primitive: model.PrimitiveTLS},
		Location: model.Location{File: addr},
		Evidence: tls.VersionName(v),
		Source:   "tls-probe",
	}
	switch v {
	case tls.VersionTLS10:
		f.Risk = model.Risk{Class: model.RiskMisconfig, Severity: model.SeverityHigh, Reason: "TLS 1.0 is deprecated"}
	case tls.VersionTLS11:
		f.Risk = model.Risk{Class: model.RiskMisconfig, Severity: model.SeverityHigh, Reason: "TLS 1.1 is deprecated"}
	}
	return f
}

func cipherFinding(addr string, id uint16) (model.Finding, bool) {
	name, weak := insecureSuites[id]
	if !weak {
		return model.Finding{}, false
	}
	return model.Finding{
		Asset:    model.Asset{Type: model.TypeProtocol, Algorithm: "TLS", Primitive: model.PrimitiveTLS},
		Location: model.Location{File: addr},
		Evidence: name,
		Source:   "tls-probe",
		Risk:     model.Risk{Class: model.RiskWeak, Severity: model.SeverityMedium, Reason: "negotiated an insecure cipher suite"},
	}, true
}

func certFindings(addr string, cert *x509.Certificate) []model.Finding {
	var out []model.Finding
	algo, size, prim := x509util.PublicKeyInfo(cert)
	if algo != "" {
		// Risk left empty: classified uniformly by risk.Apply (RSA -> quantum-
		// vulnerable, RSA<2048 -> weak, etc.).
		out = append(out, model.Finding{
			Asset:    model.Asset{Type: model.TypeCertificate, Algorithm: algo, KeySize: size, Primitive: prim},
			Location: model.Location{File: addr},
			Evidence: fmt.Sprintf("certificate %q, %s key", cert.Subject.CommonName, algo),
			Source:   "tls-probe",
		})
	}
	if cert.NotAfter.Before(time.Now()) {
		out = append(out, model.Finding{
			Asset:    model.Asset{Type: model.TypeCertificate, Algorithm: algo, KeySize: size, Primitive: prim},
			Location: model.Location{File: addr},
			Evidence: fmt.Sprintf("certificate %q expired %s", cert.Subject.CommonName, cert.NotAfter.Format("2006-01-02")),
			Source:   "tls-probe",
			Risk:     model.Risk{Class: model.RiskExpired, Severity: model.SeverityHigh, Reason: "certificate is past its NotAfter date"},
		})
	}
	return out
}
