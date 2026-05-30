// Package probe actively connects to network endpoints to discover the
// cryptography they negotiate: TLS version, cipher suite, and certificate
// chain. Unlike the static detectors it observes real deployed crypto.
//
// It probes only the explicit targets it is given — no port ranges, no host
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
		&tls.Config{ //nolint:gosec // inspection, not trust; see comment above
			InsecureSkipVerify: true,
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
	if len(state.PeerCertificates) > 0 {
		out = append(out, certFindings(addr, state.PeerCertificates[0])...)
	}
	return out, nil
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
