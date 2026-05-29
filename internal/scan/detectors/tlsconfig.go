package detectors

import (
	"path/filepath"
	"regexp"

	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/scan"
)

var (
	// Go tls.Config with a weak minimum version.
	reGoTLS10 = regexp.MustCompile(`MinVersion:\s*tls\.VersionTLS10`)
	reGoTLS11 = regexp.MustCompile(`MinVersion:\s*tls\.VersionTLS11`)
	reGoSSL30 = regexp.MustCompile(`tls\.VersionSSL30`)

	// nginx / apache style directives enabling legacy protocols.
	reConfTLS10 = regexp.MustCompile(`(?i)(ssl_protocols|SSLProtocol)[^\n;]*TLSv1(\.0)?\b`)
	reConfTLS11 = regexp.MustCompile(`(?i)(ssl_protocols|SSLProtocol)[^\n;]*TLSv1\.1\b`)
	reConfSSL3  = regexp.MustCompile(`(?i)(ssl_protocols|SSLProtocol)[^\n;]*SSLv3\b`)
)

// TLSConfig flags insecure TLS protocol configuration in code and server config.
type TLSConfig struct{}

func NewTLSConfig() *TLSConfig { return &TLSConfig{} }

func (t *TLSConfig) Name() string { return "tlsconfig" }

func (t *TLSConfig) Wants(path string) bool {
	switch filepath.Ext(path) {
	case ".go":
		return true
	case ".conf":
		return true
	}
	base := filepath.Base(path)
	return base == "nginx.conf" || base == "httpd.conf"
}

func (t *TLSConfig) Detect(f scan.File) []model.Finding {
	checks := []struct {
		re     *regexp.Regexp
		proto  string
		reason string
	}{
		{reGoSSL30, "SSL 3.0", "SSL 3.0 is broken (POODLE)"},
		{reConfSSL3, "SSL 3.0", "SSL 3.0 is broken (POODLE)"},
		{reGoTLS10, "TLS 1.0", "TLS 1.0 is deprecated"},
		{reConfTLS10, "TLS 1.0", "TLS 1.0 is deprecated"},
		{reGoTLS11, "TLS 1.1", "TLS 1.1 is deprecated"},
		{reConfTLS11, "TLS 1.1", "TLS 1.1 is deprecated"},
	}

	var out []model.Finding
	for _, c := range checks {
		for _, loc := range c.re.FindAllIndex(f.Content, -1) {
			out = append(out, model.Finding{
				Asset: model.Asset{
					Type:      model.TypeProtocol,
					Algorithm: c.proto,
					Primitive: model.PrimitiveTLS,
				},
				Location: model.Location{File: f.Path, Line: lineNumber(f.Content, loc[0])},
				Evidence: string(f.Content[loc[0]:loc[1]]),
				Source:   t.Name(),
				// Misconfig risk is asserted here because the classifier keys on
				// algorithms, not protocol-config context.
				Risk: model.Risk{
					Class:    model.RiskMisconfig,
					Severity: model.SeverityMedium,
					Reason:   c.reason,
				},
			})
		}
	}
	return out
}
