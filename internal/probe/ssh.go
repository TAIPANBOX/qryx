package probe

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/TAIPANBOX/qryx/internal/model"
)

// SSHInfo is what an SSH server announced in its identification string and its
// SSH_MSG_KEXINIT. Nothing here is negotiated: the server lists what it is
// willing to do, in its own order of preference.
type SSHInfo struct {
	Banner     string
	Kex        []string
	HostKeys   []string
	CiphersC2S []string
	CiphersS2C []string
	MACsC2S    []string
	MACsS2C    []string
	CompC2S    []string
	CompS2C    []string
}

// Every bound below exists because the server writes everything this file
// reads, and a probe pointed at a hostile host must not be the thing that
// breaks.
const (
	maxIdentLine = 255   // RFC 4253 4.2, CR LF included
	maxPreIdent  = 32    // lines a server may print before its identification
	maxPacket    = 35000 // RFC 4253 6.1: the largest total packet a peer must accept
	maxSkipped   = 16    // IGNORE and DEBUG messages tolerated before KEXINIT

	msgIgnore  = 2
	msgDebug   = 4
	msgKexInit = 20
)

var errProtocolOne = errors.New("ssh: the server speaks only protocol 1")

// SSHEndpoint connects to addr (host:port), sends qryx's identification string
// and reads the server's identification and KEXINIT. It never sends a KEXINIT
// of its own, so no key exchange starts and nothing is authenticated: this is
// the part of the protocol every server tells every client in the clear.
func SSHEndpoint(addr string, timeout time.Duration, clientVersion string) ([]model.Finding, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	if _, err := io.WriteString(conn, "SSH-2.0-qryx_"+identToken(clientVersion)+"\r\n"); err != nil {
		return nil, err
	}
	info, err := readKexInit(bufio.NewReader(conn))
	if errors.Is(err, errProtocolOne) {
		return []model.Finding{protocolOneFinding(addr, info.Banner)}, nil
	}
	if err != nil {
		return nil, err
	}
	return sshFindings(addr, info), nil
}

// identToken keeps the version usable inside an identification string, which
// allows printable ASCII without spaces.
func identToken(v string) string {
	b := []byte(v)
	for i, c := range b {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_') {
			b[i] = '_'
		}
	}
	if len(b) == 0 {
		return "dev"
	}
	return string(b)
}

// readKexInit reads the identification string, then packets until the KEXINIT,
// skipping the IGNORE and DEBUG messages a server may send first.
func readKexInit(r *bufio.Reader) (*SSHInfo, error) {
	banner, err := readIdent(r)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(banner, "SSH-2.0-") && !strings.HasPrefix(banner, "SSH-1.99-") {
		return &SSHInfo{Banner: banner}, errProtocolOne
	}
	for skipped := 0; ; skipped++ {
		if skipped > maxSkipped {
			return nil, fmt.Errorf("ssh: more than %d messages before KEXINIT", maxSkipped)
		}
		p, err := readPacket(r)
		if err != nil {
			return nil, err
		}
		switch p[0] {
		case msgIgnore, msgDebug:
			continue
		case msgKexInit:
			info, err := parseKexInit(p)
			if err != nil {
				return nil, err
			}
			info.Banner = banner
			return info, nil
		default:
			return nil, fmt.Errorf("ssh: message %d arrived before KEXINIT", p[0])
		}
	}
}

// readIdent returns the server's identification string. RFC 4253 4.2 lets a
// server print other lines first; none of them may start with "SSH-".
func readIdent(r *bufio.Reader) (string, error) {
	for i := 0; i <= maxPreIdent; i++ {
		line, err := readLine(r)
		if err != nil {
			return "", err
		}
		if !strings.HasPrefix(line, "SSH-") {
			continue
		}
		for j := 0; j < len(line); j++ {
			if line[j] < ' ' || line[j] > '~' {
				return "", fmt.Errorf("ssh: identification string carries byte 0x%02x", line[j])
			}
		}
		return line, nil
	}
	return "", fmt.Errorf("ssh: no identification string within %d lines", maxPreIdent+1)
}

func readLine(r *bufio.Reader) (string, error) {
	var b []byte
	for len(b) < maxIdentLine {
		c, err := r.ReadByte()
		if err != nil {
			return "", err
		}
		if c == '\n' {
			return strings.TrimSuffix(string(b), "\r"), nil
		}
		b = append(b, c)
	}
	return "", fmt.Errorf("ssh: a line longer than %d bytes", maxIdentLine)
}

// readPacket reads one unencrypted binary packet (RFC 4253 6) and returns its
// payload. The length is checked before anything is allocated for it.
func readPacket(r *bufio.Reader) ([]byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(hdr[:4])
	pad := uint32(hdr[4])
	if length < 6 || length > maxPacket-4 {
		return nil, fmt.Errorf("ssh: packet length %d outside 6..%d", length, maxPacket-4)
	}
	if pad < 4 || pad >= length-1 {
		return nil, fmt.Errorf("ssh: padding %d is not valid in a packet of length %d", pad, length)
	}
	body := make([]byte, length-1)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return body[:length-1-pad], nil
}

// parseKexInit decodes an SSH_MSG_KEXINIT payload (RFC 4253 7.1): the message
// byte, a 16-byte cookie, ten name-lists, a boolean and a reserved word.
func parseKexInit(p []byte) (*SSHInfo, error) {
	if len(p) < 17 || p[0] != msgKexInit {
		return nil, errors.New("ssh: not a KEXINIT")
	}
	rest := p[17:]
	var lists [10][]string
	for i := range lists {
		if len(rest) < 4 {
			return nil, fmt.Errorf("ssh: KEXINIT ends before name-list %d", i+1)
		}
		n := binary.BigEndian.Uint32(rest)
		rest = rest[4:]
		if uint64(n) > uint64(len(rest)) {
			return nil, fmt.Errorf("ssh: name-list %d claims %d bytes, %d remain", i+1, n, len(rest))
		}
		names, err := splitNames(rest[:n])
		if err != nil {
			return nil, fmt.Errorf("ssh: name-list %d: %w", i+1, err)
		}
		lists[i] = names
		rest = rest[n:]
	}
	if len(rest) < 5 {
		return nil, errors.New("ssh: KEXINIT ends before its trailer")
	}
	return &SSHInfo{
		Kex: lists[0], HostKeys: lists[1],
		CiphersC2S: lists[2], CiphersS2C: lists[3],
		MACsC2S: lists[4], MACsS2C: lists[5],
		CompC2S: lists[6], CompS2C: lists[7],
	}, nil
}

func splitNames(b []byte) ([]string, error) {
	if len(b) == 0 {
		return nil, nil
	}
	for _, c := range b {
		if c <= ' ' || c > '~' {
			return nil, fmt.Errorf("byte 0x%02x is not a name character", c)
		}
	}
	names := strings.Split(string(b), ",")
	for _, n := range names {
		if n == "" {
			return nil, errors.New("an empty name")
		}
	}
	return names, nil
}

// kexMarkers are names a server lists among its key exchanges to signal a
// protocol extension. They are not algorithms and are never reported.
var kexMarkers = map[string]bool{
	"ext-info-s":                   true,
	"ext-info-c":                   true,
	"kex-strict-s-v00@openssh.com": true,
	"kex-strict-c-v00@openssh.com": true,
}

// isPostQuantumKex reports a hybrid exchange that pairs a post-quantum KEM with
// a classical one: mlkem768x25519-sha256 (OpenSSH 9.9, its default from 10.0),
// sntrup761x25519-sha512, and the IETF draft's mlkem*nistp* names.
func isPostQuantumKex(name string) bool {
	return strings.HasPrefix(name, "mlkem") || strings.HasPrefix(name, "sntrup")
}

type sshVerdict struct {
	class  model.RiskClass
	sev    model.Severity
	prim   model.Primitive
	reason string
}

// weakSSH is what a server can still offer that a current client should not
// accept. Host key names are looked up after certificate and security-key
// decorations are stripped (see hostKeyBase).
var weakSSH = func() map[string]sshVerdict {
	m := map[string]sshVerdict{
		"diffie-hellman-group1-sha1":         {model.RiskWeak, model.SeverityHigh, model.PrimitiveKeyExch, "1024-bit Diffie-Hellman (Logjam) with SHA-1 in the exchange hash"},
		"diffie-hellman-group14-sha1":        {model.RiskWeak, model.SeverityMedium, model.PrimitiveKeyExch, "SHA-1 in the exchange hash; OpenSSH dropped it from its defaults"},
		"diffie-hellman-group-exchange-sha1": {model.RiskWeak, model.SeverityMedium, model.PrimitiveKeyExch, "SHA-1 in the exchange hash; OpenSSH dropped it from its defaults"},
		"ssh-rsa":                            {model.RiskWeak, model.SeverityMedium, model.PrimitiveSignature, "RSA signatures over SHA-1; OpenSSH turned it off by default in 8.8, and rsa-sha2-256/512 use the same key"},
		"ssh-dss":                            {model.RiskWeak, model.SeverityHigh, model.PrimitiveSignature, "DSA host keys are 1024-bit with SHA-1; OpenSSH no longer supports them"},
		"3des-cbc":                           {model.RiskWeak, model.SeverityMedium, model.PrimitiveEncryption, "3DES has a 64-bit block (Sweet32)"},
		"blowfish-cbc":                       {model.RiskWeak, model.SeverityLow, model.PrimitiveEncryption, "Blowfish has a 64-bit block (Sweet32)"},
		"cast128-cbc":                        {model.RiskWeak, model.SeverityLow, model.PrimitiveEncryption, "CAST-128 has a 64-bit block (Sweet32)"},
	}
	for _, n := range []string{"arcfour", "arcfour128", "arcfour256"} {
		m[n] = sshVerdict{model.RiskWeak, model.SeverityHigh, model.PrimitiveEncryption, "RC4 is broken"}
	}
	for _, n := range []string{"aes128-cbc", "aes192-cbc", "aes256-cbc", "rijndael-cbc@lysator.liu.se"} {
		m[n] = sshVerdict{model.RiskMisconfig, model.SeverityLow, model.PrimitiveEncryption, "CBC mode in SSH allows plaintext recovery (CVE-2008-5161); every current client has CTR and GCM"}
	}
	for _, n := range []string{"hmac-md5", "hmac-md5-96", "hmac-md5-etm@openssh.com", "hmac-md5-96-etm@openssh.com"} {
		m[n] = sshVerdict{model.RiskWeak, model.SeverityHigh, model.PrimitiveHash, "a MAC on MD5, which is broken"}
	}
	for _, n := range []string{"hmac-sha1", "hmac-sha1-96", "hmac-sha1-etm@openssh.com", "hmac-sha1-96-etm@openssh.com"} {
		m[n] = sshVerdict{model.RiskWeak, model.SeverityLow, model.PrimitiveHash, "HMAC-SHA1 is not broken as a MAC, but SHA-1 is disallowed by NIST SP 800-131A and every current client has SHA-2 MACs"}
	}
	return m
}()

// hostKeyBase strips the certificate and security-key decorations, so
// "sk-ssh-ed25519@openssh.com" and "ssh-ed25519-cert-v01@openssh.com" are both
// the Ed25519 key family they sign with.
func hostKeyBase(name string) string {
	n := strings.TrimSuffix(name, "-cert-v01@openssh.com")
	n = strings.TrimPrefix(n, "sk-")
	return strings.TrimSuffix(n, "@openssh.com")
}

// hostKeyFamily maps a host key algorithm to the key family the central
// classifier grades. Unknown names map to nothing: signal over recall.
func hostKeyFamily(base string) (string, int, bool) {
	switch {
	case base == "ssh-ed25519":
		return "Ed25519", 0, true
	case base == "rsa-sha2-256" || base == "rsa-sha2-512":
		return "RSA", 0, true
	case strings.HasPrefix(base, "ecdsa-sha2-nistp"):
		size, err := strconv.Atoi(strings.TrimPrefix(base, "ecdsa-sha2-nistp"))
		return "ECDSA", size, err == nil
	}
	return "", 0, false
}

func sshFindings(addr string, info *SSHInfo) []model.Finding {
	finding := func(t model.AssetType, algo string, size int, prim model.Primitive, evidence string) model.Finding {
		return model.Finding{
			Asset:    model.Asset{Type: t, Algorithm: algo, KeySize: size, Primitive: prim},
			Location: model.Location{File: addr},
			Evidence: evidence,
			Source:   "ssh-probe",
		}
	}
	out := []model.Finding{finding(model.TypeProtocol, "SSH", 0, model.PrimitiveSSH, info.Banner)}

	var kex []string
	for _, k := range info.Kex {
		if !kexMarkers[k] {
			kex = append(kex, k)
		}
	}
	if len(kex) > 0 {
		chosen := ""
		for _, k := range kex {
			if isPostQuantumKex(k) {
				chosen = k
				break
			}
		}
		f := finding(model.TypeAlgorithm, chosen, 0, model.PrimitiveKeyExch, "server offers key exchange "+strings.Join(kex, ", "))
		if chosen != "" {
			f.Risk = model.Risk{Class: model.RiskNone, Severity: model.SeverityNone}
		} else {
			f.Asset.Algorithm = kex[0]
			f.Risk = model.Risk{Class: model.RiskQuantumVulnerable, Severity: model.SeverityHigh,
				Reason: "no post-quantum hybrid key exchange is offered (mlkem768x25519-sha256 or sntrup761x25519-sha512): every session key is agreed with classical (EC)DH alone, so a session recorded today can be decrypted later"}
		}
		out = append(out, f)
	}

	// One finding per weak name, however many lists offer it.
	weak := map[string]bool{}
	for _, list := range [][]string{info.Kex, info.CiphersC2S, info.CiphersS2C, info.MACsC2S, info.MACsS2C} {
		for _, n := range list {
			if _, ok := weakSSH[n]; ok {
				weak[n] = true
			}
		}
	}
	families := map[string][]string{}
	for _, n := range info.HostKeys {
		base := hostKeyBase(n)
		if _, ok := weakSSH[base]; ok {
			weak[base] = true
			continue
		}
		if algo, size, ok := hostKeyFamily(base); ok {
			key := algo + "/" + strconv.Itoa(size)
			families[key] = append(families[key], n)
		}
	}
	for _, n := range sortedKeys(weak) {
		v := weakSSH[n]
		f := finding(model.TypeAlgorithm, n, 0, v.prim, "server offers "+n)
		f.Risk = model.Risk{Class: v.class, Severity: v.sev, Reason: v.reason}
		out = append(out, f)
	}
	for _, key := range sortedKeys(families) {
		algo, sizeStr, _ := strings.Cut(key, "/")
		size, _ := strconv.Atoi(sizeStr)
		// Risk left empty: graded by risk.Apply like any other key family.
		out = append(out, finding(model.TypeAlgorithm, algo, size, model.PrimitiveSignature, "server offers host key "+strings.Join(families[key], ", ")))
	}
	return out
}

func protocolOneFinding(addr, banner string) model.Finding {
	return model.Finding{
		Asset:    model.Asset{Type: model.TypeProtocol, Algorithm: "SSH", Primitive: model.PrimitiveSSH},
		Location: model.Location{File: addr},
		Evidence: banner,
		Source:   "ssh-probe",
		Risk: model.Risk{Class: model.RiskMisconfig, Severity: model.SeverityCritical,
			Reason: "the server speaks only SSH protocol 1, which is broken: nothing it agrees can be trusted"},
	}
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
