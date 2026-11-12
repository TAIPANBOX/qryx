package probe

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"math/rand"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/risk"
)

// openssh10 is the shape of what a stock OpenSSH 10 server announces: a hybrid
// post-quantum key exchange first, the strict-kex and ext-info markers last.
var openssh10 = [10][]string{
	{"mlkem768x25519-sha256", "sntrup761x25519-sha512", "sntrup761x25519-sha512@openssh.com", "curve25519-sha256", "curve25519-sha256@libssh.org", "ecdh-sha2-nistp256", "diffie-hellman-group-exchange-sha256", "diffie-hellman-group16-sha512", "diffie-hellman-group14-sha256", "ext-info-s", "kex-strict-s-v00@openssh.com"},
	{"rsa-sha2-512", "rsa-sha2-256", "ecdsa-sha2-nistp256", "ssh-ed25519"},
	{"chacha20-poly1305@openssh.com", "aes128-ctr", "aes256-ctr", "aes128-gcm@openssh.com", "aes256-gcm@openssh.com"},
	{"chacha20-poly1305@openssh.com", "aes128-ctr", "aes256-ctr", "aes128-gcm@openssh.com", "aes256-gcm@openssh.com"},
	{"umac-64-etm@openssh.com", "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com", "hmac-sha2-256", "hmac-sha2-512"},
	{"umac-64-etm@openssh.com", "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com", "hmac-sha2-256", "hmac-sha2-512"},
	{"none", "zlib@openssh.com"},
	{"none", "zlib@openssh.com"},
	nil,
	nil,
}

func sshString(s string) []byte {
	b := make([]byte, 4, 4+len(s))
	binary.BigEndian.PutUint32(b, uint32(len(s)))
	return append(b, s...)
}

func kexInitPayload(lists [10][]string) []byte {
	p := append([]byte{20}, bytes.Repeat([]byte{0xA5}, 16)...)
	for _, l := range lists {
		p = append(p, sshString(strings.Join(l, ","))...)
	}
	return append(p, 0, 0, 0, 0, 0) // first_kex_packet_follows, reserved
}

// sshPacket frames a payload as an unencrypted binary packet (RFC 4253 6).
func sshPacket(payload []byte) []byte {
	pad := 8 - (5+len(payload))%8
	if pad < 4 {
		pad += 8
	}
	b := make([]byte, 4, 5+len(payload)+pad)
	binary.BigEndian.PutUint32(b, uint32(1+len(payload)+pad))
	b = append(b, byte(pad))
	b = append(b, payload...)
	return append(b, make([]byte, pad)...)
}

func infoWith(lists [10][]string) *SSHInfo {
	return &SSHInfo{Banner: "SSH-2.0-test", Kex: lists[0], HostKeys: lists[1], CiphersC2S: lists[2], CiphersS2C: lists[3], MACsC2S: lists[4], MACsS2C: lists[5], CompC2S: lists[6], CompS2C: lists[7]}
}

func byAlgorithm(fs []model.Finding, algo string) []model.Finding {
	var out []model.Finding
	for _, f := range fs {
		if f.Asset.Algorithm == algo {
			out = append(out, f)
		}
	}
	return out
}

func keyExchange(t *testing.T, fs []model.Finding) model.Finding {
	t.Helper()
	var kex []model.Finding
	for _, f := range fs {
		if f.Asset.Primitive == model.PrimitiveKeyExch && f.Risk.Class != model.RiskWeak {
			kex = append(kex, f)
		}
	}
	if len(kex) != 1 {
		t.Fatalf("want exactly one key-exchange verdict, got %d: %+v", len(kex), kex)
	}
	return kex[0]
}

func TestParseKexInitReadsTheServersLists(t *testing.T) {
	info, err := parseKexInit(kexInitPayload(openssh10))
	if err != nil {
		t.Fatal(err)
	}
	got := [][]string{info.Kex, info.HostKeys, info.CiphersC2S, info.CiphersS2C, info.MACsC2S, info.MACsS2C, info.CompC2S, info.CompS2C}
	for i, g := range got {
		if strings.Join(g, ",") != strings.Join(openssh10[i], ",") {
			t.Errorf("list %d: got %q, want %q", i, g, openssh10[i])
		}
	}
}

// A server that offers a hybrid post-quantum key exchange gets it from any
// client that asks: a recorded session cannot be decrypted later.
func TestSSHFindingsPostQuantumKexOffered(t *testing.T) {
	fs := sshFindings("router:22", infoWith(openssh10))
	k := keyExchange(t, fs)
	if k.Asset.Algorithm != "mlkem768x25519-sha256" || k.Risk.Class != model.RiskNone {
		t.Fatalf("key exchange %q risk %q, want mlkem768x25519-sha256 with no risk", k.Asset.Algorithm, k.Risk.Class)
	}
	if k.Source != "ssh-probe" || k.Location.File != "router:22" {
		t.Fatalf("source %q location %q", k.Source, k.Location.File)
	}
	for _, marker := range []string{"ext-info-s", "kex-strict-s-v00@openssh.com"} {
		if len(byAlgorithm(fs, marker)) != 0 {
			t.Errorf("%s is a protocol marker, not an algorithm, and was reported", marker)
		}
	}
	for _, f := range fs {
		if f.Risk.Class == model.RiskWeak || f.Risk.Class == model.RiskMisconfig {
			t.Errorf("a stock OpenSSH 10 offer was flagged: %s %s", f.Asset.Algorithm, f.Risk.Reason)
		}
	}
}

// Classical (EC)DH alone is broken by Shor: the session key of a recorded
// session can be recovered later. The verdict names the server's own first
// choice, and a marker listed first is never mistaken for that choice.
func TestSSHFindingsWithoutPostQuantumKexIsQuantumVulnerable(t *testing.T) {
	lists := openssh10
	lists[0] = []string{"kex-strict-s-v00@openssh.com", "curve25519-sha256", "ecdh-sha2-nistp256", "diffie-hellman-group14-sha256"}
	k := keyExchange(t, sshFindings("router:22", infoWith(lists)))
	if k.Asset.Algorithm != "curve25519-sha256" {
		t.Fatalf("named %q, want the server's first real choice curve25519-sha256", k.Asset.Algorithm)
	}
	if k.Risk.Class != model.RiskQuantumVulnerable || k.Risk.Severity != model.SeverityHigh {
		t.Fatalf("risk %q/%v, want quantum-vulnerable/high", k.Risk.Class, k.Risk.Severity)
	}
	if !strings.Contains(k.Risk.Reason, "post-quantum") {
		t.Fatalf("reason %q does not say what is missing", k.Risk.Reason)
	}
}

func TestSSHFindingsFlagWeakOfferedAlgorithms(t *testing.T) {
	lists := [10][]string{
		{"curve25519-sha256", "diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1"},
		{"ssh-rsa", "ssh-dss", "ssh-ed25519"},
		{"aes128-ctr", "3des-cbc", "arcfour256", "blowfish-cbc", "aes256-cbc"},
		{"aes128-ctr", "3des-cbc"},
		{"hmac-sha2-256", "hmac-md5", "hmac-sha1-96"},
		{"hmac-sha2-256", "hmac-md5"},
		{"none"}, {"none"}, nil, nil,
	}
	fs := sshFindings("old:22", infoWith(lists))
	want := []struct {
		algo  string
		class model.RiskClass
		sev   model.Severity
	}{
		{"diffie-hellman-group1-sha1", model.RiskWeak, model.SeverityHigh},
		{"diffie-hellman-group14-sha1", model.RiskWeak, model.SeverityMedium},
		{"diffie-hellman-group-exchange-sha1", model.RiskWeak, model.SeverityMedium},
		{"ssh-rsa", model.RiskWeak, model.SeverityMedium},
		{"ssh-dss", model.RiskWeak, model.SeverityHigh},
		{"3des-cbc", model.RiskWeak, model.SeverityMedium},
		{"arcfour256", model.RiskWeak, model.SeverityHigh},
		{"blowfish-cbc", model.RiskWeak, model.SeverityLow},
		{"aes256-cbc", model.RiskMisconfig, model.SeverityLow},
		{"hmac-md5", model.RiskWeak, model.SeverityHigh},
		{"hmac-sha1-96", model.RiskWeak, model.SeverityLow},
	}
	for _, w := range want {
		got := byAlgorithm(fs, w.algo)
		if len(got) != 1 {
			t.Errorf("%s: %d findings, want one (offered in both directions counts once)", w.algo, len(got))
			continue
		}
		if got[0].Risk.Class != w.class || got[0].Risk.Severity != w.sev {
			t.Errorf("%s: %q/%v, want %q/%v", w.algo, got[0].Risk.Class, got[0].Risk.Severity, w.class, w.sev)
		}
		if got[0].Risk.Reason == "" || !strings.Contains(got[0].Evidence, "offers") {
			t.Errorf("%s: reason %q evidence %q", w.algo, got[0].Risk.Reason, got[0].Evidence)
		}
	}
	for _, fine := range []string{"aes128-ctr", "hmac-sha2-256"} {
		if len(byAlgorithm(fs, fine)) != 0 {
			t.Errorf("%s is sound and was flagged", fine)
		}
	}
}

// Host key algorithms carry no verdict of their own: the central classifier
// grades the key family, as it does for a certificate read by the TLS probe.
func TestSSHHostKeysAreClassifiedCentrally(t *testing.T) {
	lists := openssh10
	lists[1] = []string{"rsa-sha2-512", "rsa-sha2-256", "ecdsa-sha2-nistp384", "ssh-ed25519", "sk-ssh-ed25519@openssh.com", "ssh-ed25519-cert-v01@openssh.com", "made-up-key@example.com"}
	fs := risk.Apply(sshFindings("router:22", infoWith(lists)))
	var sig []model.Finding
	for _, f := range fs {
		if f.Asset.Primitive == model.PrimitiveSignature {
			sig = append(sig, f)
		}
	}
	want := map[string]struct {
		size  int
		class model.RiskClass
		sev   model.Severity
	}{
		"RSA":     {0, model.RiskQuantumVulnerable, model.SeverityHigh},
		"ECDSA":   {384, model.RiskQuantumVulnerable, model.SeverityHigh},
		"Ed25519": {0, model.RiskQuantumVulnerable, model.SeverityMedium},
	}
	if len(sig) != len(want) {
		t.Fatalf("got %d host key findings, want one per key family (%d): %+v", len(sig), len(want), sig)
	}
	for _, f := range sig {
		w, ok := want[f.Asset.Algorithm]
		if !ok {
			t.Errorf("unexpected host key finding %q", f.Asset.Algorithm)
			continue
		}
		if f.Asset.KeySize != w.size || f.Risk.Class != w.class || f.Risk.Severity != w.sev {
			t.Errorf("%s: size %d risk %q/%v, want %d %q/%v", f.Asset.Algorithm, f.Asset.KeySize, f.Risk.Class, f.Risk.Severity, w.size, w.class, w.sev)
		}
	}
}

// fakeSSHServer accepts one connection, reads the client's identification line,
// then writes the given bytes. The line the client sent arrives on the channel.
func fakeSSHServer(t *testing.T, reply []byte) (string, <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		line, _ := bufio.NewReader(c).ReadString('\n')
		got <- line
		_, _ = c.Write(reply)
		time.Sleep(200 * time.Millisecond)
	}()
	return ln.Addr().String(), got
}

func TestSSHEndpointReadsALiveServer(t *testing.T) {
	var reply []byte
	reply = append(reply, "a line a server may print first\r\nSSH-2.0-OpenSSH_10.0 Debian-1\r\n"...)
	reply = append(reply, sshPacket(append([]byte{2}, sshString("ignore me")...))...)
	reply = append(reply, sshPacket(kexInitPayload(openssh10))...)
	addr, sent := fakeSSHServer(t, reply)

	fs, err := SSHEndpoint(addr, 2*time.Second, "test")
	if err != nil {
		t.Fatal(err)
	}
	if line := <-sent; line != "SSH-2.0-qryx_test\r\n" {
		t.Fatalf("client identified itself as %q", line)
	}
	var proto []model.Finding
	for _, f := range fs {
		if f.Asset.Type == model.TypeProtocol {
			proto = append(proto, f)
		}
	}
	if len(proto) != 1 || proto[0].Asset.Algorithm != "SSH" || proto[0].Asset.Primitive != model.PrimitiveSSH || !strings.Contains(proto[0].Evidence, "SSH-2.0-OpenSSH_10.0 Debian-1") {
		t.Fatalf("protocol finding %+v", proto)
	}
	if k := keyExchange(t, fs); k.Asset.Algorithm != "mlkem768x25519-sha256" {
		t.Fatalf("key exchange %q", k.Asset.Algorithm)
	}
}

func TestSSHEndpointReportsProtocolOne(t *testing.T) {
	addr, _ := fakeSSHServer(t, []byte("SSH-1.5-ancient\r\n"))
	fs, err := SSHEndpoint(addr, 2*time.Second, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].Asset.Type != model.TypeProtocol || fs[0].Risk.Class != model.RiskMisconfig || fs[0].Risk.Severity != model.SeverityCritical {
		t.Fatalf("an SSH-1-only server: %+v", fs)
	}
}

// Everything after the TCP handshake is written by the server, so every length
// and every byte is hostile until checked. Each case must end in an error, not
// a panic, a huge allocation or a wait past the deadline. The control case must
// parse, or a reader that refuses everything would pass this table.
func TestSSHProbeSurvivesHostileBytes(t *testing.T) {
	ident := "SSH-2.0-hostile\r\n"
	valid := sshPacket(kexInitPayload(openssh10))
	frame := func(length uint32, pad byte, body []byte) []byte {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, length)
		return append(append(b, pad), body...)
	}
	kexWith := func(mut func(p []byte) []byte) []byte { return sshPacket(mut(kexInitPayload(openssh10))) }
	nameListAt := 17 // after the message byte and the cookie

	cases := []struct {
		name string
		in   []byte
		ok   bool
	}{
		{"control: a well-formed server", append([]byte(ident), valid...), true},
		{"identification line past 255 bytes", []byte(strings.Repeat("S", 300)), false},
		{"endless lines before the identification", []byte(strings.Repeat("hello\r\n", 100)), false},
		{"not an SSH server", []byte("HTTP/1.1 400 Bad Request\r\n\r\n"), false},
		{"packet length 0xFFFFFFFF", append([]byte(ident), frame(0xFFFFFFFF, 4, nil)...), false},
		{"packet length zero", append([]byte(ident), frame(0, 0, nil)...), false},
		{"padding as long as the packet", append([]byte(ident), frame(16, 16, make([]byte, 15))...), false},
		{"padding under four bytes", append([]byte(ident), frame(16, 2, make([]byte, 15))...), false},
		{"stream ends inside a packet", append([]byte(ident), valid[:len(valid)/2]...), false},
		{"a message that is not KEXINIT", append([]byte(ident), sshPacket([]byte{21})...), false},
		{"KEXINIT shorter than its cookie", append([]byte(ident), sshPacket([]byte{20, 1, 2, 3})...), false},
		{"name-list longer than the payload", append([]byte(ident), kexWith(func(p []byte) []byte {
			binary.BigEndian.PutUint32(p[nameListAt:], 1<<30)
			return p
		})...), false},
		{"control byte inside a name", append([]byte(ident), kexWith(func(p []byte) []byte {
			p[nameListAt+4] = 0
			return p
		})...), false},
		{"empty name between commas", append([]byte(ident), sshPacket(kexInitPayload([10][]string{{"curve25519-sha256", "", "x"}}))...), false},
		{"KEXINIT without its trailer", append([]byte(ident), kexWith(func(p []byte) []byte { return p[:len(p)-5] })...), false},
		{"ignore messages without end", append([]byte(ident), bytes.Repeat(sshPacket([]byte{2, 0, 0, 0, 0}), 100)...), false},
	}
	for _, c := range cases {
		start := time.Now()
		info, err := readKexInit(bufio.NewReader(bytes.NewReader(c.in)))
		if c.ok && (err != nil || info == nil) {
			t.Errorf("%s: %v", c.name, err)
		}
		if !c.ok && err == nil {
			t.Errorf("%s: accepted, info %+v", c.name, info)
		}
		if time.Since(start) > time.Second {
			t.Errorf("%s: took %v", c.name, time.Since(start))
		}
	}
}

// 200 seeded mutations of a real KEXINIT. Half flip only cookie bytes, which a
// correct parser must accept; the rest flip or cut anywhere, and whatever is
// accepted must still be lists of printable, non-empty names.
func TestParseKexInitSurvivesRandomMutations(t *testing.T) {
	base := kexInitPayload(openssh10)
	for seed := int64(0); seed < 200; seed++ {
		r := rand.New(rand.NewSource(seed))
		p := append([]byte(nil), base...)
		cookieOnly := seed%2 == 0
		if cookieOnly {
			for i := 0; i < 1+r.Intn(16); i++ {
				p[1+r.Intn(16)] = byte(r.Intn(256))
			}
		} else {
			for i := 0; i < 1+r.Intn(8); i++ {
				p[r.Intn(len(p))] = byte(r.Intn(256))
			}
			if r.Intn(3) == 0 {
				p = p[:r.Intn(len(p))]
			}
		}
		info, err := parseKexInit(p)
		if cookieOnly && err != nil {
			t.Fatalf("seed %d: a cookie-only change was refused: %v", seed, err)
		}
		if err != nil {
			continue
		}
		for _, l := range [][]string{info.Kex, info.HostKeys, info.CiphersC2S, info.CiphersS2C, info.MACsC2S, info.MACsS2C, info.CompC2S, info.CompS2C} {
			for _, n := range l {
				if !printableName(n) {
					t.Fatalf("seed %d: accepted name %q", seed, n)
				}
			}
		}
	}
}

func printableName(n string) bool {
	if n == "" {
		return false
	}
	for i := 0; i < len(n); i++ {
		if n[i] <= ' ' || n[i] > '~' || n[i] == ',' {
			return false
		}
	}
	return true
}

func FuzzParseKexInit(f *testing.F) {
	f.Add(kexInitPayload(openssh10))
	f.Add([]byte{20})
	f.Fuzz(func(t *testing.T, p []byte) {
		info, err := parseKexInit(p)
		if err != nil {
			return
		}
		for _, l := range [][]string{info.Kex, info.HostKeys, info.CiphersC2S, info.CiphersS2C, info.MACsC2S, info.MACsS2C, info.CompC2S, info.CompS2C} {
			for _, n := range l {
				if !printableName(n) {
					t.Fatalf("accepted name %q", n)
				}
			}
		}
	})
}
