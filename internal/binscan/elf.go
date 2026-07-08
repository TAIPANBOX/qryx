// Package binscan discovers cryptography in compiled binaries (ELF, PE,
// Mach-O). It is a connector like internal/probe, not a file detector —
// binaries are identified by magic bytes, read from disk, and parsed
// structurally rather than scanned as text.
package binscan

import (
	"debug/elf"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/TAIPANBOX/qryx/internal/model"
)

// elfMagic is the leading byte sequence of every ELF file.
var elfMagic = []byte{0x7f, 'E', 'L', 'F'}

// cryptoLibs maps a needed-library name substring to a canonical library name.
// The asset is the library itself (inventory), not an algorithm — mapping it to
// a representative algorithm would collide with real algorithm findings.
var cryptoLibs = []struct{ needle, name string }{
	{"libcrypto", "libcrypto"},
	{"libssl", "libssl"},
	{"libgnutls", "GnuTLS"},
	{"libmbedtls", "mbedTLS"},
	{"libsodium", "libsodium"},
}

// symRule maps a dynamic-symbol prefix to an algorithm and primitive.
type symRule struct {
	prefix string
	algo   string
	prim   model.Primitive
}

// symRules are checked in order; the first matching prefix wins. Ordered so more
// specific prefixes precede broader ones (SHA1 before SHA, EC before ED).
var symRules = []symRule{
	{"MD5", "MD5", model.PrimitiveHash},
	{"SHA1", "SHA-1", model.PrimitiveHash},
	{"SHA256", "SHA-256", model.PrimitiveHash},
	{"SHA512", "SHA-512", model.PrimitiveHash},
	{"RSA", "RSA", model.PrimitiveSignature},
	{"ECDSA", "ECDSA", model.PrimitiveSignature},
	{"EC_", "ECDSA", model.PrimitiveSignature},
	{"ED25519", "Ed25519", model.PrimitiveSignature},
	{"DSA", "DSA", model.PrimitiveSignature},
	{"DH_", "DH", model.PrimitiveKeyExch},
	{"DES", "DES", model.PrimitiveEncryption},
	{"RC4", "RC4", model.PrimitiveEncryption},
}

// Scan walks each path (file or directory) and returns crypto findings from
// every supported binary it contains. Unsupported/non-binary files are skipped
// silently.
func Scan(paths []string) ([]model.Finding, error) {
	var out []model.Finding
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if info.IsDir() {
			err = filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
				if err != nil || d.IsDir() || !d.Type().IsRegular() {
					return nil
				}
				out = append(out, scanFile(path)...)
				return nil
			})
			if err != nil {
				return nil, err
			}
			continue
		}
		out = append(out, scanFile(p)...)
	}
	return out, nil
}

// scanFile parses one file if it is a supported binary (ELF, PE, Mach-O),
// returning its crypto findings. Format is chosen by magic bytes so text files
// are skipped cheaply.
func scanFile(path string) []model.Finding {
	libs, syms, ok := imports(path)
	if !ok {
		return nil
	}
	out := librariesToFindings(path, libs)
	out = append(out, cryptoFromSymbols(path, syms)...)
	return out
}

// imports dispatches on magic bytes to the right parser and returns the
// binary's needed libraries and imported symbols. ok is false for unsupported
// or unparseable files.
func imports(path string) (libs, syms []string, ok bool) {
	magic := readMagic(path)
	switch {
	case len(magic) >= 4 && string(magic[:4]) == string(elfMagic):
		return elfImports(path)
	case len(magic) >= 2 && magic[0] == 'M' && magic[1] == 'Z':
		return peImports(path)
	case isMachOMagic(magic):
		return machoImports(path)
	default:
		return nil, nil, false
	}
}

// readMagic returns the first 4 bytes of a file (fewer if shorter).
func readMagic(path string) []byte {
	f, err := os.Open(path) // #nosec G304 -- path is an operator-supplied CLI argument or a file discovered under an operator-specified scan root; reading arbitrary binaries is this scanner's job
	if err != nil {
		return nil
	}
	defer f.Close()
	hdr := make([]byte, 4)
	n, _ := f.Read(hdr)
	return hdr[:n]
}

// isMachOMagic reports whether the bytes start with a Mach-O (thin or fat)
// magic, in either endianness.
func isMachOMagic(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	switch [4]byte{b[0], b[1], b[2], b[3]} {
	case [4]byte{0xfe, 0xed, 0xfa, 0xce}, // 32-bit BE
		[4]byte{0xfe, 0xed, 0xfa, 0xcf}, // 64-bit BE
		[4]byte{0xce, 0xfa, 0xed, 0xfe}, // 32-bit LE
		[4]byte{0xcf, 0xfa, 0xed, 0xfe}, // 64-bit LE
		[4]byte{0xca, 0xfe, 0xba, 0xbe}: // fat
		return true
	}
	return false
}

// elfImports extracts needed libraries and imported symbol names from an ELF.
func elfImports(path string) (libs, syms []string, ok bool) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, nil, false
	}
	defer f.Close()
	libs, _ = f.ImportedLibraries()
	imported, _ := f.ImportedSymbols()
	syms = make([]string, len(imported))
	for i, s := range imported {
		syms[i] = s.Name
	}
	return libs, syms, true
}

func librariesToFindings(path string, libs []string) []model.Finding {
	var out []model.Finding
	for _, lib := range libs {
		for _, cl := range cryptoLibs {
			if strings.Contains(lib, cl.needle) {
				out = append(out, model.Finding{
					Asset:    model.Asset{Type: model.TypeLibrary, Algorithm: cl.name, Primitive: model.PrimitiveUnknown},
					Location: model.Location{File: path},
					Evidence: "links " + lib,
					Source:   "binary",
				})
				break
			}
		}
	}
	return out
}

// cryptoFromSymbols maps imported dynamic symbols to algorithm findings,
// emitting at most one finding per algorithm to avoid per-symbol noise.
func cryptoFromSymbols(path string, symbols []string) []model.Finding {
	seen := map[string]bool{}
	var out []model.Finding
	for _, name := range symbols {
		// Mach-O prefixes C symbols with an underscore (_MD5_Init); strip it so
		// one rule set serves all formats.
		bare := strings.TrimPrefix(name, "_")
		for _, r := range symRules {
			if strings.HasPrefix(bare, r.prefix) {
				if !seen[r.algo] {
					seen[r.algo] = true
					out = append(out, model.Finding{
						Asset:    model.Asset{Type: model.TypeAlgorithm, Algorithm: r.algo, Primitive: r.prim},
						Location: model.Location{File: path},
						Evidence: "imports " + name,
						Source:   "binary",
					})
				}
				break
			}
		}
	}
	return out
}
