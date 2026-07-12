package binscan

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/TAIPANBOX/qryx/internal/model"
)

// buildStaticELF writes a minimal, non-stripped ELF64 file to a temp path and
// returns it. It carries a full symbol table (.symtab/.strtab) naming
// symbolNames, but deliberately has no .dynsym/.dynamic section at all,
// modeling a statically-linked binary whose crypto has no entry in the
// dynamic import table that ImportedSymbols()/ImportedLibraries() read from.
// Everything here is hand-built from debug/elf's own on-disk struct layouts
// (Header64, Section64, Sym64) so the bytes match exactly what elf.Open
// expects.
func buildStaticELF(t *testing.T, symbolNames ...string) string {
	t.Helper()
	bo := binary.LittleEndian
	mustWrite := func(buf *bytes.Buffer, v any) {
		t.Helper()
		if err := binary.Write(buf, bo, v); err != nil {
			t.Fatalf("binary.Write: %v", err)
		}
	}

	// Symbol-name string table (.strtab): conventional leading NUL, then one
	// NUL-terminated name per symbol.
	strtab := []byte{0}
	strOff := make(map[string]uint32, len(symbolNames))
	for _, n := range symbolNames {
		strOff[n] = uint32(len(strtab))
		strtab = append(strtab, []byte(n)...)
		strtab = append(strtab, 0)
	}

	// Section-name string table (.shstrtab).
	shstrtab := []byte{0}
	addShStr := func(s string) uint32 {
		off := uint32(len(shstrtab))
		shstrtab = append(shstrtab, []byte(s)...)
		shstrtab = append(shstrtab, 0)
		return off
	}
	shstrtabName := addShStr(".shstrtab")
	symtabName := addShStr(".symtab")
	strtabName := addShStr(".strtab")

	// Symbol table (.symtab): the mandatory null entry at index 0, then one
	// STB_GLOBAL/STT_FUNC symbol per name with Shndx=1 (i.e. "defined in this
	// binary", not SHN_UNDEF) so each looks like code compiled in, not an
	// unresolved dynamic import.
	var symtab bytes.Buffer
	mustWrite(&symtab, elf.Sym64{})
	for _, n := range symbolNames {
		mustWrite(&symtab, elf.Sym64{
			Name:  strOff[n],
			Info:  elf.ST_INFO(elf.STB_GLOBAL, elf.STT_FUNC),
			Shndx: 1,
			Value: 0x1000,
			Size:  0x20,
		})
	}

	const (
		ehsize    = 64 // sizeof(elf.Header64{})
		shentsize = 64 // sizeof(elf.Section64{})
	)
	symtabOff := uint64(ehsize)
	strtabOff := symtabOff + uint64(symtab.Len())
	shstrtabOff := strtabOff + uint64(len(strtab))
	shoff := shstrtabOff + uint64(len(shstrtab))

	var buf bytes.Buffer
	mustWrite(&buf, elf.Header64{
		Ident: [16]byte{
			0x7f, 'E', 'L', 'F', // magic
			2,                         // EI_CLASS = ELFCLASS64
			1,                         // EI_DATA = ELFDATA2LSB
			1,                         // EI_VERSION = EV_CURRENT
			0, 0, 0, 0, 0, 0, 0, 0, 0, // OSABI, ABIVERSION, padding
		},
		Type:      2,  // ET_EXEC
		Machine:   62, // EM_X86_64
		Version:   1,  // EV_CURRENT
		Shoff:     shoff,
		Ehsize:    ehsize,
		Shentsize: shentsize,
		Shnum:     4, // null, .shstrtab, .symtab, .strtab
		Shstrndx:  1,
	})
	buf.Write(symtab.Bytes())
	buf.Write(strtab)
	buf.Write(shstrtab)

	sections := []elf.Section64{
		{}, // index 0: SHN_UNDEF / null section, mandatory
		{Name: shstrtabName, Type: uint32(elf.SHT_STRTAB), Off: shstrtabOff, Size: uint64(len(shstrtab)), Addralign: 1},
		{Name: symtabName, Type: uint32(elf.SHT_SYMTAB), Off: symtabOff, Size: uint64(symtab.Len()), Link: 3, Entsize: elf.Sym64Size, Addralign: 8},
		{Name: strtabName, Type: uint32(elf.SHT_STRTAB), Off: strtabOff, Size: uint64(len(strtab)), Addralign: 1},
	}
	for _, s := range sections {
		mustWrite(&buf, s)
	}

	path := filepath.Join(t.TempDir(), "static-crypto.elf")
	if err := os.WriteFile(path, buf.Bytes(), 0o755); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

// TestScanStaticELFSymtabFallback is the fail-before/pass-after case for the
// static-binary blind spot described in CLAUDE.md: a non-stripped,
// statically-linked ELF whose crypto symbols live only in the full symbol
// table (.symtab), never in the dynamic import table (.dynsym/.dynamic),
// used to produce zero findings, reported as "clear" when it plainly links
// RSA. It must now be caught via the .symtab fallback.
func TestScanStaticELFSymtabFallback(t *testing.T) {
	path := buildStaticELF(t, "main", "RSA_new")

	// Sanity-check the fixture really has no dynamic symbols/libraries, so
	// this test exercises the new static fallback, not the pre-existing
	// dynamic-import path.
	f, err := elf.Open(path)
	if err != nil {
		t.Fatalf("fixture does not parse as ELF: %v", err)
	}
	imported, _ := f.ImportedSymbols()
	libs, _ := f.ImportedLibraries()
	f.Close()
	if len(imported) != 0 || len(libs) != 0 {
		t.Fatalf("fixture has dynamic imports=%v libs=%v, want none", imported, libs)
	}

	findings, err := Scan([]string{path})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	var rsa *model.Finding
	for i := range findings {
		if findings[i].Asset.Algorithm == "RSA" {
			rsa = &findings[i]
		}
	}
	if rsa == nil {
		t.Fatalf("statically-linked RSA_new in .symtab not detected: %+v", findings)
	}
	if rsa.Asset.Type != model.TypeAlgorithm {
		t.Errorf("asset type = %q, want %q", rsa.Asset.Type, model.TypeAlgorithm)
	}
	if rsa.Source != "binary" {
		t.Errorf("source = %q, want %q", rsa.Source, "binary")
	}
}
