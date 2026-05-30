package binscan

import "debug/macho"

// machoImports extracts needed libraries and imported symbol names from a
// Mach-O binary, including universal (fat) binaries (the union across archs).
func machoImports(path string) (libs, syms []string, ok bool) {
	if f, err := macho.Open(path); err == nil {
		defer f.Close()
		libs, _ = f.ImportedLibraries()
		syms, _ = f.ImportedSymbols()
		return libs, syms, true
	}

	fat, err := macho.OpenFat(path)
	if err != nil {
		return nil, nil, false
	}
	defer fat.Close()

	libSet, symSet := map[string]bool{}, map[string]bool{}
	for _, arch := range fat.Arches {
		l, _ := arch.ImportedLibraries()
		s, _ := arch.ImportedSymbols()
		for _, x := range l {
			libSet[x] = true
		}
		for _, x := range s {
			symSet[x] = true
		}
	}
	return keys(libSet), keys(symSet), true
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
