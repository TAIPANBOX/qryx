package binscan

import "debug/pe"

// peImports extracts needed libraries and imported symbol names from a PE
// (Windows) binary.
func peImports(path string) (libs, syms []string, ok bool) {
	f, err := pe.Open(path)
	if err != nil {
		return nil, nil, false
	}
	defer f.Close()
	libs, _ = f.ImportedLibraries()
	syms, _ = f.ImportedSymbols()
	return libs, syms, true
}
