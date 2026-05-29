package detectors

import "bytes"

// lineNumber returns the 1-based line of byte offset in content.
func lineNumber(content []byte, offset int) int {
	if offset > len(content) {
		offset = len(content)
	}
	return bytes.Count(content[:offset], []byte{'\n'}) + 1
}
