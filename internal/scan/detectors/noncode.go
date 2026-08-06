package detectors

// language is the lexical shape stripNonCode needs: what opens a comment, and
// which string forms exist.
type language int

const (
	langPython language = iota
	langJS
)

// stripNonCode blanks the parts of src that are not code, keeping every byte
// in place so a line number computed afterwards still points at the right
// line. Blanking rather than deleting is the whole trick, and it is taken
// from stripRustNonCode in rust.go, which has held that property since the
// rust detector was written.
//
// # Why this is a second implementation and not a call to that one
//
// It was read first. The technique generalizes; the lexical rules do not, and
// they differ in exactly the places this defect lives. Rust has no `#` line
// comment, so `# migrate off RSA` would have survived it. Rust has no
// triple-quoted string, so a Python docstring naming DES would have survived
// it too. Rust's `'a` lifetime heuristic is meaningless in Python and JS,
// where `'` is only ever a quote. Rust has nested block comments, which JS
// does not, and raw `r#"..."#` strings, which neither of these has, while JS
// template literals and Python triple quotes have no Rust equivalent. A
// shared function would have been a switch over three languages that share a
// loop and nothing else.
//
// # blankStrings
//
// Comments are never code in either language, so they are always blanked.
// String literals are a different question per pattern, which is why the
// caller chooses. The Python patterns are identifiers (\bRSA\b, \bAES\b), so
// a literal is prose to them and is blanked. Node's crypto API names its
// algorithm IN a string literal (createHash('md5')), so blanking literals
// would delete the JS detector's only evidence; those patterns run with
// literals kept, and see comment-free text.
//
// String state is tracked either way, so a `#` or `//` inside a string is
// never mistaken for a comment.
//
// # Known limits, none of which hide code
//
// A JS regex literal is not recognized, so `/x\/\/y/` can look like a
// comment. `${}` interpolation inside a template literal is blanked with the
// rest of the template. A backslash-newline line continuation inside a
// single-quoted string ends the string here. Each of those blanks or keeps
// text a real parser would treat differently; none of them makes the scanner
// look at less than the file, which is the direction that matters (CLAUDE.md
// invariant 6: a clean scan must never be manufactured by not looking).
func stripNonCode(src []byte, lang language, blankStrings bool) []byte {
	out := make([]byte, len(src))
	copy(out, src)

	// Newlines survive every blanking, which is what keeps line numbers true.
	blank := func(i int) {
		if out[i] != '\n' {
			out[i] = ' '
		}
	}
	blankStr := func(i int) {
		if blankStrings {
			blank(i)
		}
	}

	const (
		code = iota
		lineComment
		blockComment
		str      // '...' or "...", one line only
		triple   // Python ''' or """
		template // JS `...`
	)

	state := code
	var quote byte // delimiter of the string being read
	strStart := 0  // where the current one-line string opened
	blockBody := 0 // first byte after a /* opener, so /*/ does not close it

	for i := 0; i < len(src); i++ {
		c := src[i]
		switch state {
		case code:
			switch {
			case lang == langPython && c == '#':
				state = lineComment
				blank(i)
			case lang == langJS && c == '/' && i+1 < len(src) && src[i+1] == '/':
				state = lineComment
				blank(i)
				blank(i + 1)
				i++
			case lang == langJS && c == '/' && i+1 < len(src) && src[i+1] == '*':
				state = blockComment
				blank(i)
				blank(i + 1)
				i++
				blockBody = i + 1
			case lang == langJS && c == '`':
				state = template
				blankStr(i)
			case c == '"' || c == '\'':
				if lang == langPython && i+2 < len(src) && src[i+1] == c && src[i+2] == c {
					state, quote = triple, c
					blankStr(i)
					blankStr(i + 1)
					blankStr(i + 2)
					i += 2
					continue
				}
				state, quote, strStart = str, c, i
				blankStr(i)
			}

		case lineComment:
			if c == '\n' {
				state = code
			} else {
				blank(i)
			}

		case blockComment:
			blank(i)
			if c == '/' && i > blockBody && src[i-1] == '*' {
				state = code
			}

		case str:
			if c == '\n' {
				// Neither language lets a '...' or "..." span a line, so this
				// was not a string: an apostrophe in JSX prose, most often.
				// Give the bytes back and carry on in code. A stripper that
				// instead ran to the next quote would blank the rest of the
				// file, and every finding after it would vanish into a scan
				// that looked clean.
				copy(out[strStart:i], src[strStart:i])
				state = code
				continue
			}
			blankStr(i)
			if c == '\\' && i+1 < len(src) {
				blankStr(i + 1)
				i++
				continue
			}
			if c == quote {
				state = code
			}

		case triple:
			blankStr(i)
			if c == '\\' && i+1 < len(src) {
				blankStr(i + 1)
				i++
				continue
			}
			if c == quote && i+2 < len(src) && src[i+1] == quote && src[i+2] == quote {
				blankStr(i + 1)
				blankStr(i + 2)
				i += 2
				state = code
			}

		case template:
			blankStr(i)
			if c == '\\' && i+1 < len(src) {
				blankStr(i + 1)
				i++
				continue
			}
			if c == '`' {
				state = code
			}
		}
	}
	return out
}
