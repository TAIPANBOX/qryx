#!/usr/bin/env bash
# Checks that the gates in `scripts/` still FAIL on the faults they exist to
# catch, still PASS on what they must not catch, and REFUSE to report success
# when they measured nothing at all.
#
# WHY
#
# Every gate here parses text, and a text parser does not break loudly: it
# stops matching and reports success. The mutants that proved each one existed
# as prose, in commit messages and in the `*(gate: ...)*` markers in CLAUDE.md,
# which is a record of what was true once. Nothing ran them again.
#
# A gate that has quietly stopped catching anything looks exactly like a gate
# with nothing to catch, and stays that way until the fault it guards ships.
#
# WHY THE THIRD PROPERTY IS SEPARATE FROM THE FIRST
#
# Two of these three gates already refuse when their subject is absent, and
# CLAUDE.md says so in its reproducible-build and README-numbers invariants.
# Those sentences were true and nothing re-established them. A check that cannot tell "did not fail" from
# "did not run" is the most expensive recurring mistake in this estate's
# tooling, and it lives in tooling rather than product code because tooling is
# where a silent pass looks like a result.
#
# HOW IT MUTATES WITHOUT LEAVING A MESS
#
# It edits tracked files in place, so it refuses to start unless the tree is
# clean, restores with `git checkout` after every case, restores again from a
# trap on any exit path including a kill, and asserts the tree is clean before
# reporting success.
#
#
# A GATE THAT IS ALREADY FAILING CANNOT BE JUDGED
#
# No case proves anything if the gate was already failing before the mutation.
# So every case runs the gate on the UNMUTATED tree first and reports
# UNJUDGEABLE. Found on 2026-08-09 in it-rat, where one gate was legitimately
# red and a case against it would have been indistinguishable from a working
# one.
#
# It covered only the fail-cases at first, which left the mirror of the same
# bug: on a red gate a pass-case reports OVEREAGER, "the gate failed on
# something it must not catch", and sends the reader to look at a harmless
# mutation. The verdict was being given without the predicate it depends on.
#
# A MUTATION THAT DID NOT APPLY PROVES NOTHING
#
# Every edit asserts it changed the file. A case whose edit applied nothing is
# a failure here, not a pass. That is not hypothetical: five such mutations
# were caught across idryx and tokenfuse on 2026-08-09, and three of the five
# had been verified BY HAND against the same gate minutes earlier. The hand
# version and the harness version differ only in how many layers of quoting sit
# between the text and python, which is exactly the difference nobody sees.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

if [ -n "$(git status --porcelain)" ]; then
	printf 'this script mutates tracked files, so it needs a clean tree.\n'
	printf 'commit or stash first; it restores with `git checkout` and cannot\n'
	printf 'tell your edits from its own.\n'
	exit 1
fi

# Untracked files too: a mutation may RENAME a tracked file, and `git checkout`
# restores the original while leaving the new name behind. And the INDEX, since
# a gate may read `git ls-files` rather than the disk, so a mutation has to move
# the file in both. Safe because this
# script refuses to start unless the tree is clean, so anything untracked
# during a run was created by the run. `-x` is deliberately absent: ignored
# build output is not ours to delete.
restore() {
	git reset -q --hard HEAD 2>/dev/null
	git clean -fdq 2>/dev/null
}
baseline_dir="$(mktemp -d)"

# One trap for both, because a second `trap ... EXIT` REPLACES the first
# rather than adding to it. Writing them separately disarmed `restore` on
# every interrupt path, which would leave a mutated tree behind on Ctrl-C.
cleanup() {
	restore
	rm -rf "$baseline_dir"
}
trap cleanup EXIT INT TERM


failures=0
cases=0

# run_case <name> <expect: fail|pass> <gate> <python edit> [required output]
#
# The needle separates "it failed" from "it failed for the reason this case is
# about". Without it, a case expecting failure is satisfied by any failure,
# including one this harness caused itself.
run_case() {
	local name="$1" expect="$2" gate="$3" edit="$4" needle="${5:-}"
	cases=$((cases + 1))

	# The baseline applies to EVERY case, not only the ones expecting a failure.
	# It was `fail`-only until 2026-08-09, which left the mirror of the bug it was
	# written for: on a gate that is already red, a `pass` case reports OVEREAGER,
	# "the gate failed on something it must not catch", and sends the reader to
	# look at a harmless mutation while the gate was failing without it. Neither
	# verdict means anything on a red gate, so neither is given.
	skip_baseline=0
	if [ "$expect" = fail_env ]; then
		# `fail` with the baseline skipped, for cases whose fault IS the command
		# rather than a mutation: red before and after is the point there.
		expect=fail
		skip_baseline=1
	fi

	if [ "$skip_baseline" = 0 ]; then
		local key base_out
		key="$baseline_dir/$(printf '%s' "$gate" | cksum | tr -d ' ')"
		if [ ! -f "$key" ]; then
			if eval "$gate" >/dev/null 2>&1; then printf 'green' >"$key"; else printf 'red' >"$key"; fi
		fi
		base_out="$(cat "$key")"
		if [ "$base_out" = red ]; then
			printf 'UNJUDGEABLE  %s\n             the gate is already failing on a clean tree, so neither a\n             failure nor a pass after the mutation would prove anything\n' "$name"
			failures=$((failures + 1))
			return
		fi
	fi

	if ! python3 -c "$edit"; then
		printf 'BROKEN  %s\n        its mutation did not apply, so this case proved nothing\n' "$name"
		failures=$((failures + 1))
		restore
		return
	fi

	local out rc
	out=$(eval "$gate" 2>&1)
	rc=$?
	restore

	# Exit code first, then wording. Checking the needle before the expectation
	# turns "it did not fail at all" into "it failed for the wrong reason",
	# which sends the reader to look at prose when the gate is toothless.
	if [ "$expect" = fail ] && [ "$rc" -ne 0 ] && [ -n "$needle" ] &&
		! grep -qF -- "$needle" <<<"$out"; then
		printf 'WRONG REASON  %s\n              it failed, but not saying: %s\n' "$name" "$needle"
		failures=$((failures + 1))
		return
	fi
	if [ "$expect" = fail ] && [ "$rc" -eq 0 ]; then
		printf 'TOOTHLESS  %s\n           the gate passed on a fault it exists to catch\n' "$name"
		failures=$((failures + 1))
	elif [ "$expect" = pass ] && [ "$rc" -ne 0 ]; then
		printf 'OVEREAGER  %s\n           the gate failed on something it must not catch\n' "$name"
		failures=$((failures + 1))
		printf '%s\n' "$out" | head -4 | sed 's/^/           /'
	else
		printf 'ok  %-58s (%s)\n' "$name" "$expect"
	fi
}

py() { printf 'def edit(p, a, b):\n    s = open(p).read()\n    assert a in s, "pattern not found in " + p\n    open(p, "w").write(s.replace(a, b, 1))\n%s\n' "$1"; }

echo "=== faults each gate must catch ==="

# jcs is already in the graph as indirect, so promoting it to direct names a
# genuinely undeclared dependency without moving go.sum or touching the build.
run_case "declared-deps: an undeclared direct dependency" fail \
	'./scripts/declared-deps.sh' \
	"$(py 'edit("go.mod", "github.com/gowebpki/jcs v1.0.1 // indirect", "github.com/gowebpki/jcs v1.0.1")')" \
	"undeclared direct dependency"

# The reverse direction: the allow-list describing a repo that no longer exists.
run_case "declared-deps: an allowed dependency gone from go.mod" fail \
	'./scripts/declared-deps.sh' \
	"$(py 'edit("go.mod", "\tgithub.com/zclconf/go-cty v1.16.3\n", "")')" \
	"no longer a direct dependency"

run_case "readme-numbers: a stale test badge" fail \
	'./scripts/readme-numbers.sh' \
	"$(py 'import re
s = open("README.md").read()
m = re.search(r"badge/tests-(\d+)-", s)
assert m, "no test badge in README.md"
open("README.md","w").write(s.replace(m.group(0), "badge/tests-%d-" % (int(m.group(1))+7), 1))')" \
	"the badge says"

run_case "reproducible-build: the workflow loses a build flag" fail \
	'./scripts/reproducible-build.sh' \
	"$(py 'edit(".github/workflows/release.yml", "go build -trimpath", "go build")')" \
	"builds the release without"

run_case "reproducible-build: a version back in the asset name" fail \
	'./scripts/reproducible-build.sh' \
	"$(py 'edit(".github/workflows/release.yml", "out=\"qryx_", "out=\"qryx_${VERSION}_")')" \
	"carries the version"

echo
echo "=== and what they must NOT catch ==="

run_case "declared-deps: another indirect dependency added" pass \
	'./scripts/declared-deps.sh' \
	"$(py 'edit("go.mod", "\tgithub.com/gowebpki/jcs v1.0.1 // indirect", "\tgithub.com/gowebpki/jcs v1.0.1 // indirect\n\tgithub.com/kr/pretty v0.3.1 // indirect")')"

run_case "readme-numbers: a badge-shaped number elsewhere in the README" pass \
	'./scripts/readme-numbers.sh' \
	"$(py 'edit("README.md", "## ", "Once badge/tests-11- was the figure, long ago.\n\n## ")')"

echo
echo "=== and the one this estate learned the hard way ==="
echo "    a gate whose subject is gone must SAY so, not report OK on nothing"

run_case "readme-numbers: no badge left to compare against" fail \
	'./scripts/readme-numbers.sh' \
	"$(py 'import re
s = open("README.md").read()
m = re.search(r"badge/tests-\d+-", s)
assert m, "no test badge in README.md"
open("README.md","w").write(s.replace(m.group(0), "badge/nothing-", 1))')" \
	"nothing to compare against"

run_case "reproducible-build: no build command left to read" fail \
	'./scripts/reproducible-build.sh' \
	"$(py 'edit(".github/workflows/release.yml", "go build -trimpath", "go vet -trimpath")')" \
	"no 'go build' command found"

run_case "reproducible-build: no asset name left to read" fail \
	'./scripts/reproducible-build.sh' \
	"$(py 'edit(".github/workflows/release.yml", "out=\"qryx_", "unused=\"qryx_")')" \
	"no release asset name"

# features-are-bound: the two directions that actually rot.
#
# A binding pointing at a renamed test is the failure that happens on its own,
# because nothing links the pointer to the test but a string. A scenario with
# no binding is the one somebody adds in a hurry, and it reads as held.
run_case "features-are-bound: a binding naming a test that does not exist" fail \
	'./scripts/features-are-bound.sh' \
	"$(py 'edit("features/ai-inventory.feature", "@test:TestAIInventoryCarriesProviderAndRole", "@test:TestAIInventoryCarriesProviderAndRoleRenamed")')" \
	"DANGLING"

run_case "features-are-bound: a scenario with no binding above it" fail \
	'./scripts/features-are-bound.sh' \
	"$(py 'edit("features/ai-inventory.feature", "  # @test:TestAIInventoryIsDeterministic\n", "")')" \
	"UNBOUND"

# The non-fault: prose is what these files are for, and a gate that fires on an
# edited sentence is one people learn to skip.
run_case "features-are-bound: a reworded step" pass \
	'./scripts/features-are-bound.sh' \
	"$(py 'edit("features/ai-inventory.feature", "Given a source tree the operator owns", "Given a source tree that belongs to the operator")')"

# And the subject taken away: an empty feature file passes every check above,
# because there is nothing in it to be wrong.
run_case "features-are-bound: a feature file with no scenarios left" fail \
	'./scripts/features-are-bound.sh' \
	"$(py 'import re
b = open("features/ai-inventory.feature").read()
open("features/ai-inventory.feature", "w").write(re.sub(r"(?s)  # @test.*", "", b))')" \
	"a feature file with no scenarios"

echo
echo "=== declared-attestation: a passport's method is declared, never verified ==="

# A finding that reads as an attestation that happened is the failure F-020
# named. The gate must name the line, so the reader is not sent to a whole file.
run_case "declared-attestation: a finding that reads as an attestation that happened" fail \
	'./scripts/declared-attestation.sh' \
	"$(py 'edit("internal/agentstack/agentstack.go", "agent %s declares attestation method %s (%s); the declaration is not verified", "agent %s attests via %s (%s)")')" \
	"UNDECLARED"

run_case "declared-attestation: the no-method finding loses the word declares" fail \
	'./scripts/declared-attestation.sh' \
	"$(py 'edit("internal/agentstack/agentstack.go", "agent %s declares no attestation method", "agent %s has no attestation method")')" \
	"UNDECLARED"

# The non-fault: a reworded sentence that still says the method is declared.
run_case "declared-attestation: a reworded finding that still says declares" pass \
	'./scripts/declared-attestation.sh' \
	"$(py 'edit("internal/agentstack/agentstack.go", "agent %s declares attestation method %s", "agent %s declares the attestation method %s")')"

# And the subject taken away: the function renamed, so there is nothing to read.
run_case "declared-attestation: passportFindings renamed away" fail \
	'./scripts/declared-attestation.sh' \
	"$(py 'edit("internal/agentstack/agentstack.go", "func passportFindings(", "func passportFindingz(")')" \
	"measured nothing"

echo
echo "=== compat-surface: the surface 1.0 will freeze ==="

# A global, quote-aware substitution rather than the `py()` helper's
# first-occurrence replace: a frozen name can legitimately appear more than
# once in its file (a membership check and a switch case, for two), and a
# case that only silences the FIRST occurrence would leave the literal still
# findable, still green, and prove nothing (measured: "agents" and
# "evidence_signed" each sit in their file twice). subn with no count
# replaces every quoted occurrence at once; json.dumps builds each Python
# string literal so the file/old/new arguments never need hand escaping.
pyq() {
	local file_lit old_lit new_lit
	file_lit=$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$1")
	old_lit=$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$2")
	new_lit=$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$3")
	printf 'p = %s\nold = %s\nnew = %s\n' "$file_lit" "$old_lit" "$new_lit"
	cat <<'PYEOF'
import re
s = open(p).read()
pat = re.compile("[\"'`]" + re.escape(old) + "[\"'`]")
new_s, n = pat.subn(lambda m: m.group(0)[0] + new + m.group(0)[-1], s)
assert n >= 1, "no quoted occurrence of " + old + " in " + p
open(p, "w").write(new_s)
PYEOF
}

run_case "compat-surface: a frozen subcommand renamed" fail \
	'./scripts/compat-surface.sh' \
	"$(pyq "cmd/qryx/main.go" "agents" "agentz")" \
	"cli.subcommands: 'agents' is promised"

run_case "compat-surface: an emitted event type gone from its file" fail \
	'./scripts/compat-surface.sh' \
	"$(pyq "internal/exporter/exporter.go" "evidence_signed" "evidence_signedx")" \
	"events.emitted: 'evidence_signed' is promised"

run_case "compat-surface: an accepted schema string gone from its file" fail \
	'./scripts/compat-surface.sh' \
	"$(pyq "internal/agentstack/agentstack.go" "taipanbox.dev/agent-event/v0.2" "taipanbox.dev/agent-event/v0.2-old")" \
	"events.schemas_accepted: 'taipanbox.dev/agent-event/v0.2' is promised"

run_case "compat-surface: COMPATIBILITY.md edited by hand" fail \
	'./scripts/compat-surface.sh' \
	"$(py 'edit("COMPATIBILITY.md", "## Support", "## Hand-edited\n\n## Support")')" \
	"is not the rendering of"

echo
echo "=== and what it must NOT catch ==="

# Purely additive: a second subcommand recognised alongside "agents", nothing
# frozen removed. The gate must not care that the code grew a new name it
# never promised to freeze.
run_case "compat-surface: an additive subcommand added" pass \
	'./scripts/compat-surface.sh' \
	"$(py 'edit("cmd/qryx/main.go", "cmd != \"agents\" {", "cmd != \"agents\" && cmd != \"diag\" {")')"

echo
echo "=== and the one this estate learned the hard way ==="
echo "    a gate whose subject is gone must SAY so, not report OK on nothing"

run_case "compat-surface: the manifest removed" fail \
	'./scripts/compat-surface.sh' \
	"$(printf 'import os\np = "compat/1.0.json"\nassert os.path.isfile(p), p + " missing before the mutation"\nos.remove(p)\n')" \
	"compat/1.0.json is not there"

run_case "compat-surface: a named where-file removed" fail \
	'./scripts/compat-surface.sh' \
	"$(printf 'import os\np = "internal/exporter/exporter.go"\nassert os.path.isfile(p), p + " missing before the mutation"\nos.remove(p)\n')" \
	"is said to live, is not there"

# Invariant 20. Under pipefail a pipe into grep -q fails when the writer is still writing, so a healthy tree
# goes red at random on a loaded machine. The first cases plant the construct; the middle ones are what
# must not be flagged; the last ones break the gate itself, because a reader that has stopped matching
# reports what a clean tree reports.

run_case "no-reader-leaves-a-pipe-early: a gate pipes its text into grep -q again" fail \
	'./scripts/no-reader-leaves-a-pipe-early.sh' \
	"$(py 'edit("scripts/declared-attestation.sh", "if ! grep -qi \x27declare\x27 <<<\"$line\"; then", "if ! printf \x27%s\x27 \"$line\" | grep -qi \x27declare\x27; then")')" \
	'scripts/declared-attestation.sh:'

run_case "no-reader-leaves-a-pipe-early: the pipe is carried over a line" fail \
	'./scripts/no-reader-leaves-a-pipe-early.sh' \
	"$(py 'edit("scripts/declared-deps.sh", "#!/usr/bin/env bash\n", "#!/usr/bin/env bash\nprintf \x27%s\\n\x27 \"$x\" \\\n  | grep -q y\n")')" \
	'scripts/declared-deps.sh:'

run_case "no-reader-leaves-a-pipe-early: a workflow step reads through the pipe" fail \
	'./scripts/no-reader-leaves-a-pipe-early.sh' \
	"$(py 'edit(".github/workflows/ci.yml", "run: ./scripts/declared-deps.sh", "run: printf x | grep -q x")')" \
	'.github/workflows/ci.yml:'

run_case "no-reader-leaves-a-pipe-early: the words are only in a comment" pass \
	'./scripts/no-reader-leaves-a-pipe-early.sh' \
	"$(py 'edit("scripts/declared-deps.sh", "#!/usr/bin/env bash\n", "#!/usr/bin/env bash\n# printf x | grep -q x\n")')"

run_case "no-reader-leaves-a-pipe-early: the words are a command handed to another shell" pass \
	'./scripts/no-reader-leaves-a-pipe-early.sh' \
	"$(py 'edit("scripts/declared-deps.sh", "#!/usr/bin/env bash\n", "#!/usr/bin/env bash\nsh -c \"printf x | grep -q x\"\n")')"

run_case "no-reader-leaves-a-pipe-early: the words are in a here-document" pass \
	'./scripts/no-reader-leaves-a-pipe-early.sh' \
	"$(py 'edit("scripts/declared-deps.sh", "#!/usr/bin/env bash\n", "#!/usr/bin/env bash\ncat <<\x27EOF\x27\nprintf x | grep -q x\nEOF\n")')"

run_case "no-reader-leaves-a-pipe-early: grep -c reads to the end of a pipe" pass \
	'./scripts/no-reader-leaves-a-pipe-early.sh' \
	"$(py 'edit("scripts/declared-deps.sh", "#!/usr/bin/env bash\n", "#!/usr/bin/env bash\nprintf x | grep -c x >/dev/null\n")')"

run_case "no-reader-leaves-a-pipe-early: a here-string has no pipe to leave" pass \
	'./scripts/no-reader-leaves-a-pipe-early.sh' \
	"$(py 'edit("scripts/declared-deps.sh", "#!/usr/bin/env bash\n", "#!/usr/bin/env bash\ngrep -q x <<<x\n")')"

run_case "no-reader-leaves-a-pipe-early: a substitution in quotes reads through the pipe" fail \
	'./scripts/no-reader-leaves-a-pipe-early.sh' \
	"$(py 'edit("scripts/declared-deps.sh", "#!/usr/bin/env bash\n", "#!/usr/bin/env bash\nx=\"$(printf y | grep -m1 y)\"\n")')" \
	'scripts/declared-deps.sh:2 pipes into `grep -m1`'

run_case "no-reader-leaves-a-pipe-early: a long option leaves as early as a short one" fail \
	'./scripts/no-reader-leaves-a-pipe-early.sh' \
	"$(py 'edit("scripts/declared-deps.sh", "#!/usr/bin/env bash\n", "#!/usr/bin/env bash\nprintf y | grep --quiet y\n")')" \
	'scripts/declared-deps.sh:2 pipes into `grep --quiet`'

run_case "no-reader-leaves-a-pipe-early: a quote left open loses the reader its place" fail \
	'./scripts/no-reader-leaves-a-pipe-early.sh' \
	"$(py 's = open("scripts/declared-deps.sh").read()
open("scripts/declared-deps.sh", "w").write(s + "echo \"open\n")')" \
	'lost its place'

run_case "no-reader-leaves-a-pipe-early: the reader stops knowing -q" fail \
	'./scripts/no-reader-leaves-a-pipe-early.sh' \
	"$(py 'edit("scripts/no-reader-leaves-a-pipe-early.sh", "if ch in \"qmlL\":", "if ch in \"mlL\":")')" \
	'the reader missed'

run_case "no-reader-leaves-a-pipe-early: the reader stops reporting what it finds" fail \
	'./scripts/no-reader-leaves-a-pipe-early.sh' \
	"$(py 'edit("scripts/no-reader-leaves-a-pipe-early.sh", "found.append((m.start(), flag))", "pass")')" \
	'the reader missed'

run_case "no-reader-leaves-a-pipe-early: the reader starts reading quoted text" fail \
	'./scripts/no-reader-leaves-a-pipe-early.sh' \
	"$(py 'edit("scripts/no-reader-leaves-a-pipe-early.sh", "blank(i, end + 1)", "pass")')" \
	'the reader flagged'

run_case "no-reader-leaves-a-pipe-early: the control writes less than a pipe holds" fail \
	'./scripts/no-reader-leaves-a-pipe-early.sh' \
	"$(py 'edit("scripts/no-reader-leaves-a-pipe-early.sh", "WRITER = \"seq 1 400000\"", "WRITER = \"seq 1 3\"")')" \
	'it must fail every time'

run_case "no-reader-leaves-a-pipe-early: no pipe is read" fail \
	'./scripts/no-reader-leaves-a-pipe-early.sh' \
	"$(py 'edit("scripts/no-reader-leaves-a-pipe-early.sh", "pipes += len(PIPE.findall(masked))", "pipes += 0")')" \
	'measured NOTHING'

run_case "no-reader-leaves-a-pipe-early: no shell file is read" fail \
	'./scripts/no-reader-leaves-a-pipe-early.sh' \
	"$(py 'edit("scripts/no-reader-leaves-a-pipe-early.sh", "if path.endswith(\".sh\") or path.startswith(\".githooks/\") or (first.startswith(\"#!\") and \"bash\" in first):", "if False:")')" \
	'measured NOTHING'

run_case "no-reader-leaves-a-pipe-early: no workflow step is read" fail \
	'./scripts/no-reader-leaves-a-pipe-early.sh' \
	"$(py 'edit("scripts/no-reader-leaves-a-pipe-early.sh", "elif path.startswith(\".github/workflows/\") and", "elif path.startswith(\".github/flows/\") and")')" \
	'measured NOTHING'

echo
if [ -n "$(git status --porcelain)" ]; then
	printf 'FAIL: this script left the tree dirty, so it cannot be trusted about anything above\n'
	git status --porcelain | head -5
	exit 1
fi

if [ "$failures" -gt 0 ]; then
	printf '%d of %d cases failed.\n' "$failures" "$cases"
	printf 'A gate that has quietly stopped catching anything looks exactly like a gate\n'
	printf 'with nothing to catch, and stays that way until the fault it guards ships.\n'
	exit 1
fi

printf 'OK: %d cases. Every gate fails on its own fault, passes on a non-fault,\n' "$cases"
printf '    and refuses to report success when it measured nothing.\n'
