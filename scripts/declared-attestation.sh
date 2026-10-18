#!/usr/bin/env bash
# Checks that every finding text qryx writes for an Agent Passport's attestation
# method says the method is DECLARED, and never reads as an attestation that
# happened.
#
# WHY
#
# A passport names its attestation method in its own JSON. qryx reads no
# certificate, SVID or enclave key behind that name, so a finding that says
# "attests via mtls-cert" reports the passport's string as if it were evidence.
# That is F-020 of the 2026-10-17 security review. The wording is the whole
# defence here, and wording drifts back in one hurried edit.
#
# WHAT THIS DOES NOT DO
#
# It reads the Evidence literals as text. It cannot tell whether a sentence is
# true, and it does not check the CI-mode refusal of verify-evidence: that is
# behaviour, and TestVerifyEvidence* in cmd/qryx assert it.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

file="internal/agentstack/agentstack.go"
if [ ! -f "$file" ]; then
	printf '%s is not there: nothing to check, and that is not a pass\n' "$file" >&2
	exit 1
fi

# The function body, from its signature to its closing brace at column 0.
body=$(awk '/^func passportFindings\(/{on=1} on{print} on && /^}/{exit}' "$file")
if [ -z "$body" ]; then
	printf 'no passportFindings function in %s: measured nothing, and that is not a pass\n' "$file" >&2
	exit 1
fi

evidence=$(printf '%s\n' "$body" | grep -c 'Evidence:')
if [ "$evidence" -lt 4 ]; then
	printf 'passportFindings has %s Evidence literals, expected at least 4: measured nothing, and that is not a pass\n' "$evidence" >&2
	exit 1
fi

fail=0
while IFS= read -r line; do
	case "$line" in *Evidence:*) ;; *) continue ;; esac
	if ! printf '%s' "$line" | grep -qi 'declare'; then
		printf 'UNDECLARED  %s\n' "$(printf '%s' "$line" | sed 's/^[[:space:]]*//')"
		printf '            a passport attestation finding that does not say the method is declared\n'
		fail=$((fail + 1))
	fi
done <<<"$body"

# The phrasing that read as a completed attestation, anywhere in the file.
if grep -q 'attests via' "$file"; then
	printf 'UNDECLARED  %s contains "attests via"\n' "$file"
	printf '            that phrasing reads as an attestation that happened\n'
	fail=$((fail + 1))
fi

if [ "$fail" -gt 0 ]; then
	printf '%d attestation finding(s) do not say the method is declared.\n' "$fail"
	exit 1
fi
printf 'attestation: %d passport findings, every one says the method is declared\n' "$evidence"
