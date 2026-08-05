#!/usr/bin/env bash
# Enforces invariant 9 of CLAUDE.md: a released binary can be rebuilt, by
# somebody who does not trust us, from the tag it claims to come from.
#
# WHY THIS IS WORTH A GATE RATHER THAN A SENTENCE
#
# Qryx is a scanner. Its whole pitch is that you point it at your own code,
# binaries, containers and KMS and believe what it reports. A buyer's security
# team is exactly the reader who should not have to take our binary on trust,
# and the answer to them is not "the source is open" (it always was) but "build
# it yourself and check you got the same bytes we published".
#
# That answer was already TRUE on 2026-08-05 and written down nowhere. The
# release workflow builds with CGO_ENABLED=0, -trimpath and -ldflags "-s -w",
# which is what makes it hold, and any one of those three going missing would
# break it silently: nothing fails, the binaries simply stop matching, and the
# only person who finds out is the one who tried to verify us.
#
# Measured that day, to be sure the claim is not aspirational:
#   published  qryx_v0.3.0_darwin_arm64 from the release page, built on an
#              ubuntu runner cross-compiling to darwin/arm64
#   local      the same tag, built on macOS
#   sha256     0864315d02b8580b56cb997e31b2bcef1bb804f4713981c0fae424ace3303c2b
# Different machine, different host OS, identical bytes.
#
# WHAT THIS CHECKS, AND WHAT IT CANNOT
#
# It builds the same target twice from two directories of DIFFERENT LENGTHS and
# refuses if a byte differs. Different lengths on purpose: two paths of the same
# length would hide a length-dependent embedding, which is the exact failure
# -trimpath exists to prevent.
#
# It cannot prove a different toolchain produces the same bytes. Go's output is
# tied to its compiler version, `go.mod` pins one, and a digest is only
# meaningful next to the version that made it, so both are printed.
#
# It also does not reach the network. Comparing against the published artifact
# would be a better test and a worse gate: it would fail on every commit after a
# release, which is every commit.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

BIN="${1:-qryx}"
VERSION="$(git describe --tags --always --dirty 2>/dev/null || echo dev)"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT INT TERM

short="$work/a"
long="$work/one-rather-longer-directory-name"

for dir in "$short" "$long"; do
	mkdir -p "$dir"
	# Everything git tracks and nothing it does not: an untracked file in the
	# working tree must not be able to change the answer.
	git archive HEAD | tar -x -C "$dir"
done

echo "toolchain: $(go version)"
echo "source:    $(git rev-parse HEAD)"
echo "binary:    $BIN"

digests=()
for dir in "$short" "$long"; do
	(
		cd "$dir"
		# The same flags the release workflow uses. If these three drift apart,
		# the property this gate protects is gone and this comment is the map
		# back: CGO off so the output does not depend on a host toolchain,
		# -trimpath so the build directory is not embedded, -s -w so no build
		# id or symbol table carries a path in through the side door.
		CGO_ENABLED=0 go build -trimpath \
			-ldflags "-s -w -X main.version=${VERSION}" \
			-o "$dir/out" "./cmd/${BIN}"
	)
	if command -v sha256sum >/dev/null 2>&1; then
		digests+=("$(sha256sum "$dir/out" | cut -d' ' -f1)")
	else
		digests+=("$(shasum -a 256 "$dir/out" | cut -d' ' -f1)")
	fi
done

if [ "${digests[0]}" != "${digests[1]}" ]; then
	echo "FAIL: the same source built in two directories produced two binaries."
	echo "  ${digests[0]}  (short path)"
	echo "  ${digests[1]}  (long path)"
	echo
	echo "Something in the build is embedding the directory it ran in, so nobody"
	echo "can rebuild a release and check it against ours. Look at the flags in"
	echo "this script and in .github/workflows/release.yml: they must agree, and"
	echo "-trimpath must be in both."
	exit 1
fi

echo "reproducible: ${digests[0]}"
