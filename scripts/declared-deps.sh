#!/usr/bin/env bash
# Enforces invariant 3 of CLAUDE.md: stdlib first, and a new dependency needs a
# justification and the user's agreement rather than a commit.
#
# Note that this repository's rule is NOT the one in genaryx, which forbids
# cloud SDKs outright. Qryx inventories cloud KMS: reaching a provider is its
# job, and the SDKs are justified. Different products, different lines. Copying
# a sibling's list here would be wrong in both directions.
#
# Each entry carries why it is allowed, so adding one means writing a reason
# rather than appending a name.
#
# This file is the ONE copy of this check.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

# name<TAB>reason
ALLOWED=$(
	cat <<'LIST'
github.com/TAIPANBOX/agent-stack-go	the shared wire contract; a local copy is the drift it exists to prevent
github.com/jackc/pgx/v5	the persistence layer, and stdlib database/sql alone will not do the JSON columns
github.com/hashicorp/hcl/v2	correct Terraform parsing; string-scraping .tf files produced false matches
github.com/zclconf/go-cty	hcl's value model, unavoidable once hcl is in
github.com/aws/aws-sdk-go-v2/config	reaching a provider's KMS is this tool's job
github.com/aws/aws-sdk-go-v2/service/kms	same
github.com/aws/aws-sdk-go-v2/service/acm	same, certificates
cloud.google.com/go/kms	same, Google
google.golang.org/api	same, Google's transport
github.com/Azure/azure-sdk-for-go/sdk/azidentity	same, Azure auth
github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys	same, Azure keys
LIST
)

direct=$(go mod edit -json | python3 -c '
import json, sys
mod = json.load(sys.stdin)
for r in mod.get("Require") or []:
    if not r.get("Indirect"):
        print(r["Path"])
')

problems=0

while IFS= read -r d; do
	[ -n "$d" ] || continue
	if ! grep -q "^${d}	" <<<"$ALLOWED"; then
		echo "FAIL: undeclared direct dependency '$d'"
		echo "      Stdlib first. If this one is genuinely needed, add it to the"
		echo "      list in this script WITH A REASON, and to CLAUDE.md invariant 3."
		problems=$((problems + 1))
	fi
done <<<"$direct"

while IFS=$'\t' read -r name reason; do
	[ -n "$name" ] || continue
	if ! grep -qx "$name" <<<"$direct"; then
		echo "FAIL: '$name' is allowed here but no longer a direct dependency"
		echo "      ($reason)"
		echo "      Either it went on purpose, in which case drop it from this list"
		echo "      and from CLAUDE.md together, or something removed it by accident."
		problems=$((problems + 1))
	fi
done <<<"$ALLOWED"

if [ "$problems" -ne 0 ]; then
	echo
	echo "See CLAUDE.md invariant 3."
	exit 1
fi

echo "OK: $(wc -l <<<"$direct" | tr -d ' ') direct dependencies, every one on the list with a reason."
