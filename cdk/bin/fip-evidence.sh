#!/usr/bin/env bash
#
# fip-evidence.sh — download a case's signed records and check each one.
#   (normally invoked as: fip evidence <case-id>)
#
# Manual §6.8. Fetches every manifest and custody record of a case from the
# evidence bucket, then runs `fip verify --key-id` on each against this
# installation's signing key: unchanged since signed, and signed by us.
#
# The records are what this downloads. The evidence itself is the snapshots in
# the evidence account, which stay where they are; `fip release` shares them.
#
# Uses the evidence and orchestrator profiles saved by `fip configure`. Reads
# only; it changes nothing in AWS.

set -euo pipefail

CONFIG_FILE="${FIP_CONFIG:-$HOME/.fip/install.env}"
BIN_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CASE_ID=""
OUT=""

usage() {
    cat >&2 <<'EOF'
Usage: fip evidence <case-id> [--out DIR]

Downloads the case's manifests and custody records from the evidence bucket,
and verifies each one: unchanged since it was signed, and signed by this
installation's key. Changes nothing in AWS.

  --out DIR   Where to put them. Default: ./<case-id>
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --out) OUT="${2:?--out needs a directory}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        -*) echo "ERROR: unknown option '$1'" >&2; usage; exit 2 ;;
        *) [ -z "$CASE_ID" ] || { echo "ERROR: one case at a time" >&2; exit 2; }
           CASE_ID="$1"; shift ;;
    esac
done
[ -n "$CASE_ID" ] || { echo "ERROR: name the case id" >&2; usage; exit 2; }
case "$CASE_ID" in */*|*..*) echo "ERROR: '$CASE_ID' is not a case id" >&2; exit 2 ;; esac
OUT="${OUT:-./$CASE_ID}"

[ -f "$CONFIG_FILE" ] || { echo "ERROR: no configuration at $CONFIG_FILE. Run: fip configure" >&2; exit 1; }
# shellcheck disable=SC1090
. "$CONFIG_FILE"
REGION="${AWS_REGION:-us-east-1}"
ORCH_PROFILE="${FIP_ORCHESTRATOR_PROFILE:-fip-orchestrator}"
EVID_PROFILE="${FIP_EVIDENCE_PROFILE:-fip-evidence}"
BUCKET="fip-evidence-${FIP_EVIDENCE_ACCOUNT_ID:?missing from $CONFIG_FILE}-$REGION"

KEY_ARN="$(aws cloudformation describe-stacks --profile "$ORCH_PROFILE" --region "$REGION" \
    --stack-name FipOrchestratorStack \
    --query "Stacks[0].Outputs[?OutputKey=='ManifestSigningKeyArn'].OutputValue" --output text)"
case "$KEY_ARN" in arn:*) ;; *)
    echo "ERROR: could not read the signing key from FipOrchestratorStack with profile $ORCH_PROFILE" >&2
    exit 1 ;;
esac

echo "Case $CASE_ID, from s3://$BUCKET/cases/$CASE_ID/"
mkdir -p "$OUT"
aws s3 cp --profile "$EVID_PROFILE" --region "$REGION" --recursive --only-show-errors \
    "s3://$BUCKET/cases/$CASE_ID/" "$OUT/"

FILES=()
while IFS= read -r f; do FILES+=("$f"); done < <(find "$OUT" -type f -name '*.json' | sort)
if [ "${#FILES[@]}" -eq 0 ]; then
    echo "ERROR: nothing found for case $CASE_ID. Check the id with: fip status $CASE_ID" >&2
    rmdir "$OUT" 2>/dev/null || true
    exit 1
fi

echo "Checking each against signing key $KEY_ARN"
echo
BAD=0
for f in "${FILES[@]}"; do
    if AWS_PROFILE="$ORCH_PROFILE" AWS_REGION="$REGION" \
            "$BIN_DIR/fip-verify.sh" "$f" --key-id "$KEY_ARN" >/dev/null 2>&1; then
        echo "  ok    ${f#"$OUT"/}"
    else
        echo "  FAIL  ${f#"$OUT"/}   (see: fip verify $f --key-id $KEY_ARN)" >&2
        BAD=$((BAD+1))
    fi
done
echo
if [ "$BAD" -gt 0 ]; then
    echo "$BAD of ${#FILES[@]} record(s) did NOT verify. Treat them as untrusted." >&2
    exit 1
fi
echo "All ${#FILES[@]} record(s) verified: unchanged, and signed by this installation."
echo "Saved in $OUT"
