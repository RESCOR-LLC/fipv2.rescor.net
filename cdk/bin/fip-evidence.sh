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
TICKET=""
OUT=""

usage() {
    cat >&2 <<'EOF'
Usage: fip evidence <run-id | case-id | --ticket T> [--out DIR]

Downloads the case's manifests and custody records from the evidence bucket,
and verifies each one: unchanged since it was signed, and signed by this
installation's key. Changes nothing in AWS.

For an incident case (case-...): its log and custody records, every
member's manifest and run custody records, and the logs and custody records
of every case merged into it. Each log is also checked as a chain, so a
missing or reordered record fails.

  --out DIR   Where to put them. Default: ./<case-id>
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --out) OUT="${2:?--out needs a directory}"; shift 2 ;;
        --ticket) TICKET="${2:?--ticket needs a value}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        -*) echo "ERROR: unknown option '$1'" >&2; usage; exit 2 ;;
        *) [ -z "$CASE_ID" ] || { echo "ERROR: one case at a time" >&2; exit 2; }
           CASE_ID="$1"; shift ;;
    esac
done
[ -n "$CASE_ID" ] || [ -n "$TICKET" ] || { echo "ERROR: name the case id" >&2; usage; exit 2; }

[ -f "$CONFIG_FILE" ] || { echo "ERROR: no configuration at $CONFIG_FILE. Run: fip configure" >&2; exit 1; }
# shellcheck disable=SC1090
. "$CONFIG_FILE"
REGION="${AWS_REGION:-us-east-1}"
ORCH_PROFILE="${FIP_ORCHESTRATOR_PROFILE:-fip-orchestrator}"
EVID_PROFILE="${FIP_EVIDENCE_PROFILE:-fip-evidence}"
BUCKET="fip-evidence-${FIP_EVIDENCE_ACCOUNT_ID:?missing from $CONFIG_FILE}-$REGION"

# Incident cases are named by id or ticket; a merged one stands for the case
# it merged into.
evidence() { aws --profile "$EVID_PROFILE" --region "$REGION" "$@"; }
# shellcheck source=fip-case-lib.sh
. "$BIN_DIR/fip-case-lib.sh"
case "${CASE_ID:-case-}" in case-*) CASE_ID="$(resolve "$CASE_ID" "$TICKET")" ;; esac
case "$CASE_ID" in */*|*..*) echo "ERROR: '$CASE_ID' is not a case id" >&2; exit 2 ;; esac
OUT="${OUT:-./$CASE_ID}"

KEY_ARN="$(aws cloudformation describe-stacks --profile "$ORCH_PROFILE" --region "$REGION" \
    --stack-name FipOrchestratorStack \
    --query "Stacks[0].Outputs[?OutputKey=='ManifestSigningKeyArn'].OutputValue" --output text)"
case "$KEY_ARN" in arn:*) ;; *)
    echo "ERROR: could not read the signing key from FipOrchestratorStack with profile $ORCH_PROFILE" >&2
    exit 1 ;;
esac

fetch() {  # $1 = prefix under cases/, $2 = local directory
    mkdir -p "$2"
    aws s3 cp --profile "$EVID_PROFILE" --region "$REGION" --recursive --only-show-errors \
        "s3://$BUCKET/cases/$1" "$2/"
}

CHAIN_OK=true
CHAIN_REPORT=""
# One incident case's log and custody records, into $2, with its log checked
# as a chain against the case row: a record deleted, reordered or replaced
# fails even when every remaining record verifies on its own.
fetch_case() {  # $1 = case id, $2 = local directory
    local id="$1" dir="$2" row logged found check
    fetch "$id/" "$dir"
    row="$(get_row "$id")"
    check="$(node "$BIN_DIR/fip-case-log.mjs" "$id" "$dir/log" "$OUT/.signing-key.der")" || true
    logged="$(jq -r '.logSeq.N // "0"' <<<"$row")"
    found="$(jq '.records | length' <<<"$check" 2>/dev/null || echo 0)"
    if jq -e .ok <<<"$check" >/dev/null 2>&1 && [ "$found" -ge "$logged" ]; then
        CHAIN_REPORT+="  ok    $id: $found record(s), chained from OPENED, none missing or out of order"$'\n'
    else
        CHAIN_OK=false
        CHAIN_REPORT+="$(jq -r --arg id "$id" '.problems[]? | "  FAIL  \($id): " + .' <<<"$check")"$'\n'
        [ "$found" -ge "$logged" ] \
            || CHAIN_REPORT+="  FAIL  $id: the case table records $logged record(s), but $found are in the bucket"$'\n'
    fi
}

case "$CASE_ID" in
case-*)
    # An incident case: its own log and custody records, and for every
    # member, that member's manifest and its run's custody records. The
    # members are read from the case row.
    echo "Incident case $CASE_ID"
    mkdir -p "$OUT"
    aws kms get-public-key --profile "$ORCH_PROFILE" --region "$REGION" --key-id "$KEY_ARN" \
        --query PublicKey --output text | base64 -d > "$OUT/.signing-key.der"
    fetch_case "$CASE_ID" "$OUT/case"
    ROW="$(get_row "$CASE_ID")"
    MEMBERS="$(jq -r '(.members.M // {}) | to_entries[] | "\(.value.M.actionId.S) \(.value.M.instanceId.S)"' <<<"$ROW")"
    echo "Members ......... $(grep -c . <<<"$MEMBERS" || true)"
    SEEN_RUNS=" "
    while read -r run instance; do
        [ -n "$run" ] || continue
        echo "  $run/$instance"
        fetch "$run/$instance/" "$OUT/members/$run/$instance"
        case "$SEEN_RUNS" in *" $run "*) ;; *)
            fetch "$run/custody/" "$OUT/members/$run/custody"
            SEEN_RUNS="$SEEN_RUNS$run " ;;
        esac
    done <<<"$MEMBERS"
    # Cases merged into this one, and into those, keep their own logs and
    # custody records: a release made before a merge is recorded only there.
    QUEUE="$(jq -r '(.mergedFrom.SS // [])[]' <<<"$ROW")"
    SEEN_CASES=" $CASE_ID "
    while [ -n "$QUEUE" ]; do
        next=""
        for merged in $QUEUE; do
            case "$SEEN_CASES" in *" $merged "*) continue ;; esac
            SEEN_CASES="$SEEN_CASES$merged "
            echo "Merged in ....... $merged"
            fetch_case "$merged" "$OUT/merged/$merged"
            next="$next $(get_row "$merged" | jq -r '(.mergedFrom.SS // [])[]')"
        done
        QUEUE="$(xargs <<<"$next")"
    done
    rm -f "$OUT/.signing-key.der"
    echo
    echo "Case log chain:"
    printf '%s' "$CHAIN_REPORT"
    echo
    ;;
*)
    echo "Case $CASE_ID, from s3://$BUCKET/cases/$CASE_ID/"
    fetch "$CASE_ID/" "$OUT"
    ;;
esac

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
if [ "$CHAIN_OK" != "true" ]; then
    echo "Every record verifies on its own, but the case log's chain does NOT. Records are" >&2
    echo "missing or out of order; treat the case log as incomplete." >&2
    exit 1
fi
echo "All ${#FILES[@]} record(s) verified: unchanged, and signed by this installation."
echo "Saved in $OUT"
