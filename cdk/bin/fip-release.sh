#!/usr/bin/env bash
#
# fip-release.sh — give an analysis account access to a case's evidence, or
# take it away again.
#
#   ./bin/fip-release.sh --case CASE-2026-0001 --to 444455556666
#   ./bin/fip-release.sh --case CASE-2026-0001 --to 444455556666 --revoke
#
# THIS IS A CHAIN-OF-CUSTODY EVENT, which is why it is a separate command and
# not something acquisition does on its own. The analysis account may belong to
# a third party outside your organization, and evidence must never reach an
# outside party as a side effect of opening a case. A human decides, per case,
# and the decision is signed and recorded:
#
#   - a signed custody record at cases/<case>/custody/<timestamp>-release.json
#   - an appended entry on the case row, which a revoke never erases
#
# What a release grants: the analysis account may create volumes from the
# evidence snapshots and decrypt them. It cannot delete them, cannot re-encrypt
# under the forensic key, and cannot widen its own access.
#
# What a revoke does NOT do: it does not destroy volumes already created from
# those snapshots. Ending access and recovering copies are different problems,
# and this command only does the first. It says so again at the end.
#
# Credentials: the ORCHESTRATOR account.
#
# Manual: docs/MANUAL.md §6.11 and §10

set -euo pipefail

CASE_ID=""
ANALYSIS_ACCOUNT=""
REVOKE="false"
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"
ASSUME_YES="false"
DRY_RUN="false"

usage() {
    cat >&2 <<'EOF'
Usage: fip-release.sh --case <case-id> --to <analysis-account-id> [options]

Required:
  --case ID      The case whose evidence is being released.
  --to ACCOUNT   12-digit analysis account id. May be outside your organization.

Options:
  --revoke       Withdraw access instead of granting it.
  --region R     Default: $AWS_REGION, else us-east-1.
  --dry-run      Show what would happen. Changes nothing.
  --yes          Skip the confirmation prompt.
  -h, --help     This message.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --case)   CASE_ID="${2:?--case needs a value}"; shift 2 ;;
        --to)     ANALYSIS_ACCOUNT="${2:?--to needs a value}"; shift 2 ;;
        --revoke) REVOKE="true"; shift ;;
        --region) REGION="${2:?--region needs a value}"; shift 2 ;;
        --dry-run) DRY_RUN="true"; shift ;;
        --yes|-y) ASSUME_YES="true"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "ERROR: unknown argument '$1'" >&2; usage; exit 2 ;;
    esac
done

command -v aws >/dev/null 2>&1 || { echo "ERROR: aws CLI not installed" >&2; exit 1; }
command -v jq  >/dev/null 2>&1 || { echo "ERROR: jq not installed" >&2; exit 1; }

[ -n "$CASE_ID" ]          || { echo "ERROR: --case is required" >&2; usage; exit 2; }
[ -n "$ANALYSIS_ACCOUNT" ] || { echo "ERROR: --to is required" >&2; usage; exit 2; }

if ! printf '%s' "$ANALYSIS_ACCOUNT" | grep -Eq '^[0-9]{12}$'; then
    echo "ERROR: --to '$ANALYSIS_ACCOUNT' is not a 12-digit account id" >&2
    exit 2
fi

ORCHESTRATOR_ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
CALLER_ARN="$(aws sts get-caller-identity --query Arn --output text)"

# The evidence copies come from the case row rather than being retyped. Asking
# an operator to list snapshot ids by hand during an engagement is how the
# wrong case's evidence gets released.
EVIDENCE_ACCOUNT="$(aws lambda get-function-configuration \
    --function-name fip-member-action \
    --region "$REGION" \
    --query 'Environment.Variables.FIP_EVIDENCE_ACCOUNT_ID' --output text)"

if [ -z "$EVIDENCE_ACCOUNT" ] || [ "$EVIDENCE_ACCOUNT" = "None" ]; then
    echo "ERROR: could not read the evidence account id from the fip-member-action" >&2
    echo "       function in ${ORCHESTRATOR_ACCOUNT}. Are these orchestrator credentials?" >&2
    exit 1
fi

echo "Case ............ $CASE_ID"
echo "Action .......... $([ "$REVOKE" = true ] && echo REVOKE || echo RELEASE)"
echo "Analysis acct ... $ANALYSIS_ACCOUNT"
echo "Evidence acct ... $EVIDENCE_ACCOUNT"
echo "Running as ...... $CALLER_ARN"
echo

# Read the case row from the EVIDENCE account, via the same role the Lambda
# uses, so this script needs no permissions the orchestrator does not already
# have.
CREDS="$(aws sts assume-role \
    --role-arn "arn:aws:iam::${EVIDENCE_ACCOUNT}:role/FipEvidenceRole" \
    --role-session-name "release-${CASE_ID:0:48}" \
    --query 'Credentials' --output json --region "$REGION")"

CASE_ROW="$(AWS_ACCESS_KEY_ID="$(jq -r .AccessKeyId <<<"$CREDS")" \
    AWS_SECRET_ACCESS_KEY="$(jq -r .SecretAccessKey <<<"$CREDS")" \
    AWS_SESSION_TOKEN="$(jq -r .SessionToken <<<"$CREDS")" \
    aws dynamodb get-item \
        --table-name fip-cases \
        --key "{\"caseId\":{\"S\":\"${CASE_ID}\"}}" \
        --region "$REGION" --output json 2>/dev/null || echo '{}')"

if [ "$(jq -r 'has("Item")' <<<"$CASE_ROW")" != "true" ]; then
    echo "ERROR: no case '$CASE_ID' in the fip-cases table." >&2
    echo "       Check the id; it is case-sensitive." >&2
    exit 1
fi

CASE_STATE="$(jq -r '.Item.state.S // "unknown"' <<<"$CASE_ROW")"
SNAPSHOTS="$(jq -r '[.Item.targets.M // {} | to_entries[]
                     | .value.M.evidenceSnapshots.SS // [] | .[]]
                    | map(select(. != "none")) | unique' <<<"$CASE_ROW")"
SNAP_COUNT="$(jq 'length' <<<"$SNAPSHOTS")"

echo "Case state ...... $CASE_STATE"
echo "Evidence snaps .. $SNAP_COUNT"
jq -r '.[] | "                  " + .' <<<"$SNAPSHOTS"
echo

if [ "$SNAP_COUNT" -eq 0 ]; then
    echo "ERROR: that case has no evidence copies recorded." >&2
    if [ "$CASE_STATE" = "IN_PROGRESS" ]; then
        echo "       It is still IN_PROGRESS — wait for it to finish." >&2
    fi
    exit 1
fi

PAYLOAD="$(jq -cn \
    --arg action release \
    --arg caseId "$CASE_ID" \
    --arg analysisAccountId "$ANALYSIS_ACCOUNT" \
    --arg actor "$CALLER_ARN" \
    --argjson revoke "$REVOKE" \
    --argjson copies "$SNAPSHOTS" \
    '{action: $action, caseId: $caseId, analysisAccountId: $analysisAccountId,
      actor: $actor, revoke: $revoke, copies: $copies}')"

if [ "$DRY_RUN" = "true" ]; then
    echo "DRY RUN — nothing changed. Payload that would have been sent:"
    jq . <<<"$PAYLOAD"
    exit 0
fi

if [ "$REVOKE" = "true" ]; then
    echo "This REMOVES the snapshot share and retires the case's KMS grant for"
    echo "account ${ANALYSIS_ACCOUNT}. It does NOT destroy volumes that account"
    echo "has already created from this evidence."
else
    echo "This GRANTS account ${ANALYSIS_ACCOUNT} the ability to create volumes"
    echo "from ${SNAP_COUNT} evidence snapshot(s) and decrypt them. If that account"
    echo "belongs to a third party, this is the moment evidence leaves your"
    echo "exclusive control. It is recorded and signed."
fi
echo

if [ "$ASSUME_YES" != "true" ]; then
    printf 'Proceed? [y/N] '
    read -r reply
    case "$reply" in
        y|Y|yes|YES) ;;
        *) echo "Aborted. Nothing changed." >&2; exit 1 ;;
    esac
fi

RESPONSE_FILE="$(mktemp)"
trap 'rm -f "$RESPONSE_FILE"' EXIT

aws lambda invoke \
    --function-name fip-member-action \
    --payload "$(printf '%s' "$PAYLOAD" | base64 | tr -d '\n')" \
    --region "$REGION" \
    "$RESPONSE_FILE" >/dev/null

if jq -e 'has("errorMessage")' "$RESPONSE_FILE" >/dev/null 2>&1; then
    echo "FAILED. Nothing was recorded." >&2
    jq -r '.errorMessage' "$RESPONSE_FILE" >&2
    exit 1
fi

echo
jq -r '
  "Done.\n" +
  "\n  Event ........... " + (.event // "?") +
  "\n  Analysis acct ... " + (.analysisAccountId // "?") +
  "\n  Snapshots ....... " + ((.snapshots // []) | length | tostring) +
  "\n  KMS grants ...... " + ((.kmsGrantIds // []) | join(", ")) +
  "\n  Custody record .. " + (.custodyRecordKey // "?")
' "$RESPONSE_FILE"

cat <<EOF

The custody record is signed with the manifest key and is independently
verifiable; its own \`signature.verify\` field carries the exact command.

EOF

if [ "$REVOKE" = "true" ]; then
    cat <<EOF
REMEMBER: revoking ends future access. Volumes that account already created
from this evidence still exist in it, and recovering or destroying those is a
separate conversation with whoever holds that account.
EOF
else
    cat <<EOF
To end this access later:
  ./bin/fip-release.sh --case $CASE_ID --to $ANALYSIS_ACCOUNT --revoke
EOF
fi
