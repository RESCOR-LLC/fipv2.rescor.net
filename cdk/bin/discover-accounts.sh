#!/usr/bin/env bash
#
# discover-accounts.sh — OPTIONAL convenience. Populates the three account-id
# environment variables FIP needs by looking them up in AWS Organizations.
#
#   source ./bin/discover-accounts.sh
#
# YOU DO NOT NEED THIS. FIP requires no organization. If you know your account ids, just export them and skip this entirely:
#
#   export FIP_ORCHESTRATOR_ACCOUNT_ID=111111111111
#   export FIP_EVIDENCE_ACCOUNT_ID=222222222222
#
# This script exists only so that operators who DO run Organizations do not
# have to copy ids by hand. It looks accounts up by NAME, and the names are
# configurable, because yours will not match anyone else's:
#
#   FIP_ORCHESTRATOR_ACCOUNT_NAME   default "FIP Orchestrator"
#   FIP_EVIDENCE_ACCOUNT_NAME       default "FIP Evidence"
#   FIP_ANALYSIS_ACCOUNT_NAME       default "FIP Analysis"
#
# Requires credentials in the management account, or any account with
# organizations:ListAccounts.
#
# THE THREE ACCOUNTS:
#   Orchestrator — runs the state machine. Holds no evidence.
#   Evidence     — holds the CMK, the Object Lock bucket and the case table.
#   Analysis     — optional, and MAY BE OUTSIDE YOUR ORGANIZATION entirely if a
#                  third-party examiner holds it. Never required at deploy time.
#
# All three may be the same account if that is what you have. Separating them
# is better and is what we recommend; requiring it would be imposing a cloud
# operating model on you, which FIP does not do.

set -e

ORCH_NAME="${FIP_ORCHESTRATOR_ACCOUNT_NAME:-FIP Orchestrator}"
EVID_NAME="${FIP_EVIDENCE_ACCOUNT_NAME:-FIP Evidence}"
ANAL_NAME="${FIP_ANALYSIS_ACCOUNT_NAME:-FIP Analysis}"

command -v aws >/dev/null 2>&1 || { echo "ERROR: aws CLI not installed" >&2; return 1; }

discover() {
    aws organizations list-accounts \
        --query "Accounts[?Name=='${1}' && Status=='ACTIVE'].Id" \
        --output text 2>/dev/null || true
}

export FIP_ORCHESTRATOR_ACCOUNT_ID="${FIP_ORCHESTRATOR_ACCOUNT_ID:-$(discover "$ORCH_NAME")}"
export FIP_EVIDENCE_ACCOUNT_ID="${FIP_EVIDENCE_ACCOUNT_ID:-$(discover "$EVID_NAME")}"
export FIP_ANALYSIS_ACCOUNT_ID="${FIP_ANALYSIS_ACCOUNT_ID:-$(discover "$ANAL_NAME")}"

{
    echo "FIP account discovery:"
    echo "  FIP_ORCHESTRATOR_ACCOUNT_ID = ${FIP_ORCHESTRATOR_ACCOUNT_ID:-<not found: \"$ORCH_NAME\">}"
    echo "  FIP_EVIDENCE_ACCOUNT_ID     = ${FIP_EVIDENCE_ACCOUNT_ID:-<not found: \"$EVID_NAME\">}"
    echo "  FIP_ANALYSIS_ACCOUNT_ID     = ${FIP_ANALYSIS_ACCOUNT_ID:-<not set — expected; optional>}"
    if [ -z "$FIP_ORCHESTRATOR_ACCOUNT_ID" ] || [ -z "$FIP_EVIDENCE_ACCOUNT_ID" ]; then
        echo ""
        echo "  Not found. Either the accounts are named differently — set"
        echo "  FIP_*_ACCOUNT_NAME to match — or they do not exist yet. You can"
        echo "  also skip this script and export the ids directly."
        echo ""
        echo "  If you use AWS Control Tower, vend accounts through Account"
        echo "  Factory rather than organizations:CreateAccount, or they land"
        echo "  unenrolled and unbaselined."
    fi
} >&2
