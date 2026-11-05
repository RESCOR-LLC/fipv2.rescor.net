#!/usr/bin/env bash
#
# fip-restore.sh — put a contained instance back on its original security groups.
#   (normally invoked as: fip restore <account>:<instance>)
#
# Runs with ORCHESTRATOR credentials, like every other fip command. The work is
# done by the fip-member-action Lambda, through FipResponderRole, so the person
# restoring service does not need a login to the affected account.
#
# Where the originals come from: the signed manifest, whose signature the
# Lambda checks against this installation's key before believing it. The
# fip:original-sgs tag on each interface is only a cross-check. If the two
# disagree, that interface is BLOCKED, because a tag anyone in the member
# account can edit must not decide what network a possibly compromised host
# rejoins.
#
# It always plans first and shows the plan. It changes nothing until you
# confirm, and a restore that changes anything is written as a signed custody
# record beside the manifest.
#
# Auto Scaling is reported, not changed. Re-attaching an instance or resuming
# a suspended Launch process puts capacity back from a launch template that may
# be the compromise vector; that stays a human step, and this prints it.

set -euo pipefail

REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"
DRY_RUN="false"
ASSUME_YES="false"
TARGET=""
FUNCTION="fip-member-action"

usage() {
    cat >&2 <<'EOF'
Usage: fip restore <account>:<instance> [--dry-run] [--yes] [--region R]

Puts a contained instance back on the security groups it had before FIP
isolated it. The original groups come from the case's signed manifest.

Run it with ORCHESTRATOR credentials, for example

  AWS_PROFILE=fip-orchestrator fip restore 111122223333:i-0123456789abcdef0

It shows the plan first and changes nothing until you confirm.

  --dry-run   Show the plan only. Changes nothing.
  --yes       Skip the confirmation prompt.
  --region R  Default $AWS_REGION, else us-east-1.

Auto Scaling changes made during containment are reported with the command to
undo each one, but not undone.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run) DRY_RUN="true"; shift ;;
        --yes|-y)  ASSUME_YES="true"; shift ;;
        --region)  REGION="${2:?--region needs a value}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        -*) echo "ERROR: unknown option '$1'" >&2; usage; exit 2 ;;
        *)  [ -z "$TARGET" ] || { echo "ERROR: restore one instance at a time" >&2; exit 2; }
            TARGET="$1"; shift ;;
    esac
done

[ -n "$TARGET" ] || { echo "ERROR: name the instance as <account-id>:<instance-id>" >&2; usage; exit 2; }
ACCOUNT="${TARGET%%:*}"
INSTANCE="${TARGET#*:}"
printf '%s' "$ACCOUNT" | grep -Eq '^[0-9]{12}$' \
    || { echo "ERROR: '$ACCOUNT' is not a 12-digit account id" >&2; exit 2; }
printf '%s' "$INSTANCE" | grep -Eq '^i-[0-9a-f]{8,17}$' \
    || { echo "ERROR: '$INSTANCE' is not an instance id" >&2; exit 2; }

for tool in aws jq; do
    command -v "$tool" >/dev/null 2>&1 || { echo "ERROR: $tool not installed" >&2; exit 1; }
done

CALLER_ARN="$(aws sts get-caller-identity --query Arn --output text)"
if ! aws lambda get-function-configuration --function-name "$FUNCTION" --region "$REGION" \
        --query FunctionName --output text >/dev/null 2>&1; then
    echo "ERROR: no $FUNCTION function visible to $CALLER_ARN in $REGION." >&2
    echo "       Use orchestrator credentials, for example" >&2
    echo "       AWS_PROFILE=fip-orchestrator fip restore $TARGET" >&2
    exit 1
fi

RESPONSE_FILE="$(mktemp)"
trap 'rm -f "$RESPONSE_FILE"' EXIT

invoke() {  # $1 = true to apply, false to plan
    local payload
    payload="$(jq -cn --arg a "$ACCOUNT" --arg i "$INSTANCE" --arg actor "$CALLER_ARN" \
        --argjson apply "$1" \
        '{action: "restore", accountId: $a, instanceId: $i, actor: $actor, apply: $apply}')"
    aws lambda invoke --function-name "$FUNCTION" --region "$REGION" \
        --cli-read-timeout 300 \
        --payload "$(printf '%s' "$payload" | base64 | tr -d '\n')" \
        "$RESPONSE_FILE" >/dev/null
    if jq -e 'has("errorMessage")' "$RESPONSE_FILE" >/dev/null 2>&1; then
        echo "ERROR: $(jq -r .errorMessage "$RESPONSE_FILE")" >&2
        if jq -r .errorMessage "$RESPONSE_FILE" | grep -q 'not authorized\|AccessDenied\|UnauthorizedOperation'; then
            cat >&2 <<EOF

FIP's role in $ACCOUNT may not be allowed to restore. That is the member
stack's AllowRestore parameter; if the account chose No, restore by hand with
that account's own credentials (manual Appendix B.7).
EOF
        fi
        exit 1
    fi
}

show_plan() {
    jq -r '
      "Instance ........ \(.accountId):\(.instanceId)",
      "FIP case ........ \(.caseId)",
      "Originals from .. " + (if .source == "signed-manifest"
          then "the signed manifest (signature checked)"
          else "the fip:original-sgs tag only: no manifest was found" end),
      "",
      "Security groups, per network interface:",
      (.plan[] |
        "  \(.status | . + " " * (8 - length)) \(.eni)" +
        (if .reason then "  \(.reason)" else "" end),
        (if .status == "RESTORE" then
           "           now:        \(.current | join(" "))",
           "           restore to: \(.original | join(" "))"
         else empty end),
        (if .result then "           result:     \(.result)" +
           (if .result == "FAILED" then ", now on \(.after | join(" "))" else "" end)
         else empty end))
    ' "$RESPONSE_FILE"
    echo

    local asg mech
    asg="$(jq -r '.autoScaling.autoScalingGroupName // empty' "$RESPONSE_FILE")"
    if [ -n "$asg" ]; then
        mech="$(jq -r '.autoScaling.mechanism // "unknown"' "$RESPONSE_FILE")"
        echo "Auto Scaling group $asg (reported only; this command does not change it):"
        echo "  Containment detached the instance ($mech)."
        case "$mech" in
            launch-suspended)
                echo "  The group's Launch process is SUSPENDED, so it cannot scale out. To resume:"
                echo "    aws autoscaling resume-processes --auto-scaling-group-name $asg --scaling-processes Launch"
                echo "  It launches the deferred replacement IMMEDIATELY: fix the launch template first." ;;
            desired-capacity-decremented)
                echo "  The group is running one instance short. Raise its desired capacity once"
                echo "  the launch template is known good." ;;
        esac
        echo "  To put this instance back in the group:"
        echo "    aws autoscaling attach-instances --auto-scaling-group-name $asg --instance-ids $INSTANCE"
        echo "  Both run with the member account's credentials."
        echo
    fi
}

invoke false
show_plan

RESTORABLE="$(jq '[.plan[] | select(.status == "RESTORE")] | length' "$RESPONSE_FILE")"
CLEARABLE="$(jq '[.plan[] | select(.status == "OK" and .tag != null)] | length' "$RESPONSE_FILE")"
PROBLEMS="$(jq '[.plan[] | select(.status == "SKIP" or .status == "BLOCKED")] | length' "$RESPONSE_FILE")"

if [ "$RESTORABLE" -eq 0 ] && [ "$CLEARABLE" -eq 0 ]; then
    if [ "$PROBLEMS" -gt 0 ]; then
        echo "Nothing can be restored automatically. See the lines above." >&2
        exit 1
    fi
    echo "Nothing to do: every interface is already on its original groups."
    exit 0
fi

if [ "$DRY_RUN" = "true" ]; then
    echo "DRY RUN: nothing changed. $RESTORABLE interface(s) would be restored."
    exit 0
fi

if [ "$RESTORABLE" -gt 0 ]; then
    echo "This reconnects $INSTANCE to its original network access. If it is still"
    echo "compromised, it can reach out again as soon as this runs. It is recorded"
    echo "as a signed custody event."
    if [ "$ASSUME_YES" != "true" ]; then
        printf 'Proceed? [y/N] '
        read -r reply
        case "$reply" in
            y|Y|yes|YES) ;;
            *) echo "Aborted. Nothing was changed." >&2; exit 1 ;;
        esac
    fi
    echo
fi

invoke true
show_plan

FAILED="$(jq '[.plan[] | select(.result == "FAILED")] | length' "$RESPONSE_FILE")"
RECORD="$(jq -r '.custodyRecordKey // empty' "$RESPONSE_FILE")"
[ -z "$RECORD" ] || echo "Custody record .. $RECORD"

if [ "$FAILED" -gt 0 ]; then
    echo "Restore INCOMPLETE. Interfaces marked FAILED are still isolated or uncertain." >&2
    exit 1
fi
if [ "$PROBLEMS" -gt 0 ]; then
    echo "Restored what could be; interfaces marked SKIP or BLOCKED need a person." >&2
    exit 1
fi
echo "Restored. The isolation security group is left in place: it is free, has no"
echo "rules, and the next case in this VPC reuses it."
