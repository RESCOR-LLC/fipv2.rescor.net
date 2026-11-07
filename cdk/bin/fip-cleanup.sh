#!/usr/bin/env bash
#
# fip-cleanup.sh — find what FIP made, and remove what a test made.
#   (normally invoked as: fip cleanup)
#
#   fip cleanup --list     everything tagged application=fipv2, in every
#                          configured account. Read-only.
#   fip cleanup --test     terminate test instances and delete test snapshots:
#                          only what carries BOTH application=fipv2 and
#                          fip:class=test (manual §11).
#
# Evidence is never in reach. A snapshot from a real case in a production
# install is fip:class=evidence, and no filter here matches it. That is the
# point of the class tag: a cleanup decides by what a thing IS, not by a case
# id somebody typed.
#
# Uses the accounts and profiles saved by `fip configure`, the same ones
# `fip deploy` uses.

set -euo pipefail

CONFIG_FILE="${FIP_CONFIG:-$HOME/.fip/install.env}"
ACTION=""
DRY_RUN="false"
ASSUME_YES="false"

usage() {
    cat >&2 <<'EOF'
Usage: fip cleanup --list
       fip cleanup --test [--dry-run] [--yes]

  --list      Show everything tagged application=fipv2 in each configured
              account. Changes nothing.
  --test      Terminate instances and delete snapshots tagged both
              application=fipv2 and fip:class=test. Shows them and asks first.
  --dry-run   With --test: show what would be removed. Changes nothing.
  --yes       With --test: do not ask.

Evidence (fip:class=evidence) and FIP's own stacks are never removed by this.
To uninstall FIP, see cdk/RECOVERY.md.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --list)    ACTION="list"; shift ;;
        --test)    ACTION="test"; shift ;;
        --dry-run) DRY_RUN="true"; shift ;;
        --yes|-y)  ASSUME_YES="true"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "ERROR: unknown argument '$1'" >&2; usage; exit 2 ;;
    esac
done
[ -n "$ACTION" ] || { usage; exit 2; }

[ -f "$CONFIG_FILE" ] || { echo "ERROR: no configuration at $CONFIG_FILE. Run: fip configure" >&2; exit 1; }
unset FIP_MEMBERS
# shellcheck disable=SC1090
. "$CONFIG_FILE"
: "${FIP_MEMBERS:?no member accounts in $CONFIG_FILE; rerun fip configure}"
REGION="${AWS_REGION:-us-east-1}"
ORCH_PROFILE="${FIP_ORCHESTRATOR_PROFILE:-fip-orchestrator}"
EVID_PROFILE="${FIP_EVIDENCE_PROFILE:-fip-evidence}"

# Each account once, as "account=profile": orchestrator, evidence, members.
ACCOUNTS=("$FIP_ORCHESTRATOR_ACCOUNT_ID=$ORCH_PROFILE")
[ "$FIP_EVIDENCE_ACCOUNT_ID" = "$FIP_ORCHESTRATOR_ACCOUNT_ID" ] \
    || ACCOUNTS+=("$FIP_EVIDENCE_ACCOUNT_ID=$EVID_PROFILE")
for m in $FIP_MEMBERS; do
    seen="false"
    for a in "${ACCOUNTS[@]}"; do [ "${a%%=*}" = "${m%%=*}" ] && seen="true"; done
    [ "$seen" = "true" ] || ACCOUNTS+=("$m")
done

PRODUCT=(Name=tag:application,Values=fipv2)
TEST=(Name=tag:fip:class,Values=test)

if [ "$ACTION" = "list" ]; then
    for a in "${ACCOUNTS[@]}"; do
        id="${a%%=*}"; profile="${a#*=}"
        echo "Account $id ($profile), $REGION:"
        aws resourcegroupstaggingapi get-resources --profile "$profile" --region "$REGION" \
            --tag-filters Key=application,Values=fipv2 --output json \
          | jq -r '.ResourceTagMappingList
              | map({arn: .ResourceARN, tags: (.Tags | from_entries)})
              | sort_by(.tags["fip:class"] // "", .tags["fip:case"] // "", .arn)[]
              | "  \((.tags["fip:class"] // "-") | . + " " * (15 - length)) \((.tags["fip:case"] // "-") | . + " " * (32 - length)) \(.arn)"' \
          || echo "  (could not list: check the profile signs in)"
        echo
    done
    echo "Columns: class, incident case (fip:case, '-' for none), resource."
    echo "Classes: infrastructure = the stacks and what they hold; evidence = from a real"
    echo "case, never removed by FIP; test = may be removed with: fip cleanup --test"
    echo "Some resource types, IAM roles among them, are not listed by this API."
    exit 0
fi

# ── --test ───────────────────────────────────────────────────────────────
PLAN="$(mktemp)"
trap 'rm -f "$PLAN"' EXIT
for a in "${ACCOUNTS[@]}"; do
    id="${a%%=*}"; profile="${a#*=}"
    aws ec2 describe-instances --profile "$profile" --region "$REGION" \
        --filters "${PRODUCT[@]}" "${TEST[@]}" \
            Name=instance-state-name,Values=pending,running,stopping,stopped \
        --query 'Reservations[].Instances[].[InstanceId,State.Name]' --output text \
      | while read -r iid state; do
            [ -n "$iid" ] && printf 'instance\t%s\t%s\t%s\t%s\n' "$id" "$profile" "$iid" "$state"
        done >> "$PLAN"
    aws ec2 describe-snapshots --profile "$profile" --region "$REGION" --owner-ids self \
        --filters "${PRODUCT[@]}" "${TEST[@]}" \
        --query 'Snapshots[].[SnapshotId,VolumeSize]' --output text \
      | while read -r sid size; do
            [ -n "$sid" ] && printf 'snapshot\t%s\t%s\t%s\t%s GiB\n' "$id" "$profile" "$sid" "$size"
        done >> "$PLAN"
done

if [ ! -s "$PLAN" ]; then
    echo "Nothing tagged application=fipv2 and fip:class=test in any configured account."
    exit 0
fi

echo "Tagged application=fipv2 and fip:class=test:"
awk -F'\t' '{ printf "  %-9s %s  %s  %s\n", $1, $2, $4, $5 }' "$PLAN"
echo
if [ "$DRY_RUN" = "true" ]; then
    echo "DRY RUN: nothing removed."
    exit 0
fi
if [ "$ASSUME_YES" != "true" ]; then
    read -r -p "Terminate these instances and delete these snapshots? This cannot be undone. [y/N] " reply </dev/tty
    case "$reply" in y|Y|yes|YES) ;; *) echo "Stopped. Nothing removed."; exit 1 ;; esac
fi

FAILED=0
# Instances first, per account, then wait: a snapshot can be deleted while its
# instance runs, but terminating first means nothing new is written meanwhile.
# The plan is read on fd 3, so nothing inside the loop can consume it.
while IFS=$'\t' read -r kind id profile rid _ <&3; do
    [ "$kind" = "instance" ] || continue
    if aws ec2 terminate-instances --profile "$profile" --region "$REGION" \
            --instance-ids "$rid" >/dev/null; then
        aws ec2 wait instance-terminated --profile "$profile" --region "$REGION" --instance-ids "$rid" \
            && echo "  terminated $id $rid" || { echo "  FAIL  $rid did not finish terminating" >&2; FAILED=1; }
    else
        echo "  FAIL  could not terminate $id $rid" >&2; FAILED=1
    fi
done 3< "$PLAN"
while IFS=$'\t' read -r kind id profile rid _ <&3; do
    [ "$kind" = "snapshot" ] || continue
    if aws ec2 delete-snapshot --profile "$profile" --region "$REGION" --snapshot-id "$rid"; then
        echo "  deleted    $id $rid"
    else
        echo "  FAIL  could not delete $id $rid" >&2; FAILED=1
    fi
done 3< "$PLAN"

[ "$FAILED" -eq 0 ] || { echo "Some items were not removed (above)." >&2; exit 1; }
echo "Done. The isolation security group is left: it is free and the next isolation reuses it."
