#!/usr/bin/env bash
#
# fip-instances.sh — list the instances FIP can act on.
#   (normally invoked as: fip instances)
#
# Manual §6.4. Lists running and stopped instances in each member account
# saved by `fip configure`, with the target already written the way
# `fip isolate` and `fip restore` take it (<account>:<instance>), and the case
# FIP has already opened on any of them.
#
# Uses each member account's own profile. Reads only; it changes nothing.

set -euo pipefail

CONFIG_FILE="${FIP_CONFIG:-$HOME/.fip/install.env}"
MEMBER=""
NAME=""
STATES="pending,running,stopping,stopped"

usage() {
    cat >&2 <<'EOF'
Usage: fip instances [--member ID] [--name PATTERN] [--all]

Lists instances in the member accounts saved by fip configure. The TARGET
column is what fip isolate and fip restore take; CASE shows the case FIP
already opened on an instance, if any. Changes nothing.

  --member ID      Only this member account. Default: all of them.
  --name PATTERN   Only instances whose Name tag matches, e.g. 'web-*'.
  --all            Include terminated and shutting-down instances.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --member) MEMBER="${2:?--member needs an account id}"; shift 2 ;;
        --name)   NAME="${2:?--name needs a pattern}"; shift 2 ;;
        --all)    STATES=""; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "ERROR: unknown argument '$1'" >&2; usage; exit 2 ;;
    esac
done

[ -f "$CONFIG_FILE" ] || { echo "ERROR: no configuration at $CONFIG_FILE. Run: fip configure" >&2; exit 1; }
unset FIP_MEMBERS
# shellcheck disable=SC1090
. "$CONFIG_FILE"
: "${FIP_MEMBERS:?no member accounts in $CONFIG_FILE; rerun fip configure}"
REGION="${AWS_REGION:-us-east-1}"

FILTERS=()
[ -z "$STATES" ] || FILTERS+=("Name=instance-state-name,Values=$STATES")
[ -z "$NAME" ]   || FILTERS+=("Name=tag:Name,Values=$NAME")

FOUND=0
printf '%-36s %-10s %-12s %-28s %s\n' TARGET STATE TYPE NAME CASE
for m in $FIP_MEMBERS; do
    account="${m%%=*}"; profile="${m#*=}"
    [ -z "$MEMBER" ] || [ "$account" = "$MEMBER" ] || continue
    if ! rows="$(aws ec2 describe-instances --profile "$profile" --region "$REGION" \
            ${FILTERS[@]+--filters "${FILTERS[@]}"} \
            --query 'Reservations[].Instances[].[InstanceId,State.Name,InstanceType,Tags[?Key==`Name`]|[0].Value,Tags[?Key==`fip:case-id`]|[0].Value]' \
            --output text 2>&1)"; then
        echo "ERROR: $account ($profile): $rows" >&2
        continue
    fi
    while IFS=$'\t' read -r id state type name case_id; do
        [ -n "$id" ] || continue
        [ "$name" != "None" ] || name="-"
        [ "$case_id" != "None" ] || case_id="-"
        printf '%-36s %-10s %-12s %-28s %s\n' "$account:$id" "$state" "$type" "${name:0:28}" "$case_id"
        FOUND=$((FOUND+1))
    done <<<"$rows"
done

if [ "$FOUND" -eq 0 ]; then
    echo "No instances found${MEMBER:+ in $MEMBER}${NAME:+ named '$NAME'}." >&2
    echo "Testing? Launch one with: fip test-instance" >&2
    exit 1
fi
