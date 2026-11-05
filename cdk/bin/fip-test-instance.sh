#!/usr/bin/env bash
#
# fip-test-instance.sh — launch a throwaway instance to try FIP on.
#   (normally invoked as: fip test-instance)
#
# Testing only (manual §6.5). It launches a small Amazon Linux instance in a
# member account, tagged application=fipv2 and fip:class=test, so that
# `fip cleanup --test` finds and removes it and every snapshot FIP takes of
# it. Nothing else here is ever tagged test.
#
# Uses the member account's profile saved by `fip configure`.

set -euo pipefail

CONFIG_FILE="${FIP_CONFIG:-$HOME/.fip/install.env}"
MEMBER=""
TYPE="t3.micro"
SUBNET=""
QUIET="false"

usage() {
    cat >&2 <<'EOF'
Usage: fip test-instance [--member ID] [--type TYPE] [--subnet ID] [--quiet]

Testing only. Launches a small instance to run a case against, tagged so that
`fip cleanup --test` removes it. Prints it as a target, and the command to isolate it.

  --member ID    Member account to launch in. Default: the first one saved
                 by fip configure.
  --type TYPE    Instance type. Default t3.micro.
  --subnet ID    Subnet to launch in. Needed when the account has no
                 default VPC.
  --quiet        Print only the target, <account>:<instance>, for
                 TARGET=$(fip test-instance --quiet).
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --member) MEMBER="${2:?--member needs an account id}"; shift 2 ;;
        --type)   TYPE="${2:?--type needs an instance type}"; shift 2 ;;
        --subnet) SUBNET="${2:?--subnet needs a subnet id}"; shift 2 ;;
        --quiet|-q) QUIET="true"; shift ;;
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

PROFILE=""
for m in $FIP_MEMBERS; do
    if [ -z "$MEMBER" ] || [ "${m%%=*}" = "$MEMBER" ]; then
        MEMBER="${m%%=*}"; PROFILE="${m#*=}"; break
    fi
done
[ -n "$PROFILE" ] || { echo "ERROR: $MEMBER is not a configured member account. Add it with: fip configure" >&2; exit 2; }

AMI="$(aws ssm get-parameter --profile "$PROFILE" --region "$REGION" \
    --name /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64 \
    --query Parameter.Value --output text)"

TAGS='{Key=Name,Value=fip-install-test},{Key=application,Value=fipv2},{Key=fip:class,Value=test}'
NETWORK=()
[ -z "$SUBNET" ] || NETWORK=(--subnet-id "$SUBNET")

echo "Launching a $TYPE test instance in $MEMBER ($PROFILE), $REGION..." >&2
if ! INSTANCE="$(aws ec2 run-instances --profile "$PROFILE" --region "$REGION" \
        --image-id "$AMI" --instance-type "$TYPE" ${NETWORK[@]+"${NETWORK[@]}"} \
        --tag-specifications "ResourceType=instance,Tags=[$TAGS]" "ResourceType=volume,Tags=[$TAGS]" \
        --query 'Instances[0].InstanceId' --output text 2>&1)"; then
    echo "ERROR: $INSTANCE" >&2
    case "$INSTANCE" in
        *VPCIdNotSpecified*|*"default VPC"*|*MissingInput*)
            echo "This account has no default VPC. Name a subnet: fip test-instance --subnet subnet-..." >&2 ;;
    esac
    exit 1
fi

aws ec2 wait instance-running --profile "$PROFILE" --region "$REGION" --instance-ids "$INSTANCE"
if [ "$QUIET" = "true" ]; then
    echo "  ok    $INSTANCE is running" >&2
    echo "$MEMBER:$INSTANCE"
    exit 0
fi
cat <<EOF
  ok    $INSTANCE is running

Test instance ... $MEMBER:$INSTANCE
It bills by the second until removed. Isolate it with:

  fip isolate $MEMBER:$INSTANCE --watch

Remove it, and the snapshots of it, when you are done:

  fip cleanup --test
EOF
