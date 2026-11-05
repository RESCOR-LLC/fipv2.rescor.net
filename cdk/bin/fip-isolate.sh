#!/usr/bin/env bash
#
# fip-isolate.sh — start a FIP case. THIS IS THE COMMAND YOU RUN AT 3AM.
#
#   ./bin/fip-isolate.sh 111111111111:i-0123456789abcdef0
#   ./bin/fip-isolate.sh 1111:i-aaa 2222:i-bbb 2222:i-ccc      # one case, 3 targets
#
# Everything it does could be done with `aws stepfunctions start-execution`
# and a hand-written JSON payload. The reason it exists is that hand-writing
# that payload is the wrong thing to be doing during an incident:
#
#   - It PRE-FLIGHTS every target before starting anything. A mistyped instance
#     id fails here, in two seconds, naming the target — not thirty minutes
#     later inside a state machine that has already tagged and contained
#     something else. Validation uses FipInventoryRole, which is read-only and
#     cannot change a thing.
#   - It generates the case id, so two responders working the same incident
#     cannot invent colliding ones.
#   - It prints the console URL for the execution and the case row, so there is
#     one place to watch.
#
# WHAT IT DOES NOT DO: it does not decide anything. Containment always happens
# (that is what FIP is), and --stop is off unless you ask for it.
#
# Credentials: the ORCHESTRATOR account. The same credentials that can start
# the state machine can run the pre-flight, because FipInventoryRole trusts the
# orchestrator account and the external IDs live in its Parameter Store.
#
# Manual: docs/MANUAL.md §6.6

set -euo pipefail

CASE_ID=""
STOP_INSTANCE="false"
ASG_POLICY="prevent-replacement"
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"
DRY_RUN="false"
ASSUME_YES="false"
WATCH="false"
TARGETS=()

usage() {
    cat >&2 <<'EOF'
Usage: fip-isolate.sh [options] <account-id>:<instance-id> [<account-id>:<instance-id> ...]

Options:
  --case-id ID   Case id to use. Default: fip-<UTC timestamp>-<random>.
                 Reuse an existing id to add targets to a case already open.
  --stop         Stop each instance after containment. OFF by default: it is
                 service-affecting and loses instance-store data for good.
  --allow-replacement
                 Let an Auto Scaling group launch a replacement for each
                 isolated instance, keeping capacity up. OFF by default, and
                 think before using it: the replacement comes from the same
                 launch template, AMI, user data and instance profile, so if
                 the compromise vector is any of those the replacement is
                 just as vulnerable -- detect, isolate, replace, repeat.
                 By default FIP prevents the replacement and leaves the group
                 running short, which is a visible problem a human fixes.
  --region R     AWS region. Default: $AWS_REGION, else us-east-1.
  --dry-run      Pre-flight the targets and print what would run. Starts nothing.
  --yes          Skip the confirmation prompt. For scripted callers.
  --watch        Then follow the case until it finishes (fip status --watch).
  -h, --help     This message.

Examples:
  fip-isolate.sh 111122223333:i-0abc
  fip-isolate.sh --stop --case-id fip-2026-0042 111122223333:i-0abc 444455556666:i-0def
  fip-isolate.sh --dry-run 111122223333:i-0abc
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --case-id) CASE_ID="${2:?--case-id needs a value}"; shift 2 ;;
        --stop)    STOP_INSTANCE="true"; shift ;;
        --allow-replacement) ASG_POLICY="allow-replacement"; shift ;;
        --region)  REGION="${2:?--region needs a value}"; shift 2 ;;
        --dry-run) DRY_RUN="true"; shift ;;
        --yes|-y)  ASSUME_YES="true"; shift ;;
        --watch)   WATCH="true"; shift ;;
        -h|--help) usage; exit 0 ;;
        -*)        echo "ERROR: unknown option '$1'" >&2; usage; exit 2 ;;
        *)         TARGETS+=("$1"); shift ;;
    esac
done

# An incident case's id names a case row, not an isolation run, and the two
# share a table. --case-id reuses an earlier RUN's id.
case "${CASE_ID:-}" in case-*)
    echo "ERROR: $CASE_ID is an incident case, not an isolation run." >&2
    echo "       --case-id takes an earlier run's id (fip-...). Attaching a run to an" >&2
    echo "       incident case is not built yet; see manual §5." >&2
    exit 2 ;;
esac

command -v aws >/dev/null 2>&1 || { echo "ERROR: aws CLI not installed" >&2; exit 1; }
command -v jq  >/dev/null 2>&1 || { echo "ERROR: jq not installed" >&2; exit 1; }

if [ "${#TARGETS[@]}" -eq 0 ]; then
    echo "ERROR: name at least one target as <account-id>:<instance-id>" >&2
    usage
    exit 2
fi

# Generated rather than asked for. An id invented under pressure tends to be
# "test", "case1" or yesterday's — and the id is the partition key of the case
# row and the prefix of every manifest, so a collision merges two incidents.
#
# The suffix is computed in bash rather than piped from /dev/urandom. `tr -dc
# ... </dev/urandom | head -c 6` is the idiomatic one-liner and it is wrong
# here: head closes the pipe at 6 bytes, tr dies of SIGPIPE, and under
# `set -o pipefail` that failure propagates and kills this script before it
# prints anything. Exit 141 and total silence is a miserable thing to debug at
# 3am, which is the only time this script runs.
#
# $RANDOM is not cryptographically strong and does not need to be: this is a
# collision suffix on a UTC timestamp, not a secret. 24 bits plus the second
# is ample for two responders starting cases at once.
if [ -z "$CASE_ID" ]; then
    printf -v CASE_SUFFIX '%06x' "$(( ((RANDOM << 15) | RANDOM) & 0xFFFFFF ))"
    CASE_ID="fip-$(date -u '+%Y%m%dT%H%M%SZ')-${CASE_SUFFIX}"
fi

ORCHESTRATOR_ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
CALLER_ARN="$(aws sts get-caller-identity --query Arn --output text)"

echo "FIP case ........ $CASE_ID"
echo "Region .......... $REGION"
echo "Orchestrator .... $ORCHESTRATOR_ACCOUNT"
echo "Running as ...... $CALLER_ARN"
echo "Stop instances .. $STOP_INSTANCE"
echo "ASG policy ...... $ASG_POLICY"
echo

# ── Pre-flight ───────────────────────────────────────────────────────────
# Read-only, via FipInventoryRole. Every target is checked before ANY target
# is touched: a case that is going to fail on its third target should fail
# before its first is contained.
PREFLIGHT_FAILED=0
VALIDATED=()
TARGET_GIB=()
for target in "${TARGETS[@]}"; do
    account="${target%%:*}"
    instance="${target#*:}"

    if [ "$account" = "$target" ] || [ -z "$account" ] || [ -z "$instance" ]; then
        echo "  INVALID  $target — expected <account-id>:<instance-id>" >&2
        PREFLIGHT_FAILED=1
        continue
    fi
    if ! printf '%s' "$account" | grep -Eq '^[0-9]{12}$'; then
        echo "  INVALID  $target — '$account' is not a 12-digit account id" >&2
        PREFLIGHT_FAILED=1
        continue
    fi
    if ! printf '%s' "$instance" | grep -Eq '^i-[0-9a-f]{8,17}$'; then
        echo "  INVALID  $target — '$instance' is not an instance id" >&2
        PREFLIGHT_FAILED=1
        continue
    fi

    # The external ID is per member account and is issued BY the orchestrator,
    # so it is read from this account's Parameter Store, not supplied here.
    if ! external_id="$(aws ssm get-parameter \
            --name "/fip/member/${account}/external-id" \
            --query 'Parameter.Value' --output text \
            --region "$REGION" 2>/dev/null)"; then
        echo "  NO EXTERNAL ID  $target — /fip/member/${account}/external-id not found." >&2
        echo "                  Has FipMemberStack been deployed to ${account}?" >&2
        PREFLIGHT_FAILED=1
        continue
    fi

    if ! creds="$(aws sts assume-role \
            --role-arn "arn:aws:iam::${account}:role/FipInventoryRole" \
            --role-session-name "${CASE_ID:0:64}" \
            --external-id "$external_id" \
            --duration-seconds 900 \
            --query 'Credentials' --output json \
            --region "$REGION" 2>/dev/null)"; then
        echo "  CANNOT ASSUME  $target — FipInventoryRole in ${account} refused." >&2
        echo "                 Check the external ID and that the stack is current." >&2
        PREFLIGHT_FAILED=1
        continue
    fi

    if ! described="$(AWS_ACCESS_KEY_ID="$(jq -r .AccessKeyId <<<"$creds")" \
            AWS_SECRET_ACCESS_KEY="$(jq -r .SecretAccessKey <<<"$creds")" \
            AWS_SESSION_TOKEN="$(jq -r .SessionToken <<<"$creds")" \
            aws ec2 describe-instances \
                --instance-ids "$instance" \
                --region "$REGION" \
                --query 'Reservations[0].Instances[0].{state:State.Name,type:InstanceType,vpc:VpcId,volumes:length(BlockDeviceMappings)}' \
                --output json 2>/dev/null)"; then
        echo "  NOT FOUND  $target — no such instance in ${account} (${REGION})." >&2
        PREFLIGHT_FAILED=1
        continue
    fi

    state="$(jq -r '.state // "unknown"' <<<"$described")"
    itype="$(jq -r '.type // "unknown"' <<<"$described")"
    volumes="$(jq -r '.volumes // 0' <<<"$described")"

    # ── The volume encryption key must be one FIP can be granted on ──
    # An AWS-MANAGED key (alias/aws/ebs, the default when EBS encryption is on
    # with no key named) has a key policy that CANNOT BE EDITED. So
    # FipResponderRole can never be granted kms:CreateGrant on it, the
    # cross-account share to the evidence account is impossible, and there is
    # no way to fix it after the fact.
    #
    # This is checked HERE because the alternative is what happened on
    # 2026-10-21: the case ran for eight minutes, tagged and contained the
    # instance, created and hashed the snapshot, and only then failed at the
    # share with an AccessDenied nobody could act on.
    vol_ids="$(AWS_ACCESS_KEY_ID="$(jq -r .AccessKeyId <<<"$creds")" \
        AWS_SECRET_ACCESS_KEY="$(jq -r .SecretAccessKey <<<"$creds")" \
        AWS_SESSION_TOKEN="$(jq -r .SessionToken <<<"$creds")" \
        aws ec2 describe-instances --instance-ids "$instance" --region "$REGION" \
            --query 'Reservations[0].Instances[0].BlockDeviceMappings[].Ebs.VolumeId' \
            --output text 2>/dev/null || echo '')"

    for vol in $vol_ids; do
        vol_key="$(AWS_ACCESS_KEY_ID="$(jq -r .AccessKeyId <<<"$creds")" \
            AWS_SECRET_ACCESS_KEY="$(jq -r .SecretAccessKey <<<"$creds")" \
            AWS_SESSION_TOKEN="$(jq -r .SessionToken <<<"$creds")" \
            aws ec2 describe-volumes --volume-ids "$vol" --region "$REGION" \
                --query 'Volumes[0].KmsKeyId' --output text 2>/dev/null || echo 'None')"
        [ "$vol_key" = "None" ] || [ -z "$vol_key" ] && continue   # unencrypted: shareable

        key_mgr="$(AWS_ACCESS_KEY_ID="$(jq -r .AccessKeyId <<<"$creds")" \
            AWS_SECRET_ACCESS_KEY="$(jq -r .SecretAccessKey <<<"$creds")" \
            AWS_SESSION_TOKEN="$(jq -r .SessionToken <<<"$creds")" \
            aws kms describe-key --key-id "$vol_key" --region "$REGION" \
                --query 'KeyMetadata.KeyManager' --output text 2>/dev/null || echo 'UNKNOWN')"

        if [ "$key_mgr" = "AWS" ]; then
            echo "  AWS-MANAGED KEY  $target — volume $vol is encrypted with an" >&2
            echo "                   AWS-managed key, whose policy cannot be edited." >&2
            echo "                   FIP cannot be granted kms:CreateGrant on it, so the" >&2
            echo "                   snapshot can never be shared to the evidence account." >&2
            echo "                   Re-encrypt the volume under a customer-managed key" >&2
            echo "                   whose policy allows FipResponderRole." >&2
            PREFLIGHT_FAILED=1
            continue 2
        elif [ "$key_mgr" = "UNKNOWN" ]; then
            echo "  WARN     $target — could not read the key manager for $vol;" >&2
            echo "           if it is an AWS-managed key the share will fail" >&2
        fi
    done

    # Terminated instances have nothing left to acquire: the volumes are gone
    # unless they were set not to delete on termination. Warn rather than
    # refuse — a responder may know something this script does not.
    case "$state" in
        terminated|shutting-down)
            echo "  WARN     $target — instance is '${state}'; volumes may already be deleted" >&2
            ;;
    esac

    # Provisioned size, for the duration estimate below. Best effort: an
    # unreadable size counts as 0 and only narrows the estimate.
    target_gib=0
    if [ -n "$vol_ids" ]; then
        target_gib="$(AWS_ACCESS_KEY_ID="$(jq -r .AccessKeyId <<<"$creds")" \
            AWS_SECRET_ACCESS_KEY="$(jq -r .SecretAccessKey <<<"$creds")" \
            AWS_SESSION_TOKEN="$(jq -r .SessionToken <<<"$creds")" \
            aws ec2 describe-volumes --volume-ids $vol_ids --region "$REGION" \
                --query 'sum(Volumes[].Size)' --output text 2>/dev/null || echo 0)"
        printf '%s' "$target_gib" | grep -Eq '^[0-9]+$' || target_gib=0
    fi

    printf '  OK       %s  %s  %s  %s volume(s), %s GiB\n' "$target" "$state" "$itype" "$volumes" "$target_gib"
    VALIDATED+=("$target")
    TARGET_GIB+=("$target_gib")
done

echo
if [ "$PREFLIGHT_FAILED" -ne 0 ]; then
    echo "Pre-flight failed. NOTHING has been started, tagged or contained." >&2
    echo "Fix the targets above and re-run. ${#VALIDATED[@]} of ${#TARGETS[@]} target(s) were valid." >&2
    exit 1
fi

# ── Rough duration estimate ──────────────────────────────────────────────
# A magnitude, so a responder knows roughly when a case is late. It is NOT a
# prediction. Copy and hash time follow the data actually written to each
# volume, which FIP cannot see before it snapshots; provisioned size is the
# only figure available up front, so a mostly empty volume finishes well
# inside the range.
#
# Calibrated on live runs: an 8 GiB Linux instance in 8-9 minutes (two runs,
# 2026-10-21 and 2026-11-02) and a 30 GiB Windows volume in about 50. Per
# target: low = 4 + 0.5*GiB, high = 8 + 1.4*GiB minutes. Targets run four at
# a time (FipCase maxConcurrency), so the case takes one target-time per wave
# of four, led by the largest. "Late" is twice the high end.
CASE_CONCURRENCY=4
ESTIMATE="$(printf '%s\n' "${TARGET_GIB[@]}" | sort -rn | awk -v c="$CASE_CONCURRENCY" '
    { if ((NR - 1) % c == 0) { lo += 4 + 0.5 * $1; hi += 8 + 1.4 * $1; waves++ } }
    END { hi = int(hi + 0.999); printf "%d %d %d %d", int(lo), hi, waves, 2 * hi }')"
read -r EST_LOW EST_HIGH EST_WAVES EST_LATE <<<"$ESTIMATE"

# Minutes under two hours read as minutes; anything longer reads as hours.
span() { awk -v lo="$1" -v hi="$2" 'BEGIN {
    if (hi < 120) printf "%d-%d min", lo, hi
    else          printf "%.0f-%.0f hours", lo / 60, (hi + 59) / 60 }'; }
after() { awk -v m="$1" 'BEGIN { if (m < 120) printf "%d min", m; else printf "%.0f hours", (m + 59) / 60 }'; }

echo "Expected duration. A rough guide to when to start worrying, not a promise:"
i=0
for target in "${VALIDATED[@]}"; do
    g="${TARGET_GIB[$i]}"
    printf '  %-34s %5d GiB   about %s\n' "$target" "$g" \
        "$(span "$(awk -v g="$g" 'BEGIN { printf "%d", 4 + 0.5 * g }')" \
                "$(awk -v g="$g" 'BEGIN { printf "%d", int(8 + 1.4 * g + 0.999) }')")"
    i=$((i + 1))
done
EST_SPAN="$(span "$EST_LOW" "$EST_HIGH")"
EST_AFTER="$(after "$EST_LATE")"
echo "  Whole case ......... about ${EST_SPAN}, in ${EST_WAVES} wave(s) of up to ${CASE_CONCURRENCY}"
echo "  Look into it if still IN_PROGRESS after ${EST_AFTER}."
echo "  Based on provisioned size; volumes holding little data finish sooner."
echo

# ── Build the payload ────────────────────────────────────────────────────
PAYLOAD="$(jq -cn \
    --arg caseId "$CASE_ID" \
    --argjson stopInstance "$STOP_INSTANCE" \
    --arg asgPolicy "$ASG_POLICY" \
    --args '
    {
      caseId: $caseId,
      stopInstance: $stopInstance,
      asgPolicy: $asgPolicy,
      targets: [$ARGS.positional[] | split(":") | {accountId: .[0], instanceId: .[1]}]
    }' "${VALIDATED[@]}")"

CASE_MACHINE_ARN="arn:aws:states:${REGION}:${ORCHESTRATOR_ACCOUNT}:stateMachine:FipCase"

if [ "$DRY_RUN" = "true" ]; then
    echo "DRY RUN — nothing started. Payload that would have been sent:"
    jq . <<<"$PAYLOAD"
    echo
    echo "State machine: $CASE_MACHINE_ARN"
    exit 0
fi

echo "About to CONTAIN and ACQUIRE ${#VALIDATED[@]} instance(s):"
printf '  %s\n' "${VALIDATED[@]}"
echo
echo "Containment moves each instance's interfaces to a no-ingress/no-egress"
echo "security group and detaches it from any Auto Scaling group."
if [ "$ASG_POLICY" = "allow-replacement" ]; then
    echo
    echo "--allow-replacement WAS GIVEN: any Auto Scaling group will keep its"
    echo "capacity by LAUNCHING A REPLACEMENT from the same launch template,"
    echo "AMI, user data and instance profile. If the compromise vector is any"
    echo "of those, the replacement will be compromised too and you may end up"
    echo "isolating it in turn. Patch the launch template before relying on this."
else
    echo "Any Auto Scaling group will be left running one instance short rather"
    echo "than launching a replacement from the same (possibly vulnerable)"
    echo "launch template. A group already at its minimum size will instead have"
    echo "its Launch process SUSPENDED, which is group-wide and must be resumed."
fi
if [ "$STOP_INSTANCE" = "true" ]; then
    echo
    echo "--stop WAS GIVEN: each instance will also be STOPPED. Instance-store"
    echo "data will be lost permanently."
fi
echo

if [ "$ASSUME_YES" != "true" ]; then
    printf 'Proceed? [y/N] '
    read -r reply
    case "$reply" in
        y|Y|yes|YES) ;;
        *) echo "Aborted. Nothing was started." >&2; exit 1 ;;
    esac
fi

EXECUTION_ARN="$(aws stepfunctions start-execution \
    --state-machine-arn "$CASE_MACHINE_ARN" \
    --input "$PAYLOAD" \
    --region "$REGION" \
    --query 'executionArn' --output text)"

CONSOLE_BASE="https://${REGION}.console.aws.amazon.com"

# Echo back the credentials this run used. A hint without them runs as
# whatever the operator's default profile is, which is usually NOT the
# orchestrator account, and fails AccessDenied.
PROFILE_PREFIX="${AWS_PROFILE:+AWS_PROFILE=$AWS_PROFILE }"
PROFILE_OPTION="${AWS_PROFILE:+--profile $AWS_PROFILE }"

cat <<EOF

Case started.

  Case id ....... $CASE_ID
  Execution ..... $EXECUTION_ARN
  Targets ....... ${#VALIDATED[@]}
  Expect ........ about ${EST_SPAN}; look into it after ${EST_AFTER}

Follow it from the shell. This reads the case row in the evidence account for you:
  ${PROFILE_PREFIX}fip status $CASE_ID --watch

Or in the console, signed in to the orchestrator account:
  ${CONSOLE_BASE}/states/home?region=${REGION}#/v2/executions/details/${EXECUTION_ARN}

Raw execution status only:
  aws stepfunctions describe-execution ${PROFILE_OPTION}--region $REGION \\
      --execution-arn $EXECUTION_ARN --query status --output text

A case finishes ACQUIRED (every target), PARTIAL (some targets) or FAILED
(none). PARTIAL is a success for the targets that worked — their evidence and
manifests are real. Re-running the same --case-id retries only what you name.
EOF

if [ "$WATCH" = "true" ]; then
    echo
    echo "Following the case (Ctrl-C stops watching; the case carries on):"
    exec "$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)/fip-status.sh" "$CASE_ID" --watch --region "$REGION"
fi
