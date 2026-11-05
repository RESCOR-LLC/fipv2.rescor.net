#!/usr/bin/env bash
#
# fip-status.sh — where a case stands.
#   (normally invoked as: fip status <case-id>)
#
#   fip status CASE-2026-0001
#   fip status CASE-2026-0001 --watch
#
# `describe-execution` tells you a case is RUNNING and nothing else. During an
# incident the question is not "is it running", it is "how much longer" — so
# this reports total bytes, how much is done, throughput and an ETA, derived
# from the snapshots themselves rather than from the state machine.
#
# WHERE THE NUMBERS COME FROM, so you can judge them:
#   - Size and percent complete are EC2's own DescribeSnapshots Progress and
#     VolumeSize fields for the evidence copies.
#   - Throughput and ETA are computed from StartTime and that percentage. They
#     are an extrapolation of the average so far, not a prediction: EBS copy
#     throughput is not constant, and a snapshot of a mostly-empty volume
#     finishes far faster than its nominal size suggests. Treat the ETA as an
#     order of magnitude.
#   - VolumeSize is PROVISIONED size, not used bytes. A 500 GiB volume holding
#     8 GiB of data copies like 8 GiB. So the ETA is usually pessimistic early
#     and sharpens as the percentage moves.
#
# Hashing is NOT covered by these numbers. It follows the copy and is reported
# only as a per-target state, because its progress lives in Step Functions Map
# iterations rather than in any resource with a percentage.
#
# Credentials: the ORCHESTRATOR account.

set -euo pipefail

CASE_ID=""
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"
WATCH="false"
INTERVAL=20

usage() {
    cat >&2 <<'EOF'
Usage: fip status <case-id> [options]

Options:
  --watch          Refresh until the case leaves IN_PROGRESS.
  --interval N     Seconds between refreshes with --watch. Default 20.
  --region R       Default: $AWS_REGION, else us-east-1.
  -h, --help       This message.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --watch)    WATCH="true"; shift ;;
        --interval) INTERVAL="${2:?--interval needs a value}"; shift 2 ;;
        --region)   REGION="${2:?--region needs a value}"; shift 2 ;;
        -h|--help)  usage; exit 0 ;;
        -*) echo "ERROR: unknown option '$1'" >&2; usage; exit 2 ;;
        *) CASE_ID="$1"; shift ;;
    esac
done

[ -n "$CASE_ID" ] || { echo "ERROR: name a case id" >&2; usage; exit 2; }
for tool in aws jq python3; do
    command -v "$tool" >/dev/null 2>&1 || { echo "ERROR: $tool not installed" >&2; exit 1; }
done

EVIDENCE_ACCOUNT="$(aws lambda get-function-configuration \
    --function-name fip-member-action --region "$REGION" \
    --query 'Environment.Variables.FIP_EVIDENCE_ACCOUNT_ID' --output text 2>/dev/null || echo '')"

if [ -z "$EVIDENCE_ACCOUNT" ] || [ "$EVIDENCE_ACCOUNT" = "None" ]; then
    echo "ERROR: could not read the evidence account from fip-member-action." >&2
    echo "       Are these orchestrator credentials, and is --region right?" >&2
    exit 1
fi

evidence_env() {
    # Re-assumed on each refresh rather than cached: --watch may run longer
    # than the session, and an expiry mid-poll would look like a status change.
    local creds
    creds="$(aws sts assume-role \
        --role-arn "arn:aws:iam::${EVIDENCE_ACCOUNT}:role/FipEvidenceRole" \
        --role-session-name "status-${CASE_ID:0:48}" \
        --query 'Credentials' --output json --region "$REGION")"
    printf 'AWS_ACCESS_KEY_ID=%s AWS_SECRET_ACCESS_KEY=%s AWS_SESSION_TOKEN=%s' \
        "$(jq -r .AccessKeyId <<<"$creds")" \
        "$(jq -r .SecretAccessKey <<<"$creds")" \
        "$(jq -r .SessionToken <<<"$creds")"
}

report_once() {
    local creds_assignments case_row
    creds_assignments="$(evidence_env)"

    case_row="$(env $creds_assignments aws dynamodb get-item \
        --table-name fip-cases \
        --key "{\"caseId\":{\"S\":\"${CASE_ID}\"}}" \
        --region "$REGION" --output json 2>/dev/null || echo '{}')"

    if [ "$(jq -r 'has("Item")' <<<"$case_row")" != "true" ]; then
        echo "No case '$CASE_ID' in the fip-cases table (evidence account ${EVIDENCE_ACCOUNT})." >&2
        echo "Case ids are case-sensitive." >&2
        return 2
    fi

    local state snapshots
    state="$(jq -r '.Item.state.S // "unknown"' <<<"$case_row")"
    snapshots="$(jq -r '[.Item.targets.M // {} | to_entries[]
                         | .value.M.evidenceSnapshots.SS // [] | .[]]
                        | map(select(. != "none")) | unique' <<<"$case_row")"

    echo "Case ............ $CASE_ID"
    echo "State ........... $state"
    jq -r '
      .Item as $i
      | "Opened .......... " + ($i.openedAt.S // "?")
      + "\nTargets ......... " + ($i.targetCount.N // "?")
      + (if $i.succeededCount then "  (" + $i.succeededCount.N + " ok, " + $i.failedCount.N + " failed)" else "" end)
      + "\nASG policy ...... " + ($i.asgPolicy.S // "prevent-replacement (default)")
    ' <<<"$case_row"
    echo

    echo "Targets:"
    jq -r '.Item.targets.M // {} | to_entries[]
           | "  " + .key + "  " + (.value.M.state.S // "?")
             + "  " + ((.value.M.evidenceSnapshots.SS // []) | length | tostring) + " snapshot(s)"' \
        <<<"$case_row"
    # A requested target with no entry yet has not finished its first step.
    jq -r '
      (.Item.requestedTargets.L // []) as $req
      | (.Item.targets.M // {}) as $done
      | [$req[] | .M.instanceId.S | select($done[.] == null)]
      | if length > 0 then "  (" + (length|tostring) + " target(s) not yet recorded: " + join(", ") + ")" else empty end
    ' <<<"$case_row"
    echo

    local failures
    failures="$(jq -r '(.Item.failures.L // []) | length' <<<"$case_row")"
    if [ "$failures" != "0" ]; then
        echo "Failures:"
        jq -r '.Item.failures.L[]
               | "  " + .M.instanceId.S + " in " + .M.accountId.S + ": " + .M.error.S' <<<"$case_row"
        echo
    fi

    local custody
    custody="$(jq -r '(.Item.custody.L // []) | length' <<<"$case_row")"
    if [ "$custody" != "0" ]; then
        echo "Chain of custody:"
        jq -r '.Item.custody.L[]
               | "  " + .M.at.S + "  " + .M.event.S + "  -> " + .M.analysisAccountId.S' <<<"$case_row"
        echo
    fi

    local count
    count="$(jq 'length' <<<"$snapshots")"
    if [ "$count" = "0" ]; then
        echo "No evidence copies recorded yet."
        [ "$state" = "IN_PROGRESS" ] && echo "The case is still running; copies appear as each target completes."
        return 0
    fi

    # Progress of the evidence copies, which is the long pole of a case.
    local described
    described="$(env $creds_assignments aws ec2 describe-snapshots \
        --snapshot-ids $(jq -r '.[]' <<<"$snapshots" | tr '\n' ' ') \
        --region "$REGION" --output json 2>/dev/null || echo '{"Snapshots":[]}')"

    python3 - <<'PY' "$described"
import json, sys, datetime

data = json.loads(sys.argv[1])
snaps = data.get('Snapshots', [])
if not snaps:
    print('Evidence copies: could not describe them (shared out, or not ready yet).')
    raise SystemExit(0)

now = datetime.datetime.now(datetime.timezone.utc)
total_gib = done_gib = 0.0
oldest = None
pending = []

print('Evidence copies:')
for s in sorted(snaps, key=lambda x: x.get('SnapshotId', '')):
    size = float(s.get('VolumeSize') or 0)
    raw = (s.get('Progress') or '').rstrip('%')
    try:
        pct = float(raw)
    except ValueError:
        pct = 100.0 if s.get('State') == 'completed' else 0.0
    if s.get('State') == 'completed':
        pct = 100.0
    total_gib += size
    done_gib += size * pct / 100.0
    start = s.get('StartTime')
    if isinstance(start, str):
        try:
            st = datetime.datetime.fromisoformat(start.replace('Z', '+00:00'))
            oldest = st if oldest is None or st < oldest else oldest
        except ValueError:
            pass
    flag = '' if s.get('State') == 'completed' else '  <-- in progress'
    if s.get('State') == 'error':
        flag = '  <-- ERROR'
    print(f"  {s.get('SnapshotId','?'):<24} {s.get('State','?'):<10} {pct:5.1f}%  {size:>6.0f} GiB{flag}")
    if s.get('State') not in ('completed', 'error'):
        pending.append(s.get('SnapshotId'))

print()
print(f"  Total ......... {total_gib:.0f} GiB provisioned")
print(f"  Complete ...... {done_gib:.1f} GiB ({(done_gib/total_gib*100 if total_gib else 100):.1f}%)")
print(f"  Remaining ..... {max(total_gib - done_gib, 0):.1f} GiB")

if not pending:
    print('  All copies complete.')
    raise SystemExit(0)

if oldest is None:
    print('  Rate .......... unknown (no start time reported)')
    raise SystemExit(0)

elapsed_min = (now - oldest).total_seconds() / 60.0
if elapsed_min <= 0 or done_gib <= 0:
    print('  Rate .......... not enough elapsed time to estimate')
    raise SystemExit(0)

rate = done_gib / elapsed_min
remaining = max(total_gib - done_gib, 0)
print(f"  Elapsed ....... {elapsed_min:.1f} min")
print(f"  Rate .......... {rate:.2f} GiB/min (average so far)")
if rate > 0:
    eta_min = remaining / rate
    finish = now + datetime.timedelta(minutes=eta_min)
    print(f"  ETA ........... ~{eta_min:.0f} min (around {finish.strftime('%H:%M:%SZ')})")
    print()
    print('  ETA extrapolates the average so far. VolumeSize is PROVISIONED, not used,')
    print('  so a mostly-empty volume finishes much sooner than this suggests. Hashing')
    print('  follows the copy and is not included.')
PY
    return 0
}

if [ "$WATCH" != "true" ]; then
    report_once
    exit $?
fi

while true; do
    clear 2>/dev/null || true
    date -u '+%Y-%m-%dT%H:%M:%SZ'
    echo
    set +e
    report_once
    rc=$?
    set -e
    [ "$rc" = "2" ] && exit 2

    creds_assignments="$(evidence_env)"
    state="$(env $creds_assignments aws dynamodb get-item \
        --table-name fip-cases --key "{\"caseId\":{\"S\":\"${CASE_ID}\"}}" \
        --region "$REGION" --output json 2>/dev/null \
        | jq -r '.Item.state.S // "unknown"')"
    if [ "$state" != "IN_PROGRESS" ]; then
        echo
        echo "Case is $state. Done watching."
        exit 0
    fi
    sleep "$INTERVAL"
done
