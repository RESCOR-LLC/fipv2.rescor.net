#!/usr/bin/env bash
#
# fip-case.sh — incident cases.
#   (normally invoked as: fip case <verb> ...)
#
# Manual §5 and §6.15. A case is one incident: the isolation runs made under
# it, tickets from your own systems, signed comments, and a state. Every
# change is a signed record in the case's log in the evidence bucket, written
# by the fip-member-action Lambda; this script never signs anything itself.
#
# Writes go through the Lambda with the orchestrator profile. Reads (list,
# show) use the evidence profile, as `fip evidence` does. Both profiles are
# the ones `fip configure` saved.

set -euo pipefail

CONFIG_FILE="${FIP_CONFIG:-$HOME/.fip/install.env}"
BIN_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FUNCTION="fip-member-action"

usage() {
    cat >&2 <<'EOF'
Usage:
  fip case open    [--ticket T]... [--comment C]
  fip case list    [--all] [--ticket T]
  fip case show    <case | --ticket T> [--verify]
  fip case ticket  <case | --ticket T> T [--comment C]
  fip case comment <case | --ticket T> C
  fip case move    <member>... (--to <case> | --ticket T) --comment C
  fip case merge   <into> <from>... --comment C
  fip case close   <case | --ticket T> --comment C [--force]
  fip case reopen  <case | --ticket T> --comment C

An incident case groups the isolations of one incident, with its tickets and
comments. Use one when the incident is still unfolding; for a known, single
isolation, `fip isolate` alone is enough (manual §5.1).

  open      Open a case and print its id. Tickets and a comment are optional.
  list      Open cases. --all adds closed cases and every isolation run.
  show      The case as a timeline, with its log verified: every record
            signed by this installation, and none missing or out of order.
            --verify prints the check for each record.
  ticket    Add a ticket from your own system. A case may carry several.
  comment   Add a signed, permanent comment.
  move      Move members to another open case. A member is one target of an
            isolation run (fip-.../i-...); fip-... is every target of that run,
            case-... every member of that case. Recorded in both cases' logs.
            Nothing is relocated, and no host is touched.
  merge     Move every member of each <from> case into <into>; each <from>
            becomes an alias of <into>, and its tickets are copied across.
            There is no unmerge: move the members back instead.
  close     Close the incident. Refused while any member's host is still
            contained or its evidence is shared to an analysis account;
            --force overrides, and records what it overrode. Deletes nothing.
  reopen    Open a closed case again.

Wherever a case is named, --ticket T also works if exactly one case carries
that ticket. Naming a merged case acts on the case it merged into, and says so.

Isolations join a case only when named: fip isolate --case C (or --ticket T).
Each such run's targets are recorded in the case's log as MEMBER_ATTACHED.
EOF
}

[ $# -gt 0 ] || { usage; exit 2; }
VERB="$1"; shift
case "$VERB" in -h|--help|help) usage; exit 0 ;; esac

for tool in aws jq node; do
    command -v "$tool" >/dev/null 2>&1 || { echo "ERROR: $tool not installed" >&2; exit 1; }
done
[ -f "$CONFIG_FILE" ] || { echo "ERROR: no configuration at $CONFIG_FILE. Run: fip configure" >&2; exit 1; }
# shellcheck disable=SC1090
. "$CONFIG_FILE"
REGION="${AWS_REGION:-us-east-1}"
ORCHESTRATOR_PROFILE="${FIP_ORCHESTRATOR_PROFILE:-fip-orchestrator}"
EVIDENCE_PROFILE="${FIP_EVIDENCE_PROFILE:-fip-evidence}"
BUCKET="fip-evidence-${FIP_EVIDENCE_ACCOUNT_ID:?missing from $CONFIG_FILE}-$REGION"

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

orchestrator() { aws --profile "$ORCHESTRATOR_PROFILE" --region "$REGION" "$@"; }
evidence()     { aws --profile "$EVIDENCE_PROFILE" --region "$REGION" "$@"; }

# ── Writes, through the Lambda ───────────────────────────────────────────
invoke() {  # $1 = JSON payload
    local response="$WORK_DIR/response.json"
    orchestrator lambda invoke --function-name "$FUNCTION" --cli-read-timeout 600 \
        --payload "$(printf '%s' "$1" | base64 | tr -d '\n')" "$response" >/dev/null
    if jq -e 'has("errorMessage")' "$response" >/dev/null 2>&1; then
        echo "ERROR: $(jq -r .errorMessage "$response")" >&2
        exit 1
    fi
    cat "$response"
}

actor() { orchestrator sts get-caller-identity --query Arn --output text; }

# ── Reads, from the case table ───────────────────────────────────────────
# scan_cases, get_row and resolve.
# shellcheck source=fip-case-lib.sh
. "$BIN_DIR/fip-case-lib.sh"

new_case_id() {
    # A collision suffix on a UTC timestamp, not a secret.
    local suffix
    printf -v suffix '%06x' "$(( ((RANDOM << 15) | RANDOM) & 0xFFFFFF ))"
    printf 'case-%s-%s' "$(date -u '+%Y%m%dT%H%M%SZ')" "$suffix"
}

# ── Verbs ────────────────────────────────────────────────────────────────
cmd_open() {
    local tickets='[]' comment=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --ticket)  tickets="$(jq -c --arg t "${2:?--ticket needs a value}" '. + [$t]' <<<"$tickets")"; shift 2 ;;
            --comment) comment="${2:?--comment needs text}"; shift 2 ;;
            *) echo "ERROR: unknown option '$1'" >&2; usage; exit 2 ;;
        esac
    done
    local id payload
    id="$(new_case_id)"
    payload="$(jq -cn --arg id "$id" --arg actor "$(actor)" --argjson tickets "$tickets" --arg comment "$comment" \
        '{action: "case", op: "open", caseId: $id, actor: $actor, tickets: $tickets}
         + (if $comment == "" then {} else {comment: $comment} end)')"
    invoke "$payload" >/dev/null
    echo "Opened case $id"
    [ "$tickets" = "[]" ] || echo "Tickets ......... $(jq -r 'join(", ")' <<<"$tickets")"
    echo
    echo "Set it for the next steps, then isolate into it:"
    echo "  CASE=$id"
    echo "  fip isolate --case \$CASE <account-id>:<instance-id> ..."
}

cmd_list() {
    local all=false ticket=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --all)    all=true; shift ;;
            --ticket) ticket="${2:?--ticket needs a value}"; shift 2 ;;
            *) echo "ERROR: unknown option '$1'" >&2; usage; exit 2 ;;
        esac
    done
    scan_cases | jq -r --argjson all "$all" --arg t "$ticket" '
      map({
        id: .caseId.S,
        kind: (if .kind.S == "case" then "case" else "isolation" end),
        state: (.state.S // "?"),
        opened: (.openedAt.S // ""),
        tickets: (.tickets.SS // []),
        detail: (if .kind.S == "case" then "\(.logSeq.N // "0") log record(s)"
                 else "\(.targetCount.N // "?") target(s)" end)
      })
      | map(select($all or (.kind == "case" and .state == "OPEN")))
      | map(select($t == "" or (.tickets | index($t))))
      | sort_by(.opened) | reverse
      | if length == 0 then
          (if $all then "Nothing in the case table." else "No open cases. fip case list --all shows the rest." end)
        else
          (["CASE", "KIND", "STATE", "OPENED", "TICKETS", ""] | @tsv),
          (.[] | [.id, .kind, .state, .opened[0:16], (if (.tickets | length) > 0 then .tickets | join(",") else "-" end), .detail] | @tsv)
        end' | column -t -s $'\t'
}

our_public_key() {  # writes this installation's signing key, DER, to $1
    orchestrator kms get-public-key --key-id alias/fip-manifest-signing \
        --query PublicKey --output text | base64 -d > "$1"
}

show_isolation() {  # $1 = row
    jq -r '
      "Isolation run ... \(.caseId.S)  (not an incident case)",
      "State ........... \(.state.S // "?")",
      "Opened .......... \(.openedAt.S // "?")",
      "Targets ......... \(.targetCount.N // "?")"
        + (if .succeededCount then "  (\(.succeededCount.N) ok, \(.failedCount.N) failed)" else "" end),
      "",
      (.targets.M // {} | to_entries[] | "  \(.key)  \(.value.M.state.S // "?")"),
      ((.failures.L // [])[] | "  \(.M.instanceId.S)  FAILED  \(.M.error.S)"),
      ((.custody.L // []) | if length > 0 then "", "Custody:" else empty end),
      ((.custody.L // [])[] | "  \(.M.at.S)  \(.M.event.S)")
    ' <<<"$1"
    echo
    echo "For progress and evidence copies: fip status $(jq -r .caseId.S <<<"$1")"
}

cmd_show() {
    local id="" ticket="" verify=false
    while [ $# -gt 0 ]; do
        case "$1" in
            --ticket) ticket="${2:?--ticket needs a value}"; shift 2 ;;
            --verify) verify=true; shift ;;
            -*) echo "ERROR: unknown option '$1'" >&2; usage; exit 2 ;;
            *) [ -z "$id" ] || { echo "ERROR: one case at a time" >&2; exit 2; }; id="$1"; shift ;;
        esac
    done
    id="$(resolve "$id" "$ticket")"
    case "$id" in */*|*..*) echo "ERROR: '$id' is not a case id" >&2; exit 2 ;; esac

    local row
    row="$(get_row "$id")"
    [ -n "$row" ] || { echo "ERROR: no case or isolation run '$id' (ids are case-sensitive)" >&2; exit 1; }
    if [ "$(jq -r '.kind.S // "action"' <<<"$row")" != "case" ]; then
        show_isolation "$row"; return
    fi

    mkdir -p "$WORK_DIR/log"
    evidence s3 cp --recursive --only-show-errors "s3://$BUCKET/cases/$id/log/" "$WORK_DIR/log/"
    our_public_key "$WORK_DIR/ours.der"
    node "$BIN_DIR/fip-case-log.mjs" "$id" "$WORK_DIR/log" "$WORK_DIR/ours.der" > "$WORK_DIR/log.json"

    jq -r '
      "Case ............ \(.caseId.S)",
      "State ........... \(.state.S // "?")",
      "Opened .......... \(.openedAt.S // "?")  by \(.openedBy.S // "?")",
      "Tickets ......... " + ((.tickets.SS // []) | if length > 0 then join(", ") else "none" end),
      (if .mergedFrom then "Merged in ....... " + (.mergedFrom.SS | join(", ")) else empty end),
      (if .closedAt then "Closed .......... \(.closedAt.S)  by \(.closedBy.S // "?")" else empty end),
      "Members ......... " + ((.members.M // {}) | length | tostring)
    ' <<<"$row"
    if [ "$(jq '(.members.M // {}) | length' <<<"$row")" -gt 0 ]; then
        # Release state is per member: it follows the evidence, whichever case
        # the release was made under. Containment: fip status <case>.
        echo
        case_members "$id" false | print_members | sed 's/^/  /'
    fi
    echo
    echo "Timeline:"
    jq -r --arg id "$id" '
      def members: (.members // []) | map("\n        \(.member // "\(.accountId):\(.instanceId)")") | join("");
      .records[] |
      "  \(.seq // "?")  \(.at // "?")  \(.event // "?")"
      + (if .aborted then "  (WITHDRAWN: see the ABORTED record below)" else "" end)
      + (if .event == "OPENED" and ((.tickets // []) | length) > 0 then "  tickets \(.tickets | join(", "))" else "" end)
      + (if .event == "TICKET_ADDED" then "  \(.ticket)" else "" end)
      + (if .event == "MEMBER_ATTACHED" then "  \(.actionId)"
           + ((.members // []) | map("\n        \(.accountId):\(.instanceId)") | join("")) else "" end)
      + (if .event == "MEMBER_MOVED" then
           (if .to == $id then "  in from \(.from // "no case")" else "  out to \(.to)" end)
           + (if .via == "merge" then " (merge)" else "" end) + members
         else "" end)
      + (if .event == "MERGED" then
           (if .mergedInto then "  into \(.mergedInto); this case is now its alias"
            else "  absorbed \(.absorbed)" + (if ((.tickets // []) | length) > 0 then ", tickets \(.tickets | join(", "))" else "" end) end)
         else "" end)
      + (if .event == "RELEASED" or .event == "REVOKED" then
           "  \(if .event == "RELEASED" then "to" else "from" end) \(.analysisAccountId): \(.snapshots | length) snapshot(s) of \(.members | length) member(s)"
         else "" end)
      + (if .event == "CLOSED" and .forced then "  FORCED, overriding:" + ((.overridden // []) | map("\n        " + .) | join("")) else "" end)
      + (if .event == "ABORTED" then "  withdraws record \(.aborts.seq) (\(.aborts.event // "?"))\n        \(.reason // "")" else "" end)
      + (if .comment then "\n        \(.comment)" else "" end)
      + "\n        by \(.actor // "?")"
    ' "$WORK_DIR/log.json"
    echo
    if [ "$verify" = true ]; then
        echo "Each record:"
        jq -r '.records[] | "  " + (if (.problems | length) == 0 then "ok  " else "FAIL" end)
               + "  \(.key)" + (if (.problems | length) > 0 then "\n        " + (.problems | join("\n        ")) else "" end)' \
            "$WORK_DIR/log.json"
        echo
    fi
    local count logged
    count="$(jq '.records | length' "$WORK_DIR/log.json")"
    logged="$(jq -r '.logSeq.N // "0"' <<<"$row")"
    if jq -e '.ok' "$WORK_DIR/log.json" >/dev/null && [ "$count" -ge "$logged" ]; then
        echo "Log ............. VERIFIED  $count record(s), each signed by this installation, none missing or out of order"
    else
        echo "Log ............. FAIL"
        jq -r '.problems[] | "  " + .' "$WORK_DIR/log.json"
        [ "$count" -ge "$logged" ] || echo "  the case table records $logged record(s), but $count are in the bucket"
        exit 1
    fi
}

cmd_ticket() {
    local id="" by="" ticket="" comment=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --ticket)  by="${2:?--ticket needs a value}"; shift 2 ;;
            --comment) comment="${2:?--comment needs text}"; shift 2 ;;
            -*) echo "ERROR: unknown option '$1'" >&2; usage; exit 2 ;;
            *) if [ -z "$id" ] && [ -z "$by" ]; then id="$1"; else ticket="$1"; fi; shift ;;
        esac
    done
    [ -n "$ticket" ] || { echo "ERROR: name the ticket to add" >&2; usage; exit 2; }
    id="$(resolve "$id" "$by")"
    invoke "$(jq -cn --arg id "$id" --arg actor "$(actor)" --arg t "$ticket" --arg c "$comment" \
        '{action: "case", op: "ticket", caseId: $id, actor: $actor, ticket: $t}
         + (if $c == "" then {} else {comment: $c} end)')" >/dev/null
    echo "Case $id now carries ticket $ticket"
}

cmd_comment() {
    local id="" by="" comment=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --ticket) by="${2:?--ticket needs a value}"; shift 2 ;;
            -*) echo "ERROR: unknown option '$1'" >&2; usage; exit 2 ;;
            *) if [ -z "$id" ] && [ -z "$by" ]; then id="$1"; else comment="$1"; fi; shift ;;
        esac
    done
    [ -n "$comment" ] || { echo "ERROR: write the comment" >&2; usage; exit 2; }
    id="$(resolve "$id" "$by")"
    local seq
    seq="$(invoke "$(jq -cn --arg id "$id" --arg actor "$(actor)" --arg c "$comment" \
        '{action: "case", op: "comment", caseId: $id, actor: $actor, comment: $c}')" | jq -r '.record.seq')"
    echo "Comment recorded in case $id, record $seq. It is signed and permanent."
}

cmd_move() {
    local to="" by="" comment="" members='[]'
    while [ $# -gt 0 ]; do
        case "$1" in
            --to)      to="${2:?--to needs a case}"; shift 2 ;;
            --ticket)  by="${2:?--ticket needs a value}"; shift 2 ;;
            --comment) comment="${2:?--comment needs text}"; shift 2 ;;
            -*) echo "ERROR: unknown option '$1'" >&2; usage; exit 2 ;;
            *) members="$(jq -c --arg m "$1" '. + [$m]' <<<"$members")"; shift ;;
        esac
    done
    [ "$members" != "[]" ] || { echo "ERROR: name what to move (fip-.../i-..., fip-... or case-...)" >&2; exit 2; }
    [ -n "$comment" ] || { echo "ERROR: --comment is required: a move is part of the record" >&2; exit 2; }
    to="$(resolve "$to" "$by")"
    local result
    result="$(invoke "$(jq -cn --arg to "$to" --arg actor "$(actor)" --arg c "$comment" --argjson m "$members" \
        '{action: "case", op: "move", caseId: $to, actor: $actor, members: $m, comment: $c}')")"
    jq -r '.moves[] | "Moved to \(.to) from \(.from // "no case"):", (.members[] | "  \(.)")' <<<"$result"
    echo "Recorded in each case's log. fip case show $to"
}

cmd_merge() {
    local comment="" ids=()
    while [ $# -gt 0 ]; do
        case "$1" in
            --comment) comment="${2:?--comment needs text}"; shift 2 ;;
            -*) echo "ERROR: unknown option '$1'" >&2; usage; exit 2 ;;
            *) ids+=("$1"); shift ;;
        esac
    done
    [ "${#ids[@]}" -ge 2 ] || { echo "ERROR: name the case to keep, then the case(s) to merge into it" >&2; exit 2; }
    [ -n "$comment" ] || { echo "ERROR: --comment is required: a merge is part of the record" >&2; exit 2; }
    # Each argument is a case id or, failing that, a ticket exactly one case carries.
    local named=() a into
    for a in "${ids[@]}"; do
        case "$a" in case-*) named+=("$(resolve "$a" "")") ;; *) named+=("$(resolve "" "$a")") ;; esac
    done
    into="${named[0]}"
    local from
    from="$(printf '%s\n' "${named[@]:1}" | jq -R . | jq -sc .)"
    local result
    result="$(invoke "$(jq -cn --arg into "$into" --arg actor "$(actor)" --arg c "$comment" --argjson from "$from" \
        '{action: "case", op: "merge", caseId: $into, actor: $actor, from: $from, comment: $c}')")"
    jq -r '.merged[] | "Merged \(.from) into \(.into)"
        + ", moving \([.moves[].members | length] | add // 0) member(s)"
        + (if (.tickets | length) > 0 then " and tickets \(.tickets | join(", "))" else "" end)' <<<"$result"
    echo "Each merged case is now an alias of $into. fip case show $into"
}

cmd_close_or_reopen() {  # $1 = close | reopen
    local op="$1"; shift
    local id="" by="" comment="" force=false
    while [ $# -gt 0 ]; do
        case "$1" in
            --ticket)  by="${2:?--ticket needs a value}"; shift 2 ;;
            --comment) comment="${2:?--comment needs text}"; shift 2 ;;
            --force)   [ "$op" = close ] || { echo "ERROR: --force is for close" >&2; exit 2; }; force=true; shift ;;
            -*) echo "ERROR: unknown option '$1'" >&2; usage; exit 2 ;;
            *) [ -z "$id" ] || { echo "ERROR: one case at a time" >&2; exit 2; }; id="$1"; shift ;;
        esac
    done
    [ -n "$comment" ] || { echo "ERROR: --comment is required: it is part of the record" >&2; exit 2; }
    id="$(resolve "$id" "$by")"
    [ "$op" = reopen ] || echo "Checking every member: is its host still contained, is its evidence shared..."
    local result
    result="$(invoke "$(jq -cn --arg id "$id" --arg op "$op" --arg actor "$(actor)" --arg c "$comment" --argjson f "$force" \
        '{action: "case", op: $op, caseId: $id, actor: $actor, comment: $c, force: $f}')")"
    if [ "$op" = reopen ]; then
        echo "Case $id is OPEN again (record $(jq -r .record.seq <<<"$result"))."
        return
    fi
    echo "Case $id is CLOSED (record $(jq -r .record.seq <<<"$result")). Nothing was deleted;"
    echo "retention still decides how long its evidence is kept."
    if jq -e .forced <<<"$result" >/dev/null; then
        echo "FORCED. What was overridden is recorded with it:"
        jq -r '.overridden[] | "  " + .' <<<"$result"
    fi
}

case "$VERB" in
    open)    cmd_open "$@" ;;
    close)   cmd_close_or_reopen close "$@" ;;
    reopen)  cmd_close_or_reopen reopen "$@" ;;
    move)    cmd_move "$@" ;;
    merge)   cmd_merge "$@" ;;
    list)    cmd_list "$@" ;;
    show)    cmd_show "$@" ;;
    ticket)  cmd_ticket "$@" ;;
    comment) cmd_comment "$@" ;;
    *) echo "ERROR: unknown verb '$VERB'" >&2; usage; exit 2 ;;
esac
