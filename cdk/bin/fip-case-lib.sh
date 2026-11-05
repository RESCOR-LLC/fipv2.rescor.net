# shellcheck shell=bash
#
# fip-case-lib.sh — reading incident cases, shared by `fip case` and the
# commands that take --case / --ticket. Sourced, never run.
#
# The caller defines `evidence`, which runs the aws CLI as the evidence
# profile. Everything here only reads the case table.

# Every row, as one JSON array of items.
scan_cases() {
    evidence dynamodb scan --table-name fip-cases \
        --projection-expression 'caseId, kind, #s, openedAt, tickets, logSeq, lastEventAt, targetCount, succeededCount, failedCount, mergedInto' \
        --expression-attribute-names '{"#s":"state"}' --output json \
        | jq '.Items'
}

# $1 = id; prints the item, or nothing.
get_row() {
    evidence dynamodb get-item --table-name fip-cases --consistent-read \
        --key "$(jq -cn --arg id "$1" '{caseId: {S: $id}}')" --output json \
        | jq -c '.Item // empty'
}

# A merged case is an alias of the case it merged into. Prints the case an id
# stands for, saying so when that is a different one.
follow_alias() {  # $1 = case id
    local id="$1" row next hops=0
    case "$id" in case-*) ;; *) printf '%s' "$id"; return ;; esac
    while :; do
        row="$(get_row "$id")"
        [ -n "$row" ] && [ "$(jq -r '.state.S // ""' <<<"$row")" = "MERGED" ] || break
        next="$(jq -r '.mergedInto.S // ""' <<<"$row")"
        [ -n "$next" ] || break
        echo "NOTE: $id was merged into $next; acting on $next." >&2
        id="$next"; hops=$((hops + 1))
        [ "$hops" -lt 20 ] || { echo "ERROR: merge chain too long at $id" >&2; exit 1; }
    done
    printf '%s' "$id"
}

# A case named directly, or by a ticket exactly one case carries. A merged
# case's tickets were copied to the case it merged into, so merged cases are
# not candidates: the ticket names the survivor.
resolve() {  # $1 = id or empty, $2 = ticket or empty
    local id="$1" ticket="$2" matches
    if [ -n "$id" ] && [ -n "$ticket" ]; then
        echo "ERROR: name the case or a ticket, not both" >&2; exit 2
    fi
    if [ -n "$id" ]; then follow_alias "$id"; return; fi
    [ -n "$ticket" ] || { echo "ERROR: name a case, or --ticket T" >&2; exit 2; }
    matches="$(scan_cases | jq -r --arg t "$ticket" \
        '[.[] | select(.kind.S == "case" and .state.S != "MERGED" and ((.tickets.SS // []) | index($t)))] | .[].caseId.S')"
    case "$(printf '%s' "$matches" | grep -c . || true)" in
        0) echo "ERROR: no case carries ticket $ticket" >&2; exit 1 ;;
        1) printf '%s' "$matches" ;;
        *) echo "ERROR: several cases carry ticket $ticket; name one:" >&2
           printf '  %s\n' $matches >&2; exit 1 ;;
    esac
}

# Exits unless $1 is an incident case that an isolation can attach to now.
# The Lambda checks the same before anything is touched; this says so sooner.
require_open_case() {  # $1 = case id
    local id="$1" row state
    case "$id" in
        case-*) ;;
        fip-*) echo "ERROR: $id is an isolation run, not an incident case." >&2
               echo "       --case takes a case id (case-...); --case-id reuses a run's id." >&2
               exit 2 ;;
        *) echo "ERROR: '$id' is not an incident case id (case-...)" >&2; exit 2 ;;
    esac
    row="$(get_row "$id")"
    if [ -z "$row" ] || [ "$(jq -r '.kind.S // ""' <<<"$row")" != "case" ]; then
        echo "ERROR: no incident case $id (ids are case-sensitive). fip case list shows the open ones." >&2
        exit 1
    fi
    state="$(jq -r '.state.S // "?"' <<<"$row")"
    if [ "$state" != "OPEN" ]; then
        echo "ERROR: case $id is $state. Isolations attach only to open cases." >&2
        exit 1
    fi
}

# Open incident cases, newest first, one per line: id <tab> opened <tab> tickets.
open_cases() {
    scan_cases | jq -r '
      map(select(.kind.S == "case" and .state.S == "OPEN"))
      | sort_by(.openedAt.S // "") | reverse
      | .[] | [.caseId.S, ((.openedAt.S // "?")[0:16]),
               ((.tickets.SS // []) | if length > 0 then join(",") else "-" end)] | @tsv'
}

# A case's members, as the fip-member-action Lambda sees them: acquisition,
# evidence copies, and which analysis accounts can open them. With $2 = true,
# also whether each host is still contained (asked of its account; read-only).
# Runs as the orchestrator: ORCHESTRATOR_PROFILE if the caller set it, else
# the ambient credentials. Prints the Lambda's JSON.
case_members() {  # $1 = case id, $2 = true|false
    local out payload
    out="$(mktemp)"
    payload="$(jq -cn --arg c "$1" --argjson k "${2:-false}" \
        '{action: "case", op: "members", caseId: $c, containment: $k}')"
    aws ${ORCHESTRATOR_PROFILE:+--profile "$ORCHESTRATOR_PROFILE"} --region "${REGION:-us-east-1}" \
        lambda invoke --function-name fip-member-action --cli-read-timeout 600 \
        --payload "$(printf '%s' "$payload" | base64 | tr -d '\n')" "$out" >/dev/null
    if jq -e 'has("errorMessage")' "$out" >/dev/null 2>&1; then
        echo "ERROR: $(jq -r .errorMessage "$out")" >&2
        rm -f "$out"
        exit 1
    fi
    cat "$out"
    rm -f "$out"
}

# The members table, from case_members output on stdin.
print_members() {
    jq -r '
      (["MEMBER", "ACCOUNT", "ACQUISITION", "CONTAINED", "SHARED TO"] | @tsv),
      (.members[] | [.member, .accountId, .acquisition,
        (if .contained == true then "yes" elif .contained == false then (if .containmentNote then "no (gone)" else "no" end)
         elif has("contained") then "unknown" else "-" end),
        (if (.sharedTo | length) > 0 then .sharedTo | join(",") else "-" end)] | @tsv)
    ' | column -t -s $'\t'
}

# For commands that run as the orchestrator: the evidence profile `fip
# configure` saved, to read the case table as fip case does. Defines
# `evidence` unless the caller already has.
use_saved_evidence_profile() {  # $1 = region
    local config="${FIP_CONFIG:-$HOME/.fip/install.env}" p=""
    [ -f "$config" ] && p="$(sed -n 's/^export FIP_EVIDENCE_PROFILE=//p' "$config" | tail -1)"
    FIP_CASE_EVIDENCE_PROFILE="${p:-fip-evidence}"
    FIP_CASE_REGION="$1"
    declare -F evidence >/dev/null || evidence() {
        aws --profile "$FIP_CASE_EVIDENCE_PROFILE" --region "$FIP_CASE_REGION" "$@"
    }
}
