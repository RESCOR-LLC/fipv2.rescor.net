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
        --projection-expression 'caseId, kind, #s, openedAt, tickets, logSeq, lastEventAt, targetCount, succeededCount, failedCount' \
        --expression-attribute-names '{"#s":"state"}' --output json \
        | jq '.Items'
}

# $1 = id; prints the item, or nothing.
get_row() {
    evidence dynamodb get-item --table-name fip-cases --consistent-read \
        --key "$(jq -cn --arg id "$1" '{caseId: {S: $id}}')" --output json \
        | jq -c '.Item // empty'
}

# A case named directly, or by a ticket exactly one case carries.
resolve() {  # $1 = id or empty, $2 = ticket or empty
    local id="$1" ticket="$2" matches
    if [ -n "$id" ] && [ -n "$ticket" ]; then
        echo "ERROR: name the case or a ticket, not both" >&2; exit 2
    fi
    if [ -n "$id" ]; then printf '%s' "$id"; return; fi
    [ -n "$ticket" ] || { echo "ERROR: name a case, or --ticket T" >&2; exit 2; }
    matches="$(scan_cases | jq -r --arg t "$ticket" \
        '[.[] | select(.kind.S == "case" and ((.tickets.SS // []) | index($t)))] | .[].caseId.S')"
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
