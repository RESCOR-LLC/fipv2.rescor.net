#!/usr/bin/env bash
#
# fip-configure.sh — collect, check and save everything an install needs.
#   (normally invoked as: fip configure)
#
# Asks for anything not given as an option, offering the saved or discovered
# value as the default. Then it creates the AWS CLI profiles, proves each one
# lands in the account it claims, and saves the result to ~/.fip/install.env.
# `fip deploy` reads that file and nothing else, so a deploy never depends on
# what happens to be exported in the current shell.
#
# It changes nothing in AWS. The only things it writes are profiles in
# ~/.aws/config and the file above. An existing profile is never overwritten
# without asking, because it may be how you sign in to that account for other
# work.
#
# ~/.fip/install.env is the same file manual Appendix A.1 writes by hand, so the manual
# and the CLI stay interchangeable: either can pick up where the other left off.

set -euo pipefail

CONFIG_FILE="${FIP_CONFIG:-$HOME/.fip/install.env}"
BIN_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CDK_DIR="$(cd -P "$BIN_DIR/.." && pwd)"

usage() {
    cat >&2 <<'EOF'
Usage: fip configure [options]

Collects the account ids and sign-in details FIP needs, checks them, and saves
them for `fip deploy`. Anything not given as an option is asked for.

  --region R                 AWS region. Default us-east-1.
  --orchestrator ID          Account that runs cases.
  --evidence ID              Account that holds the evidence. May equal the
                             orchestrator.
  --member ID[=PROFILE]      An account FIP covers. Repeatable. PROFILE, if
                             given, is an existing profile to use for it.
  --analysis ID | --no-analysis
                             Optional account where examiners work. The
                             orchestrator needs to know it to release evidence.
  --org-id ID | --no-org     Your AWS Organizations id. Looked up if omitted.
  --admin-role NAME          Role FIP's profiles assume in each account.
                             Default AWSControlTowerExecution; accounts made by
                             AWS Organizations usually have
                             OrganizationAccountAccessRole.
  --source-profile NAME      Credentials those profiles start from. Default
                             "default".
  --orchestrator-profile P   Use an existing profile instead of creating
  --evidence-profile P       fip-orchestrator or fip-evidence.
  --responder Yes|No         Deploy the role that contains and acquires.
                             Default Yes. No gives read-only inventory.
  --allow-restore Yes|No     Let `fip restore` reconnect instances. Default Yes.
  --test                     Test mode, the default: nothing is locked, and
                             everything FIP creates may be removed with
                             `fip cleanup --test`.
  --production               Production mode: every manifest and custody
                             record is locked for --retention-days.
  --retention-days N         How long production evidence is locked. Yours to
                             choose; FIP has no default (manual §8).
  --retention-mode M         GOVERNANCE (default; removable with a logged
                             bypass) or COMPLIANCE (not removable by anyone).
  --tag KEY=VALUE            A tag of your own for everything FIP creates, for
                             example a cost center. Repeatable; replaces the
                             saved list. --no-tags clears it.
  --link | --no-link         Put fip on your PATH as a link in ~/.local/bin, or
                             not. Default: ask, if it is not on your PATH yet.
  --overwrite-profiles       Replace existing fip-* profiles without asking.
  --yes                      Do not ask; fail if something required is missing.
  --show                     Print the saved configuration and exit.

Example, with nothing asked:

  fip configure --yes --region us-east-1 \
    --orchestrator 111111111111 --evidence 222222222222 --member 444444444444
EOF
}

# ── Saved values are the defaults ────────────────────────────────────────
if [ -f "$CONFIG_FILE" ]; then
    # shellcheck disable=SC1090
    . "$CONFIG_FILE"
fi

REGION="${AWS_REGION:-us-east-1}"
ORCH="${FIP_ORCHESTRATOR_ACCOUNT_ID:-}"
EVID="${FIP_EVIDENCE_ACCOUNT_ID:-}"
ORG="${FIP_ORG_ID:-}"
ANALYSIS="${FIP_ANALYSIS_ACCOUNT_ID:-}"
ANALYSIS_GIVEN="false"
ORG_GIVEN="false"
ADMIN_ROLE="${FIP_ADMIN_ROLE:-AWSControlTowerExecution}"
SOURCE_PROFILE="${FIP_SOURCE_PROFILE:-default}"
ORCH_PROFILE="${FIP_ORCHESTRATOR_PROFILE:-fip-orchestrator}"
EVID_PROFILE="${FIP_EVIDENCE_PROFILE:-fip-evidence}"
ANALYSIS_PROFILE="${FIP_ANALYSIS_PROFILE:-fip-analysis}"
RESPONDER="${FIP_DEPLOY_RESPONDER:-Yes}"
ALLOW_RESTORE="${FIP_ALLOW_RESTORE:-Yes}"
PRODUCTION="${FIP_PRODUCTION_MODE:-false}"
RET_MODE="${FIP_RETENTION_MODE:-GOVERNANCE}"
RET_DAYS="${FIP_RETENTION_DAYS:-}"
TAGS="${FIP_TAGS:-}"
MODE_GIVEN="false"
TAGS_GIVEN="false"
SAVED_MEMBERS="${FIP_MEMBERS:-}"
[ -n "$SAVED_MEMBERS" ] || SAVED_MEMBERS="${FIP_MEMBER_ACCOUNT_ID:+$FIP_MEMBER_ACCOUNT_ID=fip-member}"
MEMBERS_GIVEN=()
OVERWRITE="false"
LINK=""
ASSUME_YES="false"

while [ $# -gt 0 ]; do
    case "$1" in
        --region)        REGION="${2:?--region needs a value}"; shift 2 ;;
        --orchestrator)  ORCH="${2:?--orchestrator needs an account id}"; shift 2 ;;
        --evidence)      EVID="${2:?--evidence needs an account id}"; shift 2 ;;
        --member)        MEMBERS_GIVEN+=("${2:?--member needs an account id}"); shift 2 ;;
        --analysis)      ANALYSIS="${2:?--analysis needs an account id}"; ANALYSIS_GIVEN="true"; shift 2 ;;
        --no-analysis)   ANALYSIS=""; ANALYSIS_GIVEN="true"; shift ;;
        --org-id)        ORG="${2:?--org-id needs a value}"; ORG_GIVEN="true"; shift 2 ;;
        --no-org)        ORG="none"; ORG_GIVEN="true"; shift ;;
        --admin-role)    ADMIN_ROLE="${2:?--admin-role needs a role name}"; shift 2 ;;
        --source-profile) SOURCE_PROFILE="${2:?--source-profile needs a name}"; shift 2 ;;
        --orchestrator-profile) ORCH_PROFILE="${2:?needs a profile}"; shift 2 ;;
        --evidence-profile)     EVID_PROFILE="${2:?needs a profile}"; shift 2 ;;
        --responder)     RESPONDER="${2:?--responder needs Yes or No}"; shift 2 ;;
        --allow-restore) ALLOW_RESTORE="${2:?--allow-restore needs Yes or No}"; shift 2 ;;
        --test)          PRODUCTION="false"; MODE_GIVEN="true"; shift ;;
        --production)    PRODUCTION="true"; MODE_GIVEN="true"; shift ;;
        --retention-days) RET_DAYS="${2:?--retention-days needs a number of days}"; shift 2 ;;
        --retention-mode) RET_MODE="${2:?--retention-mode needs GOVERNANCE or COMPLIANCE}"; shift 2 ;;
        --tag)           [ "$TAGS_GIVEN" = "true" ] || TAGS=""
                         TAGS="${TAGS:+$TAGS }${2:?--tag needs KEY=VALUE}"; TAGS_GIVEN="true"; shift 2 ;;
        --no-tags)       TAGS=""; TAGS_GIVEN="true"; shift ;;
        --link)          LINK="Yes"; shift ;;
        --no-link)       LINK="No"; shift ;;
        --overwrite-profiles) OVERWRITE="true"; shift ;;
        --yes|-y)        ASSUME_YES="true"; shift ;;
        --show)
            if [ -f "$CONFIG_FILE" ]; then echo "$CONFIG_FILE:"; cat "$CONFIG_FILE"
            else echo "No configuration yet. Run: fip configure"; fi
            exit 0 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "ERROR: unknown argument '$1'" >&2; usage; exit 2 ;;
    esac
done

for tool in aws jq npx openssl python3; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "ERROR: $tool is not installed. FIP needs aws (v2), jq, Node.js, openssl and python3." >&2
        exit 1
    }
done

# ── Helpers ──────────────────────────────────────────────────────────────
is_account() { printf '%s' "$1" | grep -Eq '^[0-9]{12}$'; }

ask() {  # ask VAR "question" default
    local __var="$1" question="$2" default="${3:-}" reply
    if [ "$ASSUME_YES" = "true" ]; then
        printf -v "$__var" '%s' "$default"; return
    fi
    if [ -n "$default" ]; then
        read -r -p "$question [$default]: " reply </dev/tty
    else
        read -r -p "$question: " reply </dev/tty
    fi
    printf -v "$__var" '%s' "${reply:-$default}"
}

ask_account() {  # ask_account VAR "question" default
    local __var="$1" value
    while :; do
        ask value "$2" "${3:-}"
        if is_account "$value"; then printf -v "$__var" '%s' "$value"; return; fi
        if [ "$ASSUME_YES" = "true" ]; then
            echo "ERROR: $2 is required: '${value:-empty}' is not a 12-digit account id" >&2
            exit 2
        fi
        echo "  '$value' is not a 12-digit account id. Try again."
    done
}

ask_yes_no() {  # ask_yes_no VAR "question" default(Yes|No)
    local __var="$1" value
    while :; do
        ask value "$2 (Yes/No)" "$3"
        case "$value" in
            y|Y|yes|Yes|YES) printf -v "$__var" Yes; return ;;
            n|N|no|No|NO)    printf -v "$__var" No; return ;;
        esac
        [ "$ASSUME_YES" != "true" ] || { echo "ERROR: '$value' is not Yes or No" >&2; exit 2; }
    done
}

# A tag of the customer's own. FIP's keys are reserved so a customer tag can
# never relabel something's class, and with it what a cleanup may remove.
valid_tags() {  # valid_tags "k=v k2=v2"; prints the reason and fails if not
    local t key value
    for t in $1; do
        key="${t%%=*}"; value="${t#*=}"
        if [ "$t" = "$key" ] || [ -z "$key" ] || [ -z "$value" ]; then
            echo "'$t' is not KEY=VALUE"; return 1
        fi
        printf '%s' "$t" | grep -Eq '^[A-Za-z0-9_.:/+@-]+=[A-Za-z0-9_.:/+@-]+$' \
            || { echo "'$t' may use letters, digits and _ . : / + @ - only"; return 1; }
        case "$key" in
            aws:*|fip:*|application) echo "'$key' is reserved"; return 1 ;;
        esac
    done
}

profile_role() { aws configure get role_arn --profile "$1" 2>/dev/null || true; }
profile_exists() {
    aws configure list-profiles 2>/dev/null | grep -qx "$1"
}
profile_account() {
    aws sts get-caller-identity --profile "$1" --query Account --output text 2>/dev/null || true
}

# ── 1. Region and the organization ───────────────────────────────────────
echo "FIP configuration. Press Enter to accept the value in brackets."
echo
ask REGION "AWS region" "$REGION"

ORG_ACCOUNTS=""
if aws sts get-caller-identity --profile "$SOURCE_PROFILE" >/dev/null 2>&1; then
    ORG_ERR="$(mktemp)"
    LOOKED_UP_ORG="$(aws organizations describe-organization --profile "$SOURCE_PROFILE" \
        --query Organization.Id --output text 2>"$ORG_ERR" || true)"
    # Not in an organization is an answer ("none"); a lookup that failed is
    # not, and leaves the organization blank so fip deploy stops and asks.
    grep -q AWSOrganizationsNotInUseException "$ORG_ERR" && LOOKED_UP_ORG="none"
    rm -f "$ORG_ERR"
    if [ "$ORG_GIVEN" != "true" ]; then
        case "$LOOKED_UP_ORG" in o-*|none) ORG="$LOOKED_UP_ORG" ;; *) ;; esac
    fi
    ORG_ACCOUNTS="$(aws organizations list-accounts --profile "$SOURCE_PROFILE" \
        --query "Accounts[?Status=='ACTIVE'].[Id,Name]" --output text 2>/dev/null || true)"
else
    echo "WARN  profile '$SOURCE_PROFILE' has no working credentials, so nothing can be"
    echo "      looked up. Sign in with it first, or pass --source-profile."
fi
if [ -n "$ORG" ]; then
    echo "Organization .... $ORG"
else
    echo "WARN  Organization: unknown. The lookup failed, so fip deploy will stop until you"
    echo "      choose: --org-id o-...   or, with no AWS Organization, --no-org"
fi

if [ -n "$ORG_ACCOUNTS" ] && [ "$ASSUME_YES" != "true" ]; then
    echo
    echo "Accounts in your organization:"
    printf '%s\n' "$ORG_ACCOUNTS" | awk -F'\t' '{ printf "  %s  %s\n", $1, $2 }'
fi
echo

# ── 2. Accounts ──────────────────────────────────────────────────────────
ask_account ORCH "Orchestrator account (runs the cases)" "$ORCH"
ask_account EVID "Evidence account (holds the evidence; may be the same)" "${EVID:-$ORCH}"

MEMBERS=()
if [ "${#MEMBERS_GIVEN[@]}" -gt 0 ]; then
    MEMBERS=("${MEMBERS_GIVEN[@]}")
else
    default_ids=""
    for m in $SAVED_MEMBERS; do default_ids="$default_ids ${m%%=*}"; done
    ask ids "Member accounts FIP covers, separated by spaces" "${default_ids# }"
    for id in $ids; do MEMBERS+=("$id"); done
fi
[ "${#MEMBERS[@]}" -gt 0 ] || { echo "ERROR: at least one member account is needed" >&2; exit 2; }

# Normalize to id=profile, keeping a saved profile for an id when there is one.
NORMALIZED=()
for m in "${MEMBERS[@]}"; do
    id="${m%%=*}"; profile=""
    [ "$m" = "$id" ] || profile="${m#*=}"
    is_account "$id" || { echo "ERROR: member '$id' is not a 12-digit account id" >&2; exit 2; }
    if [ -z "$profile" ]; then
        for s in $SAVED_MEMBERS; do [ "${s%%=*}" = "$id" ] && profile="${s#*=}"; done
    fi
    # The first member keeps the manual's name, fip-member; others get their id.
    [ -n "$profile" ] || { [ "${#NORMALIZED[@]}" -eq 0 ] && profile=fip-member || profile="fip-member-$id"; }
    NORMALIZED+=("$id=$profile")
done

if [ "$ANALYSIS_GIVEN" != "true" ] && [ "$ASSUME_YES" != "true" ]; then
    while :; do
        ask ANALYSIS "Analysis account, optional (type none for none)" "${ANALYSIS:-none}"
        [ "$ANALYSIS" != "none" ] || ANALYSIS=""
        if [ -z "$ANALYSIS" ] || is_account "$ANALYSIS"; then break; fi
        echo "  '$ANALYSIS' is not a 12-digit account id. Try again."
    done
fi
if [ -n "$ANALYSIS" ] && ! is_account "$ANALYSIS"; then
    echo "ERROR: analysis '$ANALYSIS' is not a 12-digit account id" >&2; exit 2
fi

echo
ask ADMIN_ROLE "Role to assume in each account" "$ADMIN_ROLE"
ask_yes_no RESPONDER "Deploy the responder role, so FIP can contain and acquire" "$RESPONDER"
if [ "$RESPONDER" = "Yes" ]; then
    ask_yes_no ALLOW_RESTORE "Let 'fip restore' reconnect contained instances" "$ALLOW_RESTORE"
fi
echo

# ── Test or production ───────────────────────────────────────────────────
# Retention is the customer's decision, so production has no default
# duration: it must be typed or passed (manual §8).
if [ "$MODE_GIVEN" != "true" ] && [ "$ASSUME_YES" != "true" ]; then
    echo "Test mode locks nothing, and 'fip cleanup --test' can remove what a test made."
    echo "Production mode locks every manifest and custody record for a period you choose."
    while :; do
        current="test"; [ "$PRODUCTION" != "true" ] || current="production"
        ask mode "Test or production" "$current"
        case "$mode" in
            test|Test|TEST) PRODUCTION="false"; break ;;
            production|Production|PRODUCTION) PRODUCTION="true"; break ;;
        esac
        echo "  Type test or production."
    done
fi
if [ "$PRODUCTION" = "true" ]; then
    while :; do
        if [ "$ASSUME_YES" != "true" ] && { [ "$MODE_GIVEN" != "true" ] || [ -z "$RET_DAYS" ]; }; then
            ask RET_DAYS "Days to lock each piece of evidence (your decision; no default)" "$RET_DAYS"
        fi
        printf '%s' "$RET_DAYS" | grep -Eq '^[1-9][0-9]*$' && break
        [ "$ASSUME_YES" != "true" ] || { echo "ERROR: production needs --retention-days, a whole number of days" >&2; exit 2; }
        echo "  '$RET_DAYS' is not a whole number of days."
        RET_DAYS=""
    done
    while :; do
        [ "$ASSUME_YES" = "true" ] || [ "$MODE_GIVEN" = "true" ] \
            || ask RET_MODE "Lock mode: GOVERNANCE (removable, logged) or COMPLIANCE (by no one)" "$RET_MODE"
        case "$RET_MODE" in
            governance|Governance) RET_MODE=GOVERNANCE ;;
            compliance|Compliance) RET_MODE=COMPLIANCE ;;
        esac
        case "$RET_MODE" in GOVERNANCE|COMPLIANCE) break ;; esac
        [ "$ASSUME_YES" != "true" ] && [ "$MODE_GIVEN" != "true" ] \
            || { echo "ERROR: --retention-mode is GOVERNANCE or COMPLIANCE, not '$RET_MODE'" >&2; exit 2; }
        echo "  Type GOVERNANCE or COMPLIANCE."
    done
fi

# ── Your own tags ────────────────────────────────────────────────────────
if [ "$TAGS_GIVEN" != "true" ] && [ "$ASSUME_YES" != "true" ]; then
    echo
    echo "FIP tags what it creates with application=fipv2. You may add tags of your own,"
    echo "such as a cost center, as KEY=VALUE separated by spaces."
    while :; do
        ask TAGS "Your tags (type none for none)" "${TAGS:-none}"
        [ "$TAGS" != "none" ] || TAGS=""
        why="$(valid_tags "$TAGS")" && break
        echo "  $why. Try again."
    done
fi
why="$(valid_tags "$TAGS")" || { echo "ERROR: tag $why" >&2; exit 2; }
echo

# ── 3. Profiles ──────────────────────────────────────────────────────────
# One profile per account, and never a second one for the same access:
#   1. the saved or named profile, if it lands in the account, is kept;
#   2. else an existing profile that assumes the same role there is reused,
#      and an Identity Center profile for that account is offered;
#   3. else one is written that assumes ADMIN_ROLE, from SOURCE_PROFILE.
# The result is in CHOSEN, and is what gets saved.
FAILED=0
CHOSEN=""

# Profiles that point at ACCOUNT, read from the config file without signing
# in: "role <name>" for role_arn == WANT, "sso <name>" for sso_account_id ==
# ACCOUNT. Identity Center access depends on the permission set, which the
# file does not say, so those are offered rather than taken.
candidates() {  # candidates ACCOUNT WANT
    local file="${AWS_CONFIG_FILE:-$HOME/.aws/config}"
    [ -f "$file" ] || return 0
    awk -v id="$1" -v want="$2" '
        function flush() {
            if (name == "") return
            if (role == want) print "role " name
            else if (sso == id) print "sso " name
        }
        /^\[/ { flush(); name = $0; gsub(/^\[(profile )?|\][ \t]*$/, "", name); role = ""; sso = ""; next }
        /^[ \t]*role_arn[ \t]*=/       { v = $0; sub(/^[^=]*=[ \t]*/, "", v); sub(/[ \t]+$/, "", v); role = v }
        /^[ \t]*sso_account_id[ \t]*=/ { v = $0; sub(/^[^=]*=[ \t]*/, "", v); sub(/[ \t]+$/, "", v); sso = v }
        END { flush() }' "$file"
}

reuse_existing() {  # reuse_existing SKIP_NAME ACCOUNT WANT -> sets CHOSEN, or fails
    local skip="$1" id="$2" want="$3" kind cand reply
    while read -r kind cand; do
        [ -n "$cand" ] && [ "$cand" != "$skip" ] || continue
        [ "$(profile_account "$cand")" = "$id" ] || continue
        if [ "$kind" = "role" ]; then
            echo "  ok    $cand -> $id (existing profile reused: it assumes $ADMIN_ROLE there)"
            CHOSEN="$cand"; return 0
        fi
        # Identity Center: same account, access set by its permission set.
        [ "$ASSUME_YES" != "true" ] || continue
        read -r -p "  $cand signs in to $id through Identity Center. Use it for FIP? [Y/n] " reply </dev/tty
        case "$reply" in n|N|no|NO) continue ;; esac
        echo "  ok    $cand -> $id (existing profile reused)"
        CHOSEN="$cand"; return 0
    done < <(candidates "$id" "$want" | sort)   # role before sso
    return 1
}

ensure_profile() {  # ensure_profile NAME ACCOUNT -> sets CHOSEN
    local name="$1" id="$2" want="arn:aws:iam::$2:role/$ADMIN_ROLE" have landed reply
    CHOSEN="$name"
    if profile_exists "$name"; then
        landed="$(profile_account "$name")"
        if [ "$landed" = "$id" ]; then
            echo "  ok    $name -> $id (existing profile kept)"
            return
        fi
    fi
    if reuse_existing "$name" "$id" "$want"; then return; fi
    CHOSEN="$name"
    if profile_exists "$name"; then
        have="$(profile_role "$name")"
        if [ "$OVERWRITE" != "true" ]; then
            if [ "$ASSUME_YES" = "true" ]; then
                echo "  FAIL  $name exists but lands in '${landed:-nothing}', not $id." >&2
                echo "        Fix it, or rerun with --overwrite-profiles." >&2
                FAILED=1; return
            fi
            read -r -p "  $name exists (${have:-no role_arn}) and lands in '${landed:-nothing}'. Replace it? [y/N] " reply </dev/tty
            case "$reply" in y|Y|yes|YES) ;; *) echo "  FAIL  $name left unchanged" >&2; FAILED=1; return ;; esac
        fi
    fi
    aws configure set role_arn "$want" --profile "$name"
    aws configure set source_profile "$SOURCE_PROFILE" --profile "$name"
    aws configure set region "$REGION" --profile "$name"
    landed="$(profile_account "$name")"
    if [ "$landed" = "$id" ]; then
        echo "  ok    $name -> $id"
    else
        echo "  FAIL  $name cannot reach $id. Check that $ADMIN_ROLE exists there and that" >&2
        echo "        '$SOURCE_PROFILE' may assume it." >&2
        FAILED=1
    fi
}

echo "Profiles, each checked by signing in:"
ensure_profile "$ORCH_PROFILE" "$ORCH"; ORCH_PROFILE="$CHOSEN"
if [ "$EVID" = "$ORCH" ]; then
    EVID_PROFILE="$ORCH_PROFILE"
else
    ensure_profile "$EVID_PROFILE" "$EVID"; EVID_PROFILE="$CHOSEN"
fi
# A member that is also the orchestrator or evidence account shares its profile.
RESOLVED=()
for m in "${NORMALIZED[@]}"; do
    id="${m%%=*}"
    if [ "$id" = "$ORCH" ]; then RESOLVED+=("$id=$ORCH_PROFILE"); continue; fi
    if [ "$id" = "$EVID" ]; then RESOLVED+=("$id=$EVID_PROFILE"); continue; fi
    ensure_profile "${m#*=}" "$id"; RESOLVED+=("$id=$CHOSEN")
done
NORMALIZED=("${RESOLVED[@]}")
# The analysis account gets a profile too, for deploying its stack (manual §10).
# It may belong to a third party who deploys it with their own credentials, so
# a profile that cannot reach it is a warning here, not a failure.
if [ -z "$ANALYSIS" ]; then
    ANALYSIS_PROFILE=""
elif [ "$ANALYSIS" = "$ORCH" ]; then
    ANALYSIS_PROFILE="$ORCH_PROFILE"
elif [ "$ANALYSIS" = "$EVID" ]; then
    ANALYSIS_PROFILE="$EVID_PROFILE"
else
    BEFORE="$FAILED"
    ensure_profile "$ANALYSIS_PROFILE" "$ANALYSIS"; ANALYSIS_PROFILE="$CHOSEN"
    if [ "$FAILED" != "$BEFORE" ]; then
        FAILED="$BEFORE"
        echo "        Not fatal: needed only if you deploy the analysis stack yourself." >&2
        ANALYSIS_PROFILE=""
    fi
fi
FIRST_MEMBER="${NORMALIZED[0]%%=*}"
FIRST_PROFILE="${NORMALIZED[0]#*=}"
echo

# ── 4. Save ──────────────────────────────────────────────────────────────
mkdir -p "$(dirname "$CONFIG_FILE")"
TMP="$(mktemp "${CONFIG_FILE}.XXXXXX")"
{
    echo "# Written by 'fip configure' on $(date -u +%Y-%m-%dT%H:%M:%SZ). Read by 'fip deploy'."
    echo "# Also the file manual Appendix A.1 writes; reload it with: source $CONFIG_FILE"
    echo "export AWS_REGION=$REGION"
    echo "export FIP_ORCHESTRATOR_ACCOUNT_ID=$ORCH"
    echo "export FIP_EVIDENCE_ACCOUNT_ID=$EVID"
    echo "export FIP_MEMBER_ACCOUNT_ID=$FIRST_MEMBER"
    echo "export FIP_MEMBERS=\"${NORMALIZED[*]}\""
    echo "export FIP_ORG_ID=$ORG"
    echo "export FIP_ANALYSIS_ACCOUNT_ID=$ANALYSIS"
    echo "export FIP_ADMIN_ROLE=$ADMIN_ROLE"
    echo "export FIP_SOURCE_PROFILE=$SOURCE_PROFILE"
    echo "export FIP_ORCHESTRATOR_PROFILE=$ORCH_PROFILE"
    echo "export FIP_EVIDENCE_PROFILE=$EVID_PROFILE"
    echo "export FIP_ANALYSIS_PROFILE=$ANALYSIS_PROFILE"
    echo "export FIP_MEMBER_PROFILE=$FIRST_PROFILE"
    echo "export FIP_DEPLOY_RESPONDER=$RESPONDER"
    echo "export FIP_ALLOW_RESTORE=$ALLOW_RESTORE"
    echo "export FIP_PRODUCTION_MODE=$PRODUCTION"
    if [ "$PRODUCTION" = "true" ]; then
        echo "export FIP_RETENTION_MODE=$RET_MODE"
        echo "export FIP_RETENTION_DAYS=$RET_DAYS"
    fi
    echo "export FIP_TAGS=\"$TAGS\""
    echo "export FIP_CDK_DIR=$CDK_DIR"
} > "$TMP"
mv "$TMP" "$CONFIG_FILE"

echo "Saved to $CONFIG_FILE:"
grep '^export' "$CONFIG_FILE" | sed 's/^export /  /'
echo

# ── 5. fip on your PATH ──────────────────────────────────────────────────
# So that during an incident nobody has to remember where this was checked
# out. A link, not a copy: it finds its subcommands through it. Your shell
# profile is not edited; if ~/.local/bin is not on your PATH, this says how.
realpath_of() { python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$1"; }
SELF="$(realpath_of "$BIN_DIR/fip")"
ON_PATH="$(command -v fip 2>/dev/null || true)"
if [ -n "$ON_PATH" ] && [ "$(realpath_of "$ON_PATH")" = "$SELF" ]; then
    echo "  ok    fip is on your PATH ($ON_PATH)"
else
    if [ -z "$LINK" ]; then
        if [ "$ASSUME_YES" = "true" ]; then LINK="No"
        else
            [ -z "$ON_PATH" ] || echo "  'fip' on your PATH is $ON_PATH, which is not this checkout."
            ask_yes_no LINK "Put fip on your PATH, as a link in ~/.local/bin" Yes
        fi
    fi
    if [ "$LINK" = "Yes" ]; then
        LINK_PATH="$HOME/.local/bin/fip"
        mkdir -p "$HOME/.local/bin"
        if [ -e "$LINK_PATH" ] && [ ! -L "$LINK_PATH" ]; then
            echo "  WARN  $LINK_PATH exists and is not a link; left alone" >&2
        else
            ln -sfn "$SELF" "$LINK_PATH"
            echo "  ok    $LINK_PATH -> $SELF"
            case ":$PATH:" in
                *":$HOME/.local/bin:"*) ;;
                *) echo "        ~/.local/bin is not on your PATH. Add it, then open a new terminal:"
                   echo "          echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.zprofile" ;;
            esac
        fi
    else
        echo "  Not linked. Run it as $BIN_DIR/fip, or rerun with --link."
    fi
fi
echo

if [ "$FAILED" -ne 0 ]; then
    echo "Configuration saved, but a profile check FAILED (above). Fix it and rerun" >&2
    echo "'fip configure' before 'fip deploy'." >&2
    exit 1
fi
echo "All profiles check out. Next: fip deploy"
