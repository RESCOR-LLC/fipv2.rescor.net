#!/usr/bin/env bash
#
# fip-deploy.sh — install or update FIP from the saved configuration.
#   (normally invoked as: fip deploy)
#
# Runs manual Appendix A.3 to A.5 in order, with the right profile for each account,
# and checks each step before starting the next:
#
#   1. pre-flight   every profile lands in its account; dependencies present
#   2. bootstrap    CDK, in the evidence and orchestrator accounts, once
#   3. core         FipCoreStack in the evidence account, then checks that
#                   Object Lock is enabled and carries no rule
#   4. orchestrator FipOrchestratorStack, then checks the signing key exists
#   5. members      per member account: reuse or issue its external ID, deploy
#                   FipMemberStack, then prove the trust path both ways
#
# Every input comes from ~/.fip/install.env, written by `fip configure`, never
# from whatever happens to be exported in this shell. That is the point: the
# organization id, for one, silently drops security conditions when a
# redeploy forgets it, and a file cannot forget.
#
# Safe to rerun. Each step is idempotent: bootstrap is skipped where it exists,
# an existing external ID is reused and never overwritten, and an unchanged
# stack is a no-op.

set -euo pipefail

CONFIG_FILE="${FIP_CONFIG:-$HOME/.fip/install.env}"
BIN_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CDK_DIR="$(cd -P "$BIN_DIR/.." && pwd)"
MEMBER_TEMPLATE="$CDK_DIR/synth/FipMemberStack.template.json"

ONLY=""
LIMIT_MEMBERS=()
ASSUME_YES="false"
DRY_RUN="false"

usage() {
    cat >&2 <<'EOF'
Usage: fip deploy [--only core|orchestrator|members] [--member ID] [--yes] [--dry-run]

Installs or updates FIP using the configuration saved by `fip configure`.
Runs every step in order and checks each one before the next. Safe to rerun.

  --only STEP    Run one step: core, orchestrator or members. Pre-flight
                 always runs.
  --member ID    Deploy only this member account. Repeatable. It must be in
                 the configuration.
  --yes          Do not stop for CDK's approval of IAM changes.
  --dry-run      Show what would run. Changes nothing.

To change accounts, profiles or options, rerun `fip configure` first.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --only)    ONLY="${2:?--only needs core, orchestrator or members}"; shift 2 ;;
        --member)  LIMIT_MEMBERS+=("${2:?--member needs an account id}"); shift 2 ;;
        --yes|-y)  ASSUME_YES="true"; shift ;;
        --dry-run) DRY_RUN="true"; shift ;;
        -h|--help) usage; exit 0 ;;
        # Compatibility with the old `fip deploy <stack>`.
        FipCoreStack)         ONLY=core; shift ;;
        FipOrchestratorStack) ONLY=orchestrator; shift ;;
        FipMemberStack)       ONLY=members; shift ;;
        *) echo "ERROR: unknown argument '$1'" >&2; usage; exit 2 ;;
    esac
done
case "$ONLY" in ""|core|orchestrator|members) ;; *)
    echo "ERROR: --only takes core, orchestrator or members, not '$ONLY'" >&2; exit 2 ;;
esac

if [ ! -f "$CONFIG_FILE" ]; then
    echo "ERROR: no configuration at $CONFIG_FILE. Run: fip configure" >&2
    exit 1
fi
# Start clean, so nothing exported in this shell leaks into a deploy.
unset FIP_ORG_ID FIP_ANALYSIS_ACCOUNT_ID FIP_MEMBERS FIP_PRODUCTION_MODE FIP_RETENTION_MODE \
    FIP_RETENTION_DAYS FIP_TAGS
# shellcheck disable=SC1090
. "$CONFIG_FILE"
: "${FIP_ORCHESTRATOR_ACCOUNT_ID:?missing from $CONFIG_FILE; rerun fip configure}"
: "${FIP_EVIDENCE_ACCOUNT_ID:?missing from $CONFIG_FILE; rerun fip configure}"
: "${FIP_MEMBERS:?no member accounts in $CONFIG_FILE; rerun fip configure}"
REGION="${AWS_REGION:-us-east-1}"
ORCH_PROFILE="${FIP_ORCHESTRATOR_PROFILE:-fip-orchestrator}"
EVID_PROFILE="${FIP_EVIDENCE_PROFILE:-fip-evidence}"
RESPONDER="${FIP_DEPLOY_RESPONDER:-Yes}"
ALLOW_RESTORE="${FIP_ALLOW_RESTORE:-Yes}"
export AWS_REGION="$REGION" FIP_ORCHESTRATOR_ACCOUNT_ID FIP_EVIDENCE_ACCOUNT_ID
export FIP_ANALYSIS_ACCOUNT_ID="${FIP_ANALYSIS_ACCOUNT_ID:-}"

# The organization is a choice that must be made, not a value that may be
# missing: an id, or "none" for an install with no organization. A blank one
# once let member roles deploy without their aws:PrincipalOrgID condition.
case "${FIP_ORG_ID:-}" in
    o-*|none) ;;
    *) echo "ERROR: no organization in $CONFIG_FILE (FIP_ORG_ID='${FIP_ORG_ID:-}')." >&2
       echo "       Rerun: fip configure --org-id o-...   or, with no AWS Organization: fip configure --no-org" >&2
       exit 1 ;;
esac
ORG_CONTEXT=()
[ "$FIP_ORG_ID" = "none" ] || ORG_CONTEXT=(--context "fip:orgId=$FIP_ORG_ID")
APPROVAL=()
[ "$ASSUME_YES" != "true" ] || APPROVAL=(--require-approval never)

# Members to deploy: all configured, or the subset named.
MEMBERS=()
for m in $FIP_MEMBERS; do
    if [ "${#LIMIT_MEMBERS[@]}" -eq 0 ]; then MEMBERS+=("$m"); continue; fi
    for want in "${LIMIT_MEMBERS[@]}"; do [ "${m%%=*}" = "$want" ] && MEMBERS+=("$m"); done
done
if [ "${#LIMIT_MEMBERS[@]}" -gt 0 ]; then
    for want in "${LIMIT_MEMBERS[@]}"; do
        case " $FIP_MEMBERS" in *" $want="*) ;; *)
            echo "ERROR: $want is not a configured member. Add it with: fip configure --member $want ..." >&2
            exit 2 ;;
        esac
    done
fi

step()  { echo; echo "── $* ──"; }
ok()    { echo "  ok    $*"; }
fail()  { echo "  FAIL  $*" >&2; exit 1; }
want()  { [ -z "$ONLY" ] || [ "$ONLY" = "$1" ]; }
run()   {  # print, then run unless dry-run
    # The external ID is visible in the role's trust policy, but a deploy log
    # gets pasted into tickets and chats, so it is not echoed here.
    echo "  \$ $*" | sed -E 's/(ExternalId=)[^ ]+/\1(hidden)/g'
    [ "$DRY_RUN" = "true" ] || "$@"
}
account_of() { aws sts get-caller-identity --profile "$1" --query Account --output text 2>/dev/null || true; }

# Test or production. From the configuration when `fip configure` set it, and
# passed to CDK as context, which overrides cdk.json. A configuration written
# before configure asked falls back to cdk.json, as the manual's by-hand path
# does.
MODE_CONTEXT=()
if [ -n "${FIP_PRODUCTION_MODE:-}" ]; then
    PRODUCTION="$FIP_PRODUCTION_MODE"
    RET_MODE="${FIP_RETENTION_MODE:-GOVERNANCE}"
    RET_DAYS="${FIP_RETENTION_DAYS:-}"
    MODE_CONTEXT=(--context "fip:productionMode=$PRODUCTION")
    if [ "$PRODUCTION" = "true" ]; then
        printf '%s' "$RET_DAYS" | grep -Eq '^[1-9][0-9]*$' \
            || { echo "ERROR: production mode with no retention days in $CONFIG_FILE. Run: fip configure" >&2; exit 1; }
        MODE_CONTEXT+=(--context "fip:retentionMode=$RET_MODE" --context "fip:retentionDays=$RET_DAYS")
    fi
else
    PRODUCTION="$(jq -r '.context["fip:productionMode"] // false' "$CDK_DIR/cdk.json")"
    RET_MODE="$(jq -r '.context["fip:retentionMode"] // "GOVERNANCE"' "$CDK_DIR/cdk.json")"
    RET_DAYS="$(jq -r '.context["fip:retentionDays"] // "none"' "$CDK_DIR/cdk.json")"
fi
ENVIRONMENT="test"; [ "$PRODUCTION" != "true" ] || ENVIRONMENT="production"

# Stack tags (manual §11). CloudFormation copies them to every resource it
# creates that takes tags. application, fip:class and fip:component are also
# in the templates themselves, so a by-hand deploy without these still
# carries them; fip:environment and your own tags come only from here.
stack_tags() {  # stack_tags COMPONENT -> KEY=VALUE per line
    printf '%s\n' application=fipv2 fip:class=infrastructure "fip:component=$1" \
        "fip:environment=$ENVIRONMENT"
    local t
    for t in ${FIP_TAGS:-}; do printf '%s\n' "$t"; done
}
cdk_tags() {  # cdk_tags COMPONENT -> sets CDK_TAGS
    CDK_TAGS=()
    local t
    while IFS= read -r t; do CDK_TAGS+=(--tags "$t"); done < <(stack_tags "$1")
}

echo "FIP deploy from $CONFIG_FILE"
echo "  Region ........... $REGION"
echo "  Orchestrator ..... $FIP_ORCHESTRATOR_ACCOUNT_ID ($ORCH_PROFILE)"
echo "  Evidence ......... $FIP_EVIDENCE_ACCOUNT_ID ($EVID_PROFILE)"
member_list=""
for m in "${MEMBERS[@]}"; do member_list="$member_list ${m%%=*} (${m#*=})"; done
echo "  Members ..........${member_list}"
echo "  Organization ..... $FIP_ORG_ID"
echo "  Analysis ......... ${FIP_ANALYSIS_ACCOUNT_ID:-none}"
echo "  Responder role ... $RESPONDER    Restore allowed ... $ALLOW_RESTORE"
if [ "$PRODUCTION" = "true" ]; then
    echo "  Retention ........ PRODUCTION: evidence is locked for $RET_DAYS days, $RET_MODE (manual §8)"
else
    echo "  Retention ........ test mode: nothing is locked (manual §8)"
fi
echo "  Tags ............. application=fipv2 fip:environment=$ENVIRONMENT${FIP_TAGS:+ $FIP_TAGS}"
[ "$DRY_RUN" != "true" ] || echo "  DRY RUN: commands are shown, not run."

# ── 1. Pre-flight ────────────────────────────────────────────────────────
step "1. Pre-flight"
for tool in aws jq npx openssl python3; do
    command -v "$tool" >/dev/null 2>&1 || fail "$tool is not installed"
done
check_profile() {
    local landed; landed="$(account_of "$1")"
    [ "$landed" = "$2" ] || fail "profile $1 lands in '${landed:-nothing}', not $2. Rerun fip configure."
    ok "$1 -> $2"
}
check_profile "$ORCH_PROFILE" "$FIP_ORCHESTRATOR_ACCOUNT_ID"
[ "$EVID_PROFILE" = "$ORCH_PROFILE" ] || check_profile "$EVID_PROFILE" "$FIP_EVIDENCE_ACCOUNT_ID"
if want members; then
    for m in "${MEMBERS[@]}"; do check_profile "${m#*=}" "${m%%=*}"; done
fi
cd "$CDK_DIR"
if [ ! -d node_modules ]; then
    run npm ci --silent
fi
ok "dependencies installed"

if [ "$PRODUCTION" = "true" ] && [ "$ASSUME_YES" != "true" ] && [ "$DRY_RUN" != "true" ]; then
    read -r -p "  PRODUCTION mode: new evidence will be undeletable for $RET_DAYS days ($RET_MODE). Continue? [y/N] " reply </dev/tty
    case "$reply" in y|Y|yes|YES) ;; *) echo "Stopped. Nothing deployed."; exit 1 ;; esac
fi

# ── 2. Bootstrap ─────────────────────────────────────────────────────────
bootstrap() {  # bootstrap ACCOUNT PROFILE
    local status
    status="$(aws cloudformation describe-stacks --stack-name CDKToolkit --profile "$2" \
        --query 'Stacks[0].StackStatus' --output text 2>/dev/null || true)"
    case "$status" in
        *_COMPLETE) ok "CDK already bootstrapped in $1 ($status)" ;;
        *) run npx cdk bootstrap "aws://$1/$REGION" --profile "$2" ;;
    esac
}
if want core || want orchestrator; then
    step "2. Bootstrap"
    want core && bootstrap "$FIP_EVIDENCE_ACCOUNT_ID" "$EVID_PROFILE"
    if want orchestrator && { [ "$FIP_ORCHESTRATOR_ACCOUNT_ID" != "$FIP_EVIDENCE_ACCOUNT_ID" ] || ! want core; }; then
        bootstrap "$FIP_ORCHESTRATOR_ACCOUNT_ID" "$ORCH_PROFILE"
    fi
fi

output_of() {  # output_of STACK KEY PROFILE
    aws cloudformation describe-stacks --stack-name "$1" --profile "$3" \
        --query "Stacks[0].Outputs[?OutputKey=='$2'].OutputValue" --output text 2>/dev/null || true
}

# ── 3. Core (evidence account) ───────────────────────────────────────────
if want core; then
    step "3. FipCoreStack in the evidence account"
    cdk_tags core
    run npx cdk deploy FipCoreStack --profile "$EVID_PROFILE" \
        ${ORG_CONTEXT[@]+"${ORG_CONTEXT[@]}"} ${MODE_CONTEXT[@]+"${MODE_CONTEXT[@]}"} \
        "${CDK_TAGS[@]}" ${APPROVAL[@]+"${APPROVAL[@]}"}
    if [ "$DRY_RUN" != "true" ]; then
        bucket="$(output_of FipCoreStack EvidenceBucketName "$EVID_PROFILE")"
        [ -n "$bucket" ] && [ "$bucket" != "None" ] || fail "FipCoreStack has no EvidenceBucketName output"
        ok "evidence bucket $bucket"
        lock="$(aws s3api get-object-lock-configuration --bucket "$bucket" --profile "$EVID_PROFILE" --output json)"
        [ "$(jq -r '.ObjectLockConfiguration.ObjectLockEnabled // empty' <<<"$lock")" = "Enabled" ] \
            || fail "Object Lock is not enabled on $bucket"
        if [ "$(jq -r '.ObjectLockConfiguration | has("Rule")' <<<"$lock")" = "true" ]; then
            fail "Object Lock on $bucket carries a default rule, so something is locking objects. Investigate (manual §8)."
        fi
        ok "Object Lock enabled, with no default rule"
    fi
fi

# ── 4. Orchestrator ──────────────────────────────────────────────────────
if want orchestrator; then
    step "4. FipOrchestratorStack in the orchestrator account"
    cdk_tags orchestrator
    run npx cdk deploy FipOrchestratorStack --profile "$ORCH_PROFILE" \
        ${ORG_CONTEXT[@]+"${ORG_CONTEXT[@]}"} ${MODE_CONTEXT[@]+"${MODE_CONTEXT[@]}"} \
        "${CDK_TAGS[@]}" ${APPROVAL[@]+"${APPROVAL[@]}"}
    if [ "$DRY_RUN" != "true" ]; then
        key="$(output_of FipOrchestratorStack ManifestSigningKeyArn "$ORCH_PROFILE")"
        [ -n "$key" ] && [ "$key" != "None" ] || fail "FipOrchestratorStack has no ManifestSigningKeyArn output"
        ok "signing key $key"
    fi
fi

# ── 5. Members ───────────────────────────────────────────────────────────
external_id_for() {  # prints the ID; issues one only if none exists
    local id="$1" param="/fip/member/$1/external-id" value err
    err="$(mktemp)"
    if value="$(aws ssm get-parameter --profile "$ORCH_PROFILE" --name "$param" \
            --query Parameter.Value --output text 2>"$err")"; then
        rm -f "$err"; echo "$value"; return
    fi
    # Issue a new one ONLY when the parameter does not exist. Any other
    # failure, such as expired credentials, must not lead to an overwrite.
    if ! grep -q ParameterNotFound "$err"; then
        cat "$err" >&2; rm -f "$err"; return 1
    fi
    rm -f "$err"
    value="fip-$(python3 -c "import secrets,string;a=string.ascii_letters+string.digits;print(''.join(secrets.choice(a) for _ in range(32)))")"
    aws ssm put-parameter --profile "$ORCH_PROFILE" --name "$param" --value "$value" \
        --type String --description "FIP external ID for member account $id" \
        --query Version --output text >/dev/null || return 1
    echo "$value"
}

if want members; then
    step "5. FipMemberStack in each member account"
    [ -f "$MEMBER_TEMPLATE" ] || fail "missing $MEMBER_TEMPLATE"
    MEMBER_TAGS=()
    while IFS= read -r t; do MEMBER_TAGS+=("$t"); done < <(stack_tags member)
    RESTORE_PARAM=()
    if jq -e '.Parameters.AllowRestore' "$MEMBER_TEMPLATE" >/dev/null 2>&1; then
        RESTORE_PARAM=("AllowRestore=$ALLOW_RESTORE")
    fi
    for m in "${MEMBERS[@]}"; do
        id="${m%%=*}"; profile="${m#*=}"
        echo "  Account $id ($profile)"
        if [ "$DRY_RUN" = "true" ]; then
            echo "  \$ (read or issue /fip/member/$id/external-id in the orchestrator account)"
            external_id="<external-id>"
        else
            external_id="$(external_id_for "$id")" || fail "could not read or issue the external ID for $id"
            ok "external ID ready"
        fi
        run aws cloudformation deploy --profile "$profile" \
            --template-file "$MEMBER_TEMPLATE" \
            --stack-name FipMemberStack \
            --capabilities CAPABILITY_NAMED_IAM \
            --no-fail-on-empty-changeset \
            --parameter-overrides \
                "OrchestratorAccountId=$FIP_ORCHESTRATOR_ACCOUNT_ID" \
                "EvidenceAccountId=$FIP_EVIDENCE_ACCOUNT_ID" \
                "ExternalId=$external_id" \
                "OrganizationId=$FIP_ORG_ID" \
                "DeployResponderRole=$RESPONDER" \
                ${RESTORE_PARAM[@]+"${RESTORE_PARAM[@]}"} \
            --tags "${MEMBER_TAGS[@]}"
        [ "$DRY_RUN" != "true" ] || continue

        # The trust path, both ways: the right external ID must be accepted,
        # and a wrong one and a missing one must both be refused.
        role="FipInventoryRole"; [ "$RESPONDER" != "Yes" ] || role="FipResponderRole"
        arn="arn:aws:iam::${id}:role/$role"
        assume() { aws sts assume-role --profile "$ORCH_PROFILE" --role-arn "$arn" \
            --role-session-name fip-deploy-check "$@" >/dev/null 2>&1; }
        assume --external-id "$external_id" || fail "$role refuses the right external ID. Rerun: fip deploy --only members --member $id"
        ok "$role accepts the right external ID"
        if assume --external-id fip-wrong-id-check; then fail "$role ACCEPTS a wrong external ID. Do not use this account."; fi
        ok "$role refuses a wrong external ID"
        if assume; then fail "$role ACCEPTS no external ID. Do not use this account."; fi
        ok "$role refuses a missing external ID"
        # The organization condition, read back from every FIP role's trust
        # policy: present and right with an organization, absent with none.
        for r in FipInventoryRole FipResponderRole; do
            trust="$(aws iam get-role --profile "$profile" --role-name "$r" \
                --query 'Role.AssumeRolePolicyDocument' --output json 2>/dev/null)" || continue
            got="$(jq -r '[.Statement[].Condition.StringEquals["aws:PrincipalOrgID"] // "none"] | unique | join(",")' <<<"$trust")"
            [ "$got" = "$FIP_ORG_ID" ] || fail "$r trust has aws:PrincipalOrgID '$got', expected '$FIP_ORG_ID'"
            if [ "$FIP_ORG_ID" = "none" ]; then ok "$r trust: no organization condition (none configured)"
            else ok "$r trust requires organization $FIP_ORG_ID"; fi
        done
    done
fi

echo
if [ "$DRY_RUN" = "true" ]; then
    echo "DRY RUN complete. Nothing was changed."
else
    echo "FIP is deployed and every check passed."
    echo "Next: fip doctor, then try a case on a test instance (manual §4)."
fi
