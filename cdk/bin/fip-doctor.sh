#!/usr/bin/env bash
#
# fip-doctor.sh — check this install can actually do its job.
#   (normally invoked as: fip doctor)
#
# Run it after installing, and again before you need it. Everything here is
# READ-ONLY: it describes, it never creates, tags, contains or deletes.
#
# The point is to move discovery of a broken install from incident time to any
# other time. Every check corresponds to something that has actually failed:
# a missing jq, an unset account id, an external ID never issued for an
# account, an evidence role that cannot be assumed because the orchestrator id
# was wrong.
#
# A member account is only checked if you name it, because FIP cannot know
# which accounts you intend to cover.
#
#   fip doctor
#   fip doctor --member 111122223333 --member 444455556666

set -euo pipefail

REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"
MEMBERS=()

usage() {
    cat >&2 <<'EOF'
Usage: fip doctor [options]

Options:
  --member ACCOUNT   Check this member account end to end. Repeatable.
                     Default: the member accounts saved by fip configure.
  --region R         Default: $AWS_REGION, else us-east-1.
  -h, --help         This message.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --member) MEMBERS+=("${2:?--member needs a value}"); shift 2 ;;
        --region) REGION="${2:?--region needs a value}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "ERROR: unknown argument '$1'" >&2; usage; exit 2 ;;
    esac
done

# With no --member, check the member accounts `fip configure` saved.
CONFIG_FILE="${FIP_CONFIG:-$HOME/.fip/install.env}"
if [ "${#MEMBERS[@]}" -eq 0 ] && [ -f "$CONFIG_FILE" ]; then
    for m in $(sed -n 's/^export FIP_MEMBERS="\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' "$CONFIG_FILE" | tail -1); do
        MEMBERS+=("${m%%=*}")
    done
fi

PASS=0; WARN=0; FAIL=0

ok()   { printf '  OK    %s\n' "$1"; PASS=$((PASS+1)); }
warn() { printf '  WARN  %s\n' "$1"; WARN=$((WARN+1)); }
bad()  { printf '  FAIL  %s\n' "$1" >&2; FAIL=$((FAIL+1)); }

echo "Region: $REGION"
echo
echo "Tools"
for tool in aws jq python3 openssl; do
    if command -v "$tool" >/dev/null 2>&1; then
        ok "$tool"
    else
        bad "$tool is not installed (needed by the fip commands)"
    fi
done
if command -v node >/dev/null 2>&1; then
    ok "node $(node --version)"
else
    warn "node is not installed — needed to deploy, not to respond"
fi

echo
echo "Credentials"
if CALLER="$(aws sts get-caller-identity --output json 2>/dev/null)"; then
    ok "authenticated as $(jq -r .Arn <<<"$CALLER")"
    THIS_ACCOUNT="$(jq -r .Account <<<"$CALLER")"
else
    bad "no usable AWS credentials"
    echo
    echo "Cannot continue without credentials. $PASS ok, $WARN warnings, $FAIL failures." >&2
    exit 1
fi

echo
echo "Orchestrator"
LAMBDA_CFG="$(aws lambda get-function-configuration --function-name fip-member-action \
    --region "$REGION" --output json 2>/dev/null || echo '')"
if [ -z "$LAMBDA_CFG" ]; then
    bad "fip-member-action not found in $THIS_ACCOUNT ($REGION)"
    bad "  these may not be orchestrator credentials, or FipOrchestratorStack is not deployed"
    EVIDENCE_ACCOUNT=""
else
    ok "fip-member-action present ($(jq -r '.Runtime' <<<"$LAMBDA_CFG"))"
    EVIDENCE_ACCOUNT="$(jq -r '.Environment.Variables.FIP_EVIDENCE_ACCOUNT_ID // empty' <<<"$LAMBDA_CFG")"
    [ -n "$EVIDENCE_ACCOUNT" ] \
        && ok "evidence account configured: $EVIDENCE_ACCOUNT" \
        || bad "the Lambda has no FIP_EVIDENCE_ACCOUNT_ID"
    ANALYSIS="$(jq -r '.Environment.Variables.FIP_ANALYSIS_ACCOUNT_ID // empty' <<<"$LAMBDA_CFG")"
    [ -n "$ANALYSIS" ] \
        && ok "analysis account configured: $ANALYSIS" \
        || warn "no analysis account configured — optional; 'fip release --to' can name one"
fi

for machine in FipCase FipAcquisition; do
    if aws stepfunctions describe-state-machine \
            --state-machine-arn "arn:aws:states:${REGION}:${THIS_ACCOUNT}:stateMachine:${machine}" \
            --region "$REGION" >/dev/null 2>&1; then
        ok "$machine state machine present"
    else
        bad "$machine state machine not found"
    fi
done

if aws kms describe-key --key-id alias/fip-manifest-signing --region "$REGION" \
        --query 'KeyMetadata.KeyId' --output text >/dev/null 2>&1; then
    SPEC="$(aws kms describe-key --key-id alias/fip-manifest-signing --region "$REGION" \
        --query 'KeyMetadata.[KeySpec,KeyUsage,KeyState]' --output text)"
    ok "manifest signing key present ($SPEC)"
else
    bad "alias/fip-manifest-signing not found — manifests cannot be signed"
fi

echo
echo "Evidence account"
if [ -n "$EVIDENCE_ACCOUNT" ]; then
    if CREDS="$(aws sts assume-role \
            --role-arn "arn:aws:iam::${EVIDENCE_ACCOUNT}:role/FipEvidenceRole" \
            --role-session-name fip-doctor \
            --query 'Credentials' --output json --region "$REGION" 2>/dev/null)"; then
        ok "FipEvidenceRole is assumable"
        E_ENV=(
            "AWS_ACCESS_KEY_ID=$(jq -r .AccessKeyId <<<"$CREDS")"
            "AWS_SECRET_ACCESS_KEY=$(jq -r .SecretAccessKey <<<"$CREDS")"
            "AWS_SESSION_TOKEN=$(jq -r .SessionToken <<<"$CREDS")"
        )

        BUCKET="fip-evidence-${EVIDENCE_ACCOUNT}-${REGION}"
        # THE EVIDENCE BUCKET CANNOT BE PROBED READ-ONLY. Worth explaining,
        # because two plausible checks were tried against a live deployment on
        # 2026-10-21 and both were wrong:
        #
        #   s3api head-bucket  needs s3:ListBucket, which FipEvidenceRole
        #                      deliberately does not hold — it may add evidence
        #                      and never enumerate or remove it.
        #   get-object on a    ALSO needs s3:ListBucket. Without it S3 returns
        #   missing key        403 rather than 404 for an object that is not
        #                      there, on purpose, so it does not leak whether
        #                      the key exists. AWS said so verbatim:
        #                      "not authorized to perform: s3:ListBucket".
        #
        # So a correctly least-privileged write-only role is unprobeable by
        # design, and the only live proof is a case actually completing. Making
        # either check pass would have meant WIDENING the role, which is the
        # opposite of the control.
        #
        # What is checked instead is the GRANT, read with the caller's own
        # credentials. Static rather than live, and labeled as such.
        EV_POLICY="$(aws iam list-role-policies --role-name FipEvidenceRole \
            --query 'PolicyNames[0]' --output text 2>/dev/null || echo '')"
        if [ -z "$EV_POLICY" ] || [ "$EV_POLICY" = "None" ]; then
            warn "evidence bucket write grant not checked — needs credentials in the evidence account"
        else
            EV_DOC="$(aws iam get-role-policy --role-name FipEvidenceRole \
                --policy-name "$EV_POLICY" --query 'PolicyDocument' --output json 2>/dev/null || echo '{}')"
            if jq -e --arg b "arn:aws:s3:::${BUCKET}/cases/*" '
                    [.Statement[] | select((.Action|tostring) | contains("s3:PutObject"))
                                  | select((.Resource|tostring) | contains($b))] | length > 0
                ' <<<"$EV_DOC" >/dev/null 2>&1; then
                ok "FipEvidenceRole may write manifests to $BUCKET (policy check, not a live call)"
            else
                bad "FipEvidenceRole has no s3:PutObject on ${BUCKET}/cases/* — manifests will fail to write"
            fi
            if jq -e '[.Statement[] | select(.Effect=="Allow")
                      | select((.Action|tostring) | test("s3:Delete|BypassGovernance|PutObjectRetention"))] | length > 0
                ' <<<"$EV_DOC" >/dev/null 2>&1; then
                bad "FipEvidenceRole can DELETE or UNLOCK evidence — it must never be able to"
            else
                ok "FipEvidenceRole cannot delete evidence or alter retention"
            fi
        fi

        # Object Lock config is deliberately NOT readable by FipEvidenceRole —
        # that role must never inspect or alter retention. So this check needs
        # the caller's own credentials in the evidence account, and is SKIPPED
        # rather than failed when the caller does not have them.
        LOCK="$(aws s3api get-object-lock-configuration --bucket "$BUCKET" \
            --region "$REGION" --output json 2>/dev/null || echo '')"
        if [ -z "$LOCK" ]; then
            warn "Object Lock not checked — needs credentials in the evidence account, not FipEvidenceRole"
        elif [ "$(jq -r '.ObjectLockConfiguration.ObjectLockEnabled // empty' <<<"$LOCK")" = "Enabled" ]; then
            ok "Object Lock is ENABLED on the evidence bucket"
            if jq -e '.ObjectLockConfiguration.Rule' <<<"$LOCK" >/dev/null 2>&1; then
                DAYS="$(jq -r '.ObjectLockConfiguration.Rule.DefaultRetention | "\(.Mode) \(.Days // .Years)"' <<<"$LOCK")"
                warn "a DEFAULT retention rule is set ($DAYS) — objects written here WILL be locked"
            else
                ok "no default retention rule — nothing is locked by the bucket"
            fi
        else
            bad "Object Lock is NOT enabled, and it cannot be added to an existing bucket"
        fi

        # GetItem, not DescribeTable: the role holds GetItem/PutItem/UpdateItem
        # and nothing else. GetItem on a key that does not exist succeeds with
        # no Item, which is exactly the signal wanted.
        if env "${E_ENV[@]}" aws dynamodb get-item --table-name fip-cases \
                --key '{"caseId":{"S":"__fip-doctor-probe__"}}' \
                --region "$REGION" >/dev/null 2>&1; then
            ok "fip-cases table reachable"
        else
            bad "fip-cases table not reachable"
        fi

        if env "${E_ENV[@]}" aws kms describe-key --key-id alias/fip-evidence \
                --region "$REGION" >/dev/null 2>&1; then
            ok "alias/fip-evidence forensic key reachable"
        else
            bad "alias/fip-evidence not found in the evidence account"
        fi
    else
        bad "cannot assume FipEvidenceRole in $EVIDENCE_ACCOUNT"
        bad "  check FipCoreStack was deployed with the right OrchestratorAccountId"
    fi
else
    warn "skipping evidence checks — no evidence account known"
fi

if [ "${#MEMBERS[@]}" -gt 0 ]; then
    echo
    echo "Member accounts"
    for member in "${MEMBERS[@]}"; do
        if ! printf '%s' "$member" | grep -Eq '^[0-9]{12}$'; then
            bad "$member is not a 12-digit account id"
            continue
        fi
        if EXT="$(aws ssm get-parameter --name "/fip/member/${member}/external-id" \
                --query 'Parameter.Value' --output text --region "$REGION" 2>/dev/null)"; then
            ok "$member: external ID issued"
            for role in FipInventoryRole FipResponderRole; do
                if aws sts assume-role \
                        --role-arn "arn:aws:iam::${member}:role/${role}" \
                        --role-session-name fip-doctor \
                        --external-id "$EXT" \
                        --query 'Credentials.AccessKeyId' --output text \
                        --region "$REGION" >/dev/null 2>&1; then
                    ok "$member: $role assumable"
                elif [ "$role" = "FipResponderRole" ]; then
                    warn "$member: $role not assumable — expected if deployed with DeployResponderRole=No (read-only coverage)"
                else
                    bad "$member: $role not assumable"
                fi
            done
        else
            bad "$member: no external ID at /fip/member/${member}/external-id"
            bad "  nothing can be acquired from this account until one is issued (fip deploy --only members)"
        fi
    done
else
    echo
    warn "no member accounts checked — pass --member <id> to test one end to end"
fi

echo
echo "$PASS ok, $WARN warnings, $FAIL failures."
if [ "$FAIL" -ne 0 ]; then
    echo "This install cannot be relied on. Fix the failures above." >&2
    exit 1
fi
[ "$WARN" -ne 0 ] && echo "Usable. Read the warnings before you need it."
exit 0
