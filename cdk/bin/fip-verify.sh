#!/usr/bin/env bash
#
# fip-verify.sh — check a FIP manifest or custody record.
#   (normally invoked as: fip verify <file> [--key-id ARN | --public-key FILE])
#
# Two separate questions, answered separately:
#
#   INTEGRITY  Has this file changed since it was signed?
#              Always checked. Needs nothing but the file: no AWS credentials,
#              no network, no trust in whoever handed it over. Anyone can run
#              it, including opposing counsel.
#
#   ORIGIN     Was it signed by OUR signing key, not someone else's?
#              Checked only when you say which key it should be:
#                --key-id ARN       compare with the key in KMS. Needs
#                                   credentials that can read it (the
#                                   orchestrator account, kms:GetPublicKey).
#                --public-key FILE  compare with a public key you were handed,
#                                   from `fip signing-key`. No AWS access.
#
# Integrity alone does NOT establish origin. The public key travels inside the
# file, so a fabricated record signed with an attacker's own key passes every
# integrity check. Before 2026-11 the --key-id option compared only the
# envelope's keyId field, a label outside the signed bytes that a forger can
# simply set to the right ARN. It now compares the actual public key bytes.
#
# Integrity checks, in order:
#   1. the envelope carries the exact bytes that were signed
#   2. those bytes hash to the digest recorded alongside them
#   3. the ECDSA P-384 signature over those bytes verifies under the embedded
#      public key
#   4. the readable copy in the envelope matches the signed bytes
#
# Step 4 is the one people skip and it is the one that catches tampering with
# the human-readable half: an envelope whose `manifest` was edited while
# `signedPayloadBase64` was left alone still passes steps 1-3.

set -euo pipefail

FILE=""
EXPECT_KEY=""
EXPECT_PUBKEY_FILE=""
OURS="false"

usage() {
    cat >&2 <<'EOF'
Usage: fip verify <file> [--ours | --key-id ARN | --public-key FILE]

Answers two questions about a manifest or custody record:

  Integrity   Has the file changed since it was signed?
              Always checked. Needs only the file. Anyone can run it.

  Origin      Was it signed by your FIP signing key?
              Checked only with one of these:
  --ours              Compare with this installation's signing key, looked up
                      in FipOrchestratorStack. The same as --key-id with that
                      key's ARN; needs the same credentials.
  --key-id ARN       Compare with the signing key in KMS. For the FIP operator:
                      needs orchestrator-account credentials (kms:GetPublicKey).
  --public-key FILE   Compare with a public key handed over by the operator,
                      produced by `fip signing-key`. Needs no AWS access.

Without either, origin is reported as NOT CHECKED: a forger can sign a
fabricated record with their own key and it passes the integrity checks.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --key-id)     EXPECT_KEY="${2:?--key-id needs a value}"; shift 2 ;;
        --public-key) EXPECT_PUBKEY_FILE="${2:?--public-key needs a file}"; shift 2 ;;
        --ours)       OURS="true"; shift ;;
        -h|--help) usage; exit 0 ;;
        -*) echo "ERROR: unknown option '$1'" >&2; usage; exit 2 ;;
        *) FILE="$1"; shift ;;
    esac
done

[ -n "$FILE" ] || { echo "ERROR: name a file to verify" >&2; usage; exit 2; }
[ -f "$FILE" ] || { echo "ERROR: no such file: $FILE" >&2; exit 1; }
if [ "$OURS" = "true" ] && { [ -n "$EXPECT_KEY" ] || [ -n "$EXPECT_PUBKEY_FILE" ]; }; then
    echo "ERROR: give one of --ours, --key-id or --public-key" >&2; exit 2
fi
if [ -n "$EXPECT_KEY" ] && [ -n "$EXPECT_PUBKEY_FILE" ]; then
    echo "ERROR: give --key-id or --public-key, not both" >&2; exit 2
fi
if [ "$OURS" = "true" ]; then
    EXPECT_KEY="$(aws cloudformation describe-stacks --stack-name FipOrchestratorStack \
        --query "Stacks[0].Outputs[?OutputKey=='ManifestSigningKeyArn'].OutputValue" \
        --output text 2>/dev/null || true)"
    case "$EXPECT_KEY" in arn:*) ;; *)
        echo "ERROR: --ours could not read the signing key from FipOrchestratorStack." >&2
        echo "       Run it with orchestrator credentials (fip configure saves them)." >&2
        exit 1 ;;
    esac
fi
if [ -n "$EXPECT_PUBKEY_FILE" ] && [ ! -f "$EXPECT_PUBKEY_FILE" ]; then
    echo "ERROR: no such public key file: $EXPECT_PUBKEY_FILE" >&2; exit 1
fi

for tool in jq openssl python3; do
    command -v "$tool" >/dev/null 2>&1 || { echo "ERROR: $tool not installed" >&2; exit 1; }
done

if ! jq -e '.signature.signedPayloadBase64 and .signature.value and .signature.publicKeyDer' \
        "$FILE" >/dev/null 2>&1; then
    echo "ERROR: $FILE is not a signed FIP envelope." >&2
    echo "       Expected .signature with signedPayloadBase64, value and publicKeyDer." >&2
    echo "       A manifest written before 2026-10 may predate signedPayloadBase64; those" >&2
    echo "       cannot be verified from the stored object alone." >&2
    exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

jq -r .signature.signedPayloadBase64 "$FILE" | base64 -d > "$WORK/signed.json"
jq -r .signature.value                "$FILE" | base64 -d > "$WORK/signature.der"
jq -r .signature.publicKeyDer         "$FILE" | base64 -d > "$WORK/pubkey.der"

ALGO="$(jq -r '.signature.algorithm // "unknown"' "$FILE")"
KEY_ID="$(jq -r '.signature.keyId // "unknown"' "$FILE")"
EXPECT_SHA="$(jq -r '.signature.signedPayloadSha256 // empty' "$FILE")"

fingerprint() { python3 -c "
import hashlib,sys
print('sha256:' + hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())
" "$1"; }
EMBEDDED_FP="$(fingerprint "$WORK/pubkey.der")"

echo "File ............ $FILE"
echo "Algorithm ....... $ALGO"
echo "Key label ....... $KEY_ID  (a label only; not covered by the signature)"
echo "Embedded key .... $EMBEDDED_FP"
echo
echo "Integrity: has this file changed since it was signed?"

FAILED=0

# 2. digest of the signed bytes
ACTUAL_SHA="$(python3 -c "
import hashlib,sys
print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())
" "$WORK/signed.json")"

if [ -n "$EXPECT_SHA" ]; then
    if [ "$ACTUAL_SHA" = "$EXPECT_SHA" ]; then
        echo "  OK    signed bytes match signedPayloadSha256"
    else
        echo "  FAIL  signed bytes do NOT match signedPayloadSha256" >&2
        echo "          recorded $EXPECT_SHA" >&2
        echo "          actual   $ACTUAL_SHA" >&2
        FAILED=1
    fi
else
    echo "  --    no signedPayloadSha256 recorded; skipping that check"
fi

# 3. the signature itself
openssl pkey -pubin -inform DER -in "$WORK/pubkey.der" -out "$WORK/pubkey.pem" 2>/dev/null \
    || { echo "  FAIL  embedded public key is not readable DER" >&2; exit 1; }

if openssl dgst -sha384 -verify "$WORK/pubkey.pem" \
        -signature "$WORK/signature.der" "$WORK/signed.json" >/dev/null 2>&1; then
    echo "  OK    ECDSA signature verifies under the embedded public key"
else
    echo "  FAIL  SIGNATURE DOES NOT VERIFY" >&2
    FAILED=1
fi

# 4. the readable copy against the signed bytes
python3 - "$FILE" "$WORK/signed.json" <<'PY' || FAILED=1
import json, sys
envelope = json.load(open(sys.argv[1]))
signed = json.load(open(sys.argv[2]))
# Whichever document key this envelope carries.
keys = [k for k in envelope if k != 'signature']
if len(keys) != 1:
    print(f"  FAIL  expected one document key beside 'signature', found {keys}")
    sys.exit(1)
readable = envelope[keys[0]]
if readable == signed:
    print(f"  OK    readable '{keys[0]}' matches the signed bytes")
    sys.exit(0)
print(f"  FAIL  readable '{keys[0]}' DIFFERS from the signed bytes")
print("        The signature covers signedPayloadBase64, so steps 1-3 can pass")
print("        while the human-readable copy has been altered. Trust the signed")
print("        bytes and treat this file as tampered with.")
sys.exit(1)
PY

INTEGRITY_FAILED=$FAILED

# ── Origin ───────────────────────────────────────────────────────────────
# Compares KEYS, not labels. The expected key's DER bytes are fetched or read,
# fingerprinted, and compared with the key embedded in the envelope -- the key
# the signature was just verified under.
ORIGIN="NOT CHECKED"
echo
echo "Origin: was it signed by your FIP signing key?"
if [ -n "$EXPECT_KEY" ]; then
    if ! expected_b64="$(aws kms get-public-key --key-id "$EXPECT_KEY" \
            --query PublicKey --output text 2>"$WORK/kms.err")"; then
        echo "  FAIL  could not read $EXPECT_KEY from KMS:" >&2
        sed 's/^/          /' "$WORK/kms.err" >&2
        echo "        Use credentials for the orchestrator account, for example" >&2
        echo "        AWS_PROFILE=fip-orchestrator fip verify ..." >&2
        ORIGIN="FAILED"; FAILED=1
    else
        printf '%s' "$expected_b64" | base64 -d > "$WORK/expected.der"
        EXPECTED_SOURCE="KMS key $EXPECT_KEY"
    fi
elif [ -n "$EXPECT_PUBKEY_FILE" ]; then
    if openssl pkey -pubin -in "$EXPECT_PUBKEY_FILE" -outform DER -out "$WORK/expected.der" 2>/dev/null \
       || openssl pkey -pubin -inform DER -in "$EXPECT_PUBKEY_FILE" -outform DER -out "$WORK/expected.der" 2>/dev/null; then
        EXPECTED_SOURCE="public key file $EXPECT_PUBKEY_FILE"
    else
        echo "  FAIL  $EXPECT_PUBKEY_FILE is not a readable public key (PEM or DER)" >&2
        ORIGIN="FAILED"; FAILED=1
    fi
fi

if [ -f "$WORK/expected.der" ]; then
    EXPECTED_FP="$(fingerprint "$WORK/expected.der")"
    if [ "$EXPECTED_FP" = "$EMBEDDED_FP" ]; then
        echo "  OK    signed by the expected key: $EXPECTED_SOURCE"
        echo "          $EXPECTED_FP"
        ORIGIN="VERIFIED"
    else
        echo "  FAIL  NOT signed by the expected key ($EXPECTED_SOURCE)" >&2
        echo "          expected $EXPECTED_FP" >&2
        echo "          embedded $EMBEDDED_FP" >&2
        ORIGIN="FAILED"; FAILED=1
    fi
elif [ "$ORIGIN" = "NOT CHECKED" ]; then
    echo "  --    not checked: no expected key given"
fi

# ── Verdict ──────────────────────────────────────────────────────────────
echo
if [ "$INTEGRITY_FAILED" -ne 0 ]; then
    echo "Integrity ... FAILED   the file has been altered or is malformed" >&2
else
    echo "Integrity ... VERIFIED unchanged since it was signed"
fi
case "$ORIGIN" in
    VERIFIED) echo "Origin ...... VERIFIED signed by your FIP signing key" ;;
    FAILED)   echo "Origin ...... FAILED   not shown to be signed by your FIP signing key" >&2 ;;
    *)        echo "Origin ...... NOT CHECKED" ;;
esac

if [ "$FAILED" -ne 0 ]; then
    echo
    echo "VERIFICATION FAILED. Do not rely on this file." >&2
    exit 1
fi

if [ "$ORIGIN" = "NOT CHECKED" ]; then
    cat <<EOF

This shows the file was not altered after signing. It does not show WHO signed
it: the public key travels inside the file, so a fabricated record signed with
someone else's key passes too. To check origin, run one of:

  fip verify $FILE --ours
      if you operate this FIP installation

  fip verify $FILE --public-key fip-signing-key.pem
      with a key file the operator gave you from 'fip signing-key'
EOF
fi

echo
python3 -c "
import json,sys
d = json.load(open(sys.argv[1]))
doc = next(d[k] for k in d if k != 'signature')
print('Document:', doc.get('schema', '?'))
for field in ('caseId', 'event', 'at', 'createdAt', 'analysisAccountId'):
    if field in doc:
        print(f'  {field} = {doc[field]}')
src = doc.get('source') or {}
if src:
    print(f\"  source   = {src.get('instanceId','?')} in {src.get('accountId','?')}\")
ev = doc.get('evidence') or []
if ev:
    print(f'  evidence = {len(ev)} snapshot(s) of record')
    for e in ev:
        print(f\"    {e.get('snapshotId','?')}  sha256={str(e.get('sha256',''))[:16]}...\")
" "$FILE"
