#!/usr/bin/env bash
#
# fip-signing-key.sh — export this installation's manifest signing public key.
#   (normally invoked as: fip signing-key [--out FILE])
#
# Run by the FIP operator, with orchestrator-account credentials. It writes the
# PUBLIC half of the KMS signing key to a PEM file and prints its fingerprint.
# The private half never leaves KMS and this command cannot reach it.
#
# Why it exists: `fip verify` proves a record is unchanged with nothing but the
# file, but proving WHO signed it needs the expected key. An examiner, counsel
# or a court-appointed expert usually has no access to your AWS accounts, so
# you hand them this file instead, and they run
#
#   fip verify manifest.json --public-key fip-signing-key.pem
#
# Hand it over by a channel that is not the one the manifest travels by, and
# read the fingerprint to them separately, so that a single intercepted channel
# cannot substitute both.

set -euo pipefail

OUT="fip-signing-key.pem"
REGION="${AWS_REGION:-us-east-1}"

usage() {
    cat >&2 <<'EOF'
Usage: fip signing-key [--out FILE] [--region R]

Writes the public key that signs this installation's manifests and custody
records to a PEM file, default fip-signing-key.pem, and prints its fingerprint.
Run it with orchestrator-account credentials, for example

  AWS_PROFILE=fip-orchestrator fip signing-key

Give the file to anyone who must check that a record came from you. They run

  fip verify manifest.json --public-key fip-signing-key.pem

The file is a public key: it is safe to share and cannot be used to sign.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --out)    OUT="${2:?--out needs a file}"; shift 2 ;;
        --region) REGION="${2:?--region needs a value}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "ERROR: unknown argument '$1'" >&2; usage; exit 2 ;;
    esac
done

for tool in aws openssl python3; do
    command -v "$tool" >/dev/null 2>&1 || { echo "ERROR: $tool not installed" >&2; exit 1; }
done

KEY_ARN="$(aws cloudformation describe-stacks --stack-name FipOrchestratorStack \
    --region "$REGION" \
    --query "Stacks[0].Outputs[?OutputKey=='ManifestSigningKeyArn'].OutputValue" \
    --output text 2>/dev/null || true)"
if [ -z "$KEY_ARN" ] || [ "$KEY_ARN" = "None" ]; then
    echo "ERROR: no FipOrchestratorStack with a ManifestSigningKeyArn output in $REGION" >&2
    echo "       for account $(aws sts get-caller-identity --query Account --output text 2>/dev/null || echo '?')." >&2
    echo "       Use orchestrator-account credentials: AWS_PROFILE=fip-orchestrator fip signing-key" >&2
    exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

aws kms get-public-key --key-id "$KEY_ARN" --region "$REGION" \
    --query PublicKey --output text | base64 -d > "$WORK/key.der"
openssl pkey -pubin -inform DER -in "$WORK/key.der" -out "$OUT"

FINGERPRINT="$(python3 -c "
import hashlib,sys
print('sha256:' + hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())
" "$WORK/key.der")"

cat <<EOF
Signing key ..... $KEY_ARN
Fingerprint ..... $FINGERPRINT
Written to ...... $OUT

Give $OUT to whoever must confirm a record came from this installation.
Send the fingerprint separately, by a different channel, so they can check
the file they received is this one. They then run:

  fip verify manifest.json --public-key $OUT
EOF
