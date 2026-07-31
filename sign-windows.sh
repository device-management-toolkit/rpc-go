#!/bin/bash

# Authenticode-sign the Windows release executables using Azure Trusted Signing.
#
# This embeds a Microsoft-recognised Authenticode signature *inside* each PE so
# Windows SmartScreen stops flagging the download as "not commonly downloaded".
# It is distinct from and complementary to Cosign (sign.sh): Cosign proves
# supply-chain provenance across all platforms via Sigstore; Authenticode is the
# signature Windows itself trusts.
#
# ORDER MATTERS: run this BEFORE sign.sh. Authenticode modifies the .exe bytes,
# so Cosign must sign the final (already Authenticode-signed) file — otherwise
# `cosign verify-blob` fails against the shipped binary.
#
# Signing is performed by the `sign` dotnet global tool with the Azure Trusted
# Signing dlib; the private key never leaves Azure. In CI the workflow installs
# the tool and authenticates to Azure (OIDC). Required environment:
#   AZURE_TS_ENDPOINT         e.g. https://wus.codesigning.azure.net/
#   AZURE_TS_ACCOUNT          Trusted Signing account name
#   AZURE_TS_CERT_PROFILE     certificate profile name
# Azure auth is taken from the ambient azure/login session (AZURE_* / OIDC).
#
# If AZURE_TS_ENDPOINT is unset (local dev, forks without the cert), this script
# logs and exits 0 so the release still succeeds with Cosign signing only.

set -euo pipefail

# Windows executables produced by build.sh.
windows_artifacts=(
    rpc_windows_x64.exe
    rpc_windows_x86.exe
)

if [ -z "${AZURE_TS_ENDPOINT:-}" ]; then
    echo "⏭️  AZURE_TS_ENDPOINT not set — skipping Authenticode signing."
    echo "    (Windows binaries ship unsigned by Authenticode; Cosign still applies.)"
    exit 0
fi

# Timestamping keeps signatures valid after the short-lived cert expires.
timestamp_url="${AZURE_TS_TIMESTAMP_URL:-http://timestamp.acs.microsoft.com}"
timestamp_digest="${AZURE_TS_TIMESTAMP_DIGEST:-SHA256}"

for artifact in "${windows_artifacts[@]}"; do
    if [ ! -f "$artifact" ]; then
        echo "❌ Windows artifact not found, cannot sign: $artifact"
        exit 1
    fi

    echo "──────────────────────────────"
    echo "🔏 Authenticode signing: $artifact"
    echo "──────────────────────────────"

    sign code trusted-signing \
        --trusted-signing-endpoint "$AZURE_TS_ENDPOINT" \
        --trusted-signing-account "$AZURE_TS_ACCOUNT" \
        --trusted-signing-certificate-profile "$AZURE_TS_CERT_PROFILE" \
        --timestamp-url "$timestamp_url" \
        --timestamp-digest "$timestamp_digest" \
        --file-digest SHA256 \
        --verbosity information \
        "$artifact"

    echo "✅ Authenticode signed $artifact"
done

echo "Authenticode signing complete."
