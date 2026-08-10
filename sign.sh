#!/bin/bash

# Sign the release binaries with Cosign using keyless (Fulcio/OIDC) signing.
#
# Reference: orch-ci .github/actions/security/cosign (sigstore/cosign).
# In CI this relies on the ambient GitHub Actions OIDC token, so the calling
# workflow must grant `id-token: write` and have cosign installed
# (sigstore/cosign-installer). For each artifact this emits a Sigstore bundle
# (.sigstore.json) for offline `cosign verify-blob` verification.
#
# After signing, each artifact is verified with `cosign verify-blob` (as the
# orch-ci action does) so a bad signature fails the release instead of
# shipping. The verified identity is this repo's release workflow via the
# GitHub Actions OIDC issuer. Set COSIGN_SKIP_VERIFY=1 to skip verification
# (e.g. local key-based testing, where there is no Fulcio identity to match).

set -euo pipefail

# Keyless verification identity. GITHUB_REPOSITORY is set by GitHub Actions;
# fall back to the canonical repo for local runs.
repo="${GITHUB_REPOSITORY:-device-management-toolkit/rpc-go}"
cert_identity_regexp="^https://github.com/${repo}/.github/workflows/release\\.yml@refs/(heads|tags)/.*$"
oidc_issuer="https://token.actions.githubusercontent.com"

# The release artifacts produced by build.sh (see .releaserc.json assets).
artifacts=(
    rpc_linux_x64.tar.gz
    rpc_linux_x86.tar.gz
    rpc_windows_x64.exe
    rpc_windows_x86.exe
    rpc_so_x64.tar.gz
)

for artifact in "${artifacts[@]}"; do
    if [ ! -f "$artifact" ]; then
        echo "❌ Artifact not found, cannot sign: $artifact"
        exit 1
    fi

    echo "──────────────────────────────"
    echo "🔏 Signing binary: $artifact"
    echo "──────────────────────────────"

    cosign sign-blob \
        --yes \
        --bundle "${artifact}.sigstore.json" \
        "$artifact"

    echo "✅ Signed $artifact"

    if [ "${COSIGN_SKIP_VERIFY:-0}" = "1" ]; then
        echo "⏭️  Skipping verification (COSIGN_SKIP_VERIFY=1) for $artifact"
        continue
    fi

    echo "🧾 Verifying $artifact"
    cosign verify-blob \
        --bundle "${artifact}.sigstore.json" \
        --certificate-identity-regexp "$cert_identity_regexp" \
        --certificate-oidc-issuer "$oidc_issuer" \
        "$artifact"
    echo "🟢 Verified $artifact"
done

echo "Cosign artifacts:"
ls -lh ./*.sigstore.json || true
