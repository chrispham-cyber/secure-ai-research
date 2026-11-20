#!/usr/bin/env bash
# Generate a CycloneDX SBOM for the installed environment (dev convenience, non-reproducible).
# For the committed, reproducible, SHA-256-pinned RELEASE SBOM use: make sbom-release
#   (python -m secure_ai_research.supply_chain.sbom -> sbom/release-sbom.cdx.json + manifest).
# PUBLIC / synthetic data only.
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

OUT="${1:-sbom.json}"
.venv/bin/cyclonedx-py environment -o "$OUT"
echo "SBOM written to $OUT"
