#!/usr/bin/env bash
# Generate a CycloneDX SBOM for the installed environment.
# PUBLIC / synthetic data only.
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

OUT="${1:-sbom.json}"
.venv/bin/cyclonedx-py environment -o "$OUT"
echo "SBOM written to $OUT"
