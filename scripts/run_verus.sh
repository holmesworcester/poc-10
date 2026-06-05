#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERUS="${VERUS:-/home/holmes/verus-install/verus-x86-linux/verus}"

"$VERUS" --crate-type=lib "$ROOT/src/protocol/proof.rs"
