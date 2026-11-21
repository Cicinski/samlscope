#!/usr/bin/env bash
# Build a single-file desktop executable for the current OS (Linux here, Windows via CI).
set -euo pipefail
cd "$(dirname "$0")"
python -m PyInstaller --noconfirm --clean --distpath ../dist --workpath ../build samlscope.spec
