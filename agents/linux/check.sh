#!/usr/bin/env bash
# Bash entry point; Python handles structured JSON and bounded subprocess calls.
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$script_dir/collect.py" "$@"
