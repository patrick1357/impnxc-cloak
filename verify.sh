#!/usr/bin/env bash
# Read-only check that every patch is still present in the live impacket.
# Run this before each engagement day -- an apt upgrade or a reinstall can
# silently revert the patches, and "I think it's patched" is the dangerous state.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$HERE/opsec_patcher.py" verify --profile "$HERE/profile.conf" "$@"
