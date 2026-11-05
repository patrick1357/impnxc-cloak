#!/usr/bin/env bash
# Restores the original impacket files from ./backups and unholds the package.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="$(command -v python3)"

if [[ $EUID -ne 0 ]]; then
    exec sudo -E "$PY" "$HERE/opsec_patcher.py" uninstall "$@"
fi

"$PY" "$HERE/opsec_patcher.py" uninstall "$@"

if command -v apt-mark >/dev/null 2>&1; then
    for pkg in python3-impacket netexec; do
        dpkg -s "$pkg" >/dev/null 2>&1 && apt-mark unhold "$pkg" >/dev/null 2>&1 && \
            echo "[+] apt-mark unhold $pkg" || true
    done
fi

if [[ -f /usr/local/bin/nxc_obf ]]; then
    rm -f /usr/local/bin/nxc_obf && echo "[+] removed /usr/local/bin/nxc_obf"
fi
