#!/usr/bin/env bash
# impacket-opsec installer
# Applies the wire de-fingerprinting patches to the system-wide impacket and
# pins the package so `apt upgrade` cannot silently revert them.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PY="$(command -v python3)"

if [[ "${1:-}" == "--no-hold" ]]; then HOLD=0; shift; else HOLD=1; fi

if [[ $EUID -ne 0 ]]; then
    echo "[*] impacket lives in a root-owned system path; re-running under sudo..."
    exec sudo -E "$PY" "$HERE/opsec_patcher.py" install --profile "$HERE/profile.conf" "$@"
fi

"$PY" "$HERE/opsec_patcher.py" install --profile "$HERE/profile.conf" "$@"

if [[ $HOLD -eq 1 ]] && command -v apt-mark >/dev/null 2>&1; then
    for pkg in python3-impacket netexec; do
        if dpkg -s "$pkg" >/dev/null 2>&1; then
            apt-mark hold "$pkg" >/dev/null && \
                echo "[+] apt-mark hold $pkg  (upgrades will not overwrite the patches)"
        fi
    done
    dpkg -s python3-impacket >/dev/null 2>&1 || \
        echo "[!] python3-impacket not a dpkg package; pin impacket yourself if from pip/git."
fi

# Install the nxc_obf wrapper (stealth mode) into PATH.
if [[ -f "$HERE/nxc_obf" ]] && command -v nxc >/dev/null 2>&1; then
    install -m 0755 "$HERE/nxc_obf" /usr/local/bin/nxc_obf && \
        echo "[+] installed /usr/local/bin/nxc_obf  (run 'nxc_obf ...' for stealth mode)"
fi

echo "[+] Done. Run ./verify.sh before each engagement day."
