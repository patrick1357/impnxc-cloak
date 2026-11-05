# impnxc-cloak

Wire- and behavioural de-fingerprinting patches for a **system-wide
[impacket](https://github.com/fortra/impacket)** installation **and
[NetExec (nxc)](https://github.com/Pennyw0rth/NetExec)**.

> **Alpha / Proof of Concept** — This project was developed for internal red
> team engagements and is released as-is. Not all impacket functionality has
> been regression-tested after patching. Other tools that depend on the patched
> impacket libraries (e.g. Certipy, Coercer, bloodyAD, …) **may break**. The
> primary goal was making **NetExec** OPSEC-safe for authorized assessments;
> broader compatibility is a non-goal at this stage.

---

## Disclaimer

**This software is provided for authorized penetration testing and security
research only.** It must be used exclusively within the scope of a written
engagement agreement or in a lab environment you own.

The authors assume **no liability** for misuse. Unauthorized access to computer
systems is illegal. By using this tool you agree that you are solely
responsible for compliance with all applicable laws and regulations.

---

## How It Works

impacket (and tools built on it) carries several protocol-level fingerprints
that network security monitoring, EDR, and IDS/IPS solutions can use to
identify it — even before authentication completes. Examples include a
recognisable SMB2 negotiate shape, ASCII-only `ClientGuid`, leaked hostname
(`kali`), RC4-only Kerberos requests, and hardcoded TDS handshake constants.

**impacket-opsec** patches these fingerprints **in place** so the traffic
resembles a legitimate Windows 11 client. It operates in two layers:

- **Wire layer** (always on) — pure network de-fingerprinting: binary
  `ClientGuid`, Windows-style SMB2 multi-dialect negotiate with
  PreAuth/Encryption contexts, configurable workstation name, AES-first
  Kerberos etypes, normalised MSSQL/TDS handshake.
- **Behavioural layer** (gated behind `IMPACKET_OPSEC=1` / the `nxc_obf`
  wrapper) — SMB1 negotiation disabled, RID-cycling throttled and jittered,
  exec artifacts renamed, output redirect reshaped to evade specific EDR
  signatures.

All patches are **anchor-based** (matched on code content, not line numbers),
**idempotent** (safe to re-run), and **fully reversible** (`./uninstall.sh`
restores originals byte-for-byte from automatic backups).

---

## Prerequisites

| Requirement | Tested version |
|---|---|
| **Kali Linux** (or Debian-based with system-wide impacket) | Kali 2024.x / 2025.x |
| **Python 3** | 3.11+ |
| **impacket** (system-wide, via `apt` or `pip`) | `0.14.0.dev0` (`python3-impacket`) |
| **NetExec** (optional, for `nxc_obf` behavioural patches) | `1.5.1` |
| **Root access** | Required (patches live in `/usr/lib/python3/…`) |

Other impacket or NetExec versions **may** work — the patcher matches on code
anchors, not version numbers. If an anchor no longer matches, that single patch
is reported as `DRIFT` and skipped; the file is never corrupted. Always check
the install output.

---

## Installation

```bash
git clone https://github.com/patrick1357/impnxc-cloak.git
cd impnxc-cloak
./install.sh          # auto-sudo: backup → patch → apt-mark hold
./verify.sh           # read-only: are all patches live?
```

`install.sh`:
1. Backs up every file it will touch (originals in `backups/`, sha256 in
   `manifest.json`; existing backups are never overwritten).
2. Applies all patches via `opsec_patcher.py`.
3. Runs `apt-mark hold` on `python3-impacket` and `netexec` so `apt upgrade`
   cannot silently revert the patches (pass `--no-hold` to skip).
4. Installs `/usr/local/bin/nxc_obf` (the stealth NetExec wrapper).

### Bake in profile values at install time

Override any value from `profile.conf` without editing the file:

```bash
./install.sh --workstation DESKTOP-4XE7ZQW                   # stable name across runs
./install.sh --set ntlm_build=22631 --set smb2_capabilities=0x47
./install.sh --workstation FIN-WKS042 --set tds_prelogin_version=16.0.4155
```

`--workstation ""` forces a random `DESKTOP-XXXXXXX` per process (the default).
Values are baked into the generated `_opsec.py`; per-run environment variables
(`IMPACKET_OPSEC_<KEY>`) still override them.

### Move to another machine

Copy the entire directory, run `./install.sh`. The patcher auto-detects the
impacket and NetExec paths.

### Uninstall

```bash
./uninstall.sh                       # byte-exact restore + apt-mark unhold
python3 opsec_patcher.py status      # check what's installed
```

---

## Usage

### NetExec — vanilla vs. stealth

| Command | Wire layer | Behavioural layer |
|---|---|---|
| `nxc smb …` | Active | **Off** (vanilla nxc) |
| `nxc_obf smb …` | Active | **On** (OPSEC mode) |

```bash
# Vanilla — wire fixes apply, behaviour unchanged
nxc smb 10.0.0.5 -u user -p pass --shares

# Stealth — full OPSEC (SMB1 off, AES etypes, RID pacing, quiet exec)
nxc_obf smb 10.0.0.5 -u user -p pass --shares
```

`nxc_obf` additionally pins one workstation name across all protocols
(SMB/LDAP/WMI/MSSQL/WinRM) for the duration of the run.

### impacket tools

Every impacket tool inherits the wire layer automatically:

```bash
impacket-secretsdump 'lab.local/user@10.0.0.5'
impacket-wmiexec 'lab.local/user@10.0.0.5'
impacket-GetUserSPNs 'lab.local/user:pass' -dc-ip 10.0.0.10 -request
```

### Per-run overrides

Any `profile.conf` value can be overridden per run via environment variables:

```bash
IMPACKET_OPSEC_WORKSTATION=FIN-WKS042 nxc_obf smb 10.0.0.5 -u u -p p --shares
IMPACKET_OPSEC_PACE_MS_MAX=0 nxc_obf smb 10.0.0.5 -u u -p p --rid-brute 5000
```

### Exec modes (nxc_obf)

**Default — goexec-style redirect (output on)**
```bash
nxc_obf smb 10.0.0.5 -u user -p pass -x whoami
```
Output is collected. Uses the redirect technique from
[goexec](https://github.com/FalconForceTeam/goexec) (FalconForce): `>` instead
of impacket's `1>`. Both are semantically identical (redirect stdout), but the
different token evades the Sophos `WIN-EXE-PRC-IMPACKET-WMIEXEC` signature
which matches on `1>`.

**Raw / no-cmd — maximum stealth (no output)**
```bash
IMPACKET_OPSEC_EXEC_NO_CMD=1 nxc_obf smb 10.0.0.5 -u user -p pass -x calc.exe
```
No `cmd.exe` child, no redirect, **no output returned**. Only real `.exe` — no
shell builtins, pipes, or chaining.

**Stock redirect — back to impacket's default**
```bash
IMPACKET_OPSEC_EXEC_REDIRECT_STYLE=stock nxc_obf smb 10.0.0.5 -u user -p pass -x whoami
```
Reverts to impacket's `1>` redirect (useful for A/B testing against EDR).

### nxc_obf Quick Reference

`nxc_obf` is a drop-in replacement for `nxc` with all OPSEC features enabled.
Everything below is **automatic** — no flags needed unless you want to
override.

| Feature | What nxc_obf does | Override |
|---|---|---|
| **Workstation name** | Pins one random `DESKTOP-XXXXXXX` across SMB/LDAP/WMI/MSSQL/WinRM for the entire run | `IMPACKET_OPSEC_WORKSTATION=FIN-WKS042` |
| **SMB1 negotiation** | Disabled (Win11 doesn't speak SMB1) | — |
| **AS-REP etype** | AES256, AES128, RC4 (not RC4-only) | — |
| **RID cycling** | Batch size 250 (not 1000) + jittered pause between batches | `IMPACKET_OPSEC_RID_BATCH=100` / `_PACE_MS_MAX=0` |
| **Random strings** | `random.choices(letters+digits)` (not no-repeat letters-only) | — |
| **Exec redirect** | `>` instead of `1>` (evades Sophos WMIEXEC rule) | `IMPACKET_OPSEC_EXEC_REDIRECT_STYLE=stock` |
| **Exec shell wrapper** | Configurable `cmd.exe` prefix | `IMPACKET_OPSEC_EXEC_SHELL_PREFIX='cmd.exe /c '` |
| **Raw exec (no cmd)** | Fire-and-forget, no `cmd.exe` child, no output | `IMPACKET_OPSEC_EXEC_NO_CMD=1` |
| **MSSQL identity** | Pre-auth Login7 carries workstation + app name (not empty) | — |
| **MSSQL ClientPID** | Realistic Windows PID (×4, thousands range) | — |

**Examples:**

```bash
# Standard stealth — all defaults
nxc_obf smb 10.0.0.5 -u user -p pass --shares

# RID brute with custom pacing
nxc_obf smb 10.0.0.5 -u user -p pass --rid-brute 5000

# Maximum-quiet exec (no cmd.exe, no output, only .exe)
IMPACKET_OPSEC_EXEC_NO_CMD=1 nxc_obf smb 10.0.0.5 -u user -p pass -x calc.exe

# Fixed workstation for the whole engagement
IMPACKET_OPSEC_WORKSTATION=YOURNAME nxc_obf smb 10.0.0.5 -u user -p pass --shares

# WinRM — workstation is consistent across protocols automatically
nxc_obf winrm 10.0.0.5 -u user -p pass -x whoami
```

---

## Validate on the Wire

Static verification (`./verify.sh`) is not enough — always capture and inspect
traffic before an engagement:

```bash
sudo tcpdump -i eth0 -w /tmp/smb.pcap host <lab-dc> and port 445 &
nxc_obf smb <lab-dc> -u user -p pass --shares
```

In Wireshark, the SMB2 NEGOTIATE request should show:
- **Dialects:** 2.0.2, 2.1, 3.0, 3.0.2, 3.1.1 (with PreAuth + Encryption
  contexts)
- **Salt:** random bytes (not ASCII letters)
- **Capabilities:** `0x47` (no `DIRECTORY_LEASING` / `0x20`)
- **Client GUID:** random bytes (not ASCII letters)
- **Workstation:** your chosen name or `DESKTOP-XXXXXXX`, not `kali`

---

## What's Patched

A high-level summary is below. For the full list of every patch, residual
tells, and known limitations, see **[PATCHES.md](PATCHES.md)**.

### Wire layer (always on)

- **SMB2 negotiate** matches a real Windows 10/11 client (full dialect list,
  PreAuth + Encryption contexts, random-byte salt, binary `ClientGuid`)
- **Workstation / hostname** never leaks `kali`
- **Kerberos TGS/AS-REQ** offer AES first (no more RC4-only 4768/4769 events)
- **MSSQL/TDS** handshake normalised (PreLogin version, packet size, client PID)

### Behavioural layer (nxc_obf only)

- **SMB1 negotiation** disabled (a real Win11 client doesn't speak SMB1)
- **RID cycling** throttled and jittered
- **Exec output** filenames drop the `__`/`__output` IOC prefix
- **Redirect** reshaped (`>` instead of `1>`) to evade observed EDR signatures
- **MSSQL** pre-auth Login7 identity fields filled (were empty in vanilla nxc)

### Honest limitations

- Single AES-128-CCM cipher (Windows offers GCM; impacket can't handle it)
- No NTLM `VERSION` block (adding it breaks SMB session setup)
- Exec process lineage (`wmiprvse→cmd`, `sqlservr→cmd`) is **not** hidden
- Missing negotiate contexts (`NETNAME`, `COMPRESSION`, `SIGNING`)

---

## Environment Variables

| Variable | Effect |
|---|---|
| `IMPACKET_OPSEC` | `1` enables gated NetExec behaviours (set by `nxc_obf`) |
| `IMPACKET_OPSEC_WORKSTATION` | Workstation / NetBIOS name (empty = random) |
| `IMPACKET_OPSEC_SMB2_CAPABILITIES` | SMB2 caps bitmask (default `0x47`; **never set `0x20`**) |
| `IMPACKET_OPSEC_RID_BATCH` | RID lookups per call (default `250`) |
| `IMPACKET_OPSEC_PACE_MS_MIN` / `_MAX` | Jitter between RID batches (`MAX=0` disables) |
| `IMPACKET_OPSEC_EXEC_NO_CMD` | `1` = raw process, no `cmd.exe`, no output |
| `IMPACKET_OPSEC_EXEC_REDIRECT_STYLE` | `goexec` or `stock` |
| `IMPACKET_OPSEC_EXEC_SHELL_PREFIX` | Override the `cmd.exe /Q /c ` wrapper |
| `IMPACKET_OPSEC_EXEC_OUTPUT_EXT` | Exec temp-file extension (default `.tmp`) |
| `IMPACKET_OPSEC_EXEC_SERVICE_NAME` | smbexec transient service name |
| `IMPACKET_OPSEC_TDS_PRELOGIN_VERSION` | MSSQL PreLogin version (default `16.0.1000`) |
| `IMPACKET_OPSEC_TDS_PACKET_SIZE` | MSSQL packet size (default `4096`) |
| `IMPACKET_OPSEC_TDS_CLIENT_PID_MIN` / `_MAX` | MSSQL Login7 PID range |
| `NETBIOS_COMPUTER_NAME` | WinRM workstation (pypsrp/spnego); pinned by `nxc_obf` |

---

## Files

```
opsec_patcher.py   Patch engine + definitions (anchor-based, idempotent, reversible)
profile.conf       Tunable profile values (Win11 identity, enum pacing, exec config)
install.sh         Backup → patch → apt-mark hold (auto-sudo)
verify.sh          Read-only patch verification
uninstall.sh       Restore originals + apt-mark unhold
nxc_obf            NetExec wrapper enabling the gated behavioural patches
```

---

## License

[Apache License 2.0](LICENSE)

---

## Acknowledgements

- [impacket](https://github.com/fortra/impacket) by Fortra (formerly SecureAuth)
- [NetExec](https://github.com/Pennyw0rth/NetExec) (nxc)
- [FalconOps / goexec](https://github.com/FalconForceTeam/FalconOps) — inspiration for the `>` redirect technique
