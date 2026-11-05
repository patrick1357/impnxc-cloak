# Patch Details

Full breakdown of every patch applied by impnxc-cloak, the reasoning behind
each, and honest documentation of what remains detectable.

---

## Wire Layer — Always On

These patches are active for **all** impacket tools and NetExec (both `nxc`
and `nxc_obf`). They are pure network de-fingerprinting — no behavioural
changes to tool logic.

### SMB2/3 ClientGuid (`smb3.py`)

**Stock:** 16 random ASCII letters (e.g. `aAbBcCdDeEfFgGhH`).
**Patched:** `os.urandom(16)` — a real binary GUID, as Windows sends.

An all-ASCII `ClientGuid` is an instant impacket tell on the wire.

### SMB2/3 Multi-Dialect Negotiate (`smb3.py`)

**Stock (default path, no `preferredDialect`):** offers only
`[2.0.2, 2.1, 3.0]` with **no** negotiate contexts and capabilities `0x40`.
This is a glaring impacket fingerprint — a real Windows 10/11 client offers
the full dialect range with PreAuth and Encryption contexts.

**Patched:** the default negotiate now sends:
- **Dialects:** `2.0.2, 2.1, 3.0, 3.0.2, 3.1.1`
- **Negotiate contexts:** PreAuth-Integrity (SHA-512, 32-byte random salt) +
  Encryption (AES-128-CCM)
- **Capabilities:** `0x47` (DFS | LEASING | LARGE_MTU | ENCRYPTION)
- `NegotiateContextOffset` correctly computed for the multi-dialect case

The **server** selects the dialect — pre-2016 targets automatically negotiate
down to ≤3.0 (ignoring the contexts). Backward-compatible by design.

**A/B tested against Server 2022** (DC, member server, Win11 client):
- 3.1.1 + contexts: works (the old `STATUS_INVALID_PARAMETER` was caused by a
  wrong `NegotiateContextOffset` calculation, not 3.1.1 itself)
- Random-byte salt: works
- Caps up to `0x57`: works
- `DIRECTORY_LEASING` (`0x20`): **crashes** — the server reports
  `SupportsDirectoryLeasing` and impacket hits an `UnboundLocalError`
  (`parentDir`) on every root-level file/dir create. **Never set `0x20`.**
- GCM cipher: **breaks** — the server picks GCM, impacket is CCM-only,
  connection resets. Stays at AES-128-CCM.

### SMB1 Native Strings (`smb.py`)

**Stock:** `NativeOS = 'Unix'`, `NativeLanMan = 'Samba'` (both occurrences).
**Patched:** `Windows 11 Enterprise 26100` / `Windows 11 Enterprise 10.0`.

Low priority — a real Win11 client doesn't speak SMB1 at all. The stronger
control is `nxc_obf` disabling SMB1 negotiation entirely (see behavioural
layer).

### Hostname / Workstation Leak (`smbconnection.py`)

**Stock:** `myName = socket.gethostname()` — leaks `kali` (or whatever the
attack machine's hostname is) into the NetBIOS session header and the NTLM
workstation field.

**Patched:** `myName = _opsec.workstation()` — returns a configured name, or
a random `DESKTOP-XXXXXXX` if none is set (cached per process).

**Note:** per-process caching means separate invocations generate different
names (= multiple "hosts" to a correlator). For a stable identity across an
engagement, bake one in at install time (`--workstation DESKTOP-...`) or set
`IMPACKET_OPSEC_WORKSTATION` on every run.

### Kerberoasting TGS-REQ etype (`krb5/kerberosv5.py`)

**Stock:** `getKerberosTGS` hardcodes `RC4, DES3, DES` as the etype
preference → every TGS request yields an RC4 ticket (Event 4769,
`TicketEncryptionType 0x17`, SigmaHQ rule `496a0e47-…`).

**Patched:** `AES256, AES128, RC4, <cipher>` — AES-capable accounts now
return AES tickets, matching normal Windows behaviour.

**Trade-off:** AES roast hashes are slower to crack than RC4.

### MSSQL / TDS Handshake (`tds.py`)

Four patches normalise the TDS wire fingerprint:

| Field | Stock | Patched |
|---|---|---|
| Login7 `workstation_id` | Random `DESKTOP-xxxx` (per-connection, inconsistent with SMB) | `_opsec.workstation()` (same name across protocols) |
| PreLogin `Version` | Hardcoded `08 00 01 55 00 00` | Configurable (default `16.0.1000`, a SQL-2022-era placeholder) |
| `packetSize` | `32763` (init) / `16383` (TLS path) | `4096` (SSMS default) |
| Login7 `ClientPID` | `random.randint(0, 1024)` | Realistic Windows PID: random multiple of 4 in range `[1000, 40000)` |

The server does not validate the `Version` token (it echoes its own), and
accepts any `packetSize` (dictating the effective size via `ENVCHANGE`). All
functionally safe.

**Verified against SQL Server 2022:** auth + `-q` query intact with all
changes applied.

---

## Example / CLI Script Patches — Always On

These patch the impacket example scripts (the tools installed as
`impacket-<name>` on Kali).

### AS-REP Roasting etype (`GetNPUsers.py`)

**Stock:** AS-REQ requests `RC4` only → Event 4768 with `etype 0x17` and
PreAuth `0` is a high-confidence AS-REP roasting indicator (MITRE DET0113).

**Patched:** `AES256, AES128, RC4` — AES first, RC4 as legacy fallback.

### RID Cycling (`lookupsid.py`)

**Stock:** `SIMULTANEOUS = 1000` — 1000 SIDs per LSAR call, a burst that
lights up 4661/4662 mass-lookup analytics.

**Patched:** batch size from `_opsec.rid_batch()` (default `250`) with
`_opsec.pace()` jitter between batches.

### LDAP Page Size (`GetADUsers.py`)

**Stock:** `SimplePagedResultsControl(size=100)` — unusual; AD's default
`MaxPageSize` is 1000.

**Patched:** `size=1000` — matches the AD default.

**Note:** the LDAP *filters* (`servicePrincipalName=*`, `…:=4194304`, etc.)
are inherent to the techniques and are **not** patched. Reducing their
footprint requires targeted queries, not a blanket fix.

### Exec Output Filenames (`wmiexec.py`, `smbexec.py`)

**Stock:**
- wmiexec: `OUTPUT_FILENAME = '__' + str(time.time())` (e.g.
  `__1694000000.123`)
- smbexec: `OUTPUT_FILENAME = '__output_' + <8 random letters>`

Both patterns are matched by public Sigma/Defender rules for `ADMIN$`/`C$`
temp files.

**Patched:** `_opsec.exec_output_name()` — random alphanumeric name with a
configurable extension (default `.tmp`), no `__` prefix.

### smbexec Service Name (`smbexec.py`)

**Stock:** 8 random ASCII letters (all-letter names are themselves a mild
Event 7045 tell).

**Patched:** `_opsec.exec_service_name()` — random mixed alphanumeric; or set
`IMPACKET_OPSEC_EXEC_SERVICE_NAME=SophosUpdate` (or similar) for an
environment-plausible fixed name.

---

## NetExec Patches — Gated (`nxc_obf` / `IMPACKET_OPSEC=1`)

These are **off** when running plain `nxc` and **on** when running `nxc_obf`.
They reuse the same `impacket/_opsec` module.

### SMB1-First Negotiation Off (`protocols/smb.py`)

**Stock:** nxc always tries SMB1 first, then falls back to SMB2 on failure.
A real Windows 10/11 client never negotiates SMB1.

**Patched (obf):** the SMB1 negotiation attempt is skipped. Equivalent to
`--no-smbv1` being always on.

### RID-Brute Throttling (`protocols/smb.py`)

**Stock:** `simultaneous = 1000` + no delay — same burst as `lookupsid.py`.

**Patched (obf):** `_opsec.rid_batch()` (250) + `_opsec.pace()` jitter
between LSAR calls.

### AS-REP Roasting etype (`protocols/ldap/kerberos.py`)

**Stock:** nxc builds its **own** AS-REQ with `RC4` only (separate from the
`GetNPUsers.py` path).

**Patched (obf):** `AES256, AES128, RC4` (via `_opsec.asrep_ciphers()`).

### Random String Generation (`helpers/misc.py`)

**Stock:** `gen_random_string` uses `random.sample(ascii_letters, n)` —
no-repeat letters only, no digits. The lack of repeats and digits is a
statistical tell.

**Patched (obf):** `random.choices(ascii_letters + digits, k=n)` —
with-replacement, includes digits.

### WMI Exec Shell Wrapper (`protocols/smb/wmiexec.py`)

**Stock:** hardcoded `cmd.exe /Q /c `. Under `wmiprvse.exe`, this shape is
the `WIN-EXE-PRC-IMPACKET-WMIEXEC` signature (Sophos, empirically confirmed).

**Patched (obf):** routed through `_opsec.exec_shell_prefix()` — configurable
per run. Default is unchanged (`cmd.exe /Q /c `); softening is opt-in:
- `IMPACKET_OPSEC_EXEC_SHELL_PREFIX='cmd.exe /c '` — drop `/Q`
- `IMPACKET_OPSEC_EXEC_SHELL_PREFIX='cmd.exe /c ping -n 4 127.0.0.1 >nul & '`

**Limitation:** this only changes the command **line**. The
`wmiprvse.exe → cmd.exe` process lineage (what behavioural EDR rules actually
key on) is **not** changed — it can't be, from a wire/CLI patch.

### Exec No-CMD Mode (`protocols/smb/wmiexec.py`)

`IMPACKET_OPSEC_EXEC_NO_CMD=1` (obf):
- Drops the `cmd.exe` wrapper entirely → `Win32_Process.Create` launches the
  target binary directly (no `wmiprvse→cmd` child)
- Drops the output redirect and file read

**Cost:** no command output returned; only real `.exe` (no shell builtins,
pipes, `&&`, or environment variable expansion).

### Redirect Style (`protocols/smb/wmiexec.py`, `protocols/smb/mmcexec.py`)

**Stock:** `1> <file> 2>&1` — the explicit `1>` (combined with `/Q /c`) is
what the Sophos `WIN-EXE-PRC-IMPACKET-WMIEXEC` rule was observed to match.

**Patched (obf, `IMPACKET_OPSEC_EXEC_REDIRECT_STYLE=goexec`):** `> <file>
2>&1` — semantically identical (`>` and `1>` both redirect stdout), but the
different token evades the signature. A/B tested against Sophos: `1>` =
detection, `>` = silent.

Also applies to `mmcexec` (MMC20.Application DCOM exec). `atexec`/`smbexec`
already use `>`/`^>` natively and don't need this patch.

### WMI Protocol Shell Wrapper (`protocols/wmi/wmiexec.py`)

Same `exec_shell_prefix()` routing as the SMB wmiexec path. The WMI protocol
retrieves output via base64→registry instead of C$ file read, which helps if
the EDR rule targets the SMB read — but not if it targets the command line
(the cmd redirect remains).

### MSSQL Identity (`protocols/mssql.py`)

**Stock:** nxc's `enum_host_info()` builds its **own** pre-auth Login7 with
empty `HostName = ""` and `AppName = ""`, bypassing the patched `tds.py`
defaults. The first MSSQL packet on the wire carries no workstation or
application identity — itself a mild anomaly (real SSMS/SqlClient always sends
both).

**Patched (obf):** both fields filled from `self.conn.workstation_id` /
`self.conn.application_name` so the enum Login7 presents the **same** identity
as the auth Login7. `CltIntName` (the ODBC `APP` field) copies `AppName`
downstream, so it follows automatically.

Also gates the `ClientPID` to `_opsec.client_pid()` (realistic ×4 PID).
`packetSize` follows from the ungated `tds.py` patch automatically.

---

## Residual Tells — Not Hidden

These are documented limitations that either **cannot be fixed** without
rewriting core impacket internals, or where fixing them would **break
functionality** or **introduce a worse fingerprint**.

### SMB2 Cipher (AES-128-CCM only)

A real Windows 11 client offers AES-128-GCM (preferred) + AES-128-CCM.
Offering GCM makes the server select it, and impacket — which only implements
CCM — resets the connection. Single-CCM is a residual negotiate tell.

### Missing Negotiate Contexts

The patched negotiate sends PreAuth-Integrity + Encryption contexts but **not**
`NETNAME_NEGOTIATE_CONTEXT`, `SMB2_COMPRESSION_CAPABILITIES`, or
`SMB2_SIGNING_CAPABILITIES` that a Windows 11 client also sends. A deep
protocol inspector can still distinguish impacket's 3.1.1 from real Windows.

### No NTLM VERSION Block

Windows sends an NTLM `VERSION` structure in Type1/Type3 messages. Adding one
to impacket's SMB session setup causes `STATUS_INVALID_PARAMETER` — confirmed
by isolation testing against Server 2022. The root cause is a payload-offset
miscalculation in `NTLMAuthChallengeResponse.getData()` (it shifts offsets by
16 instead of 8 when `VERSION` is present). The absence of a `VERSION` block
is itself slightly un-Windows, but working authentication beats a perfect
fingerprint.

### Exec Process Lineage

Behavioural EDR detections that key on **process parent-child relationships**
survive all patches in this toolkit:
- `wmiprvse.exe → cmd.exe` (WMI exec)
- `sqlservr.exe → cmd.exe` (MSSQL `xp_cmdshell`)
- Service creation Event 7045 (smbexec/psexec)
- Scheduled task creation (atexec)

The redirect and shell-wrapper patches reduce the **command-line** signature
but do not alter the **process tree**. Real exec stealth requires different
techniques (WMI event consumers, `scmr/tsch change`, in-memory execution),
which are out of scope for a de-fingerprinting patcher.

### MSSQL TDS Encryption Preference

impacket sends `TDS_ENCRYPT_OFF` and encrypts only the login packet, then
drops to plaintext — a legacy shape. A modern SSMS/SqlClient defaults to full-
session TLS. This is not safely fixable: (1) impacket's TDS discards
`tlsSocket` after login, so `ENCRYPT_ON` risks breaking the connection; (2) it
would expose Python `ssl`'s TLS ClientHello (JA3/JA4), which range-EDR already
resets on LDAPS.

### Behavioural / Volume Patterns

A `/24` sweep, DCSync/DRSUAPI from a non-DC source, and LDAP filters like
`servicePrincipalName=*` are inherent to the techniques. Mitigate
operationally (jitter, targeting, smaller batches), not with a patch.

### WinRM

nxc-winrm runs on `pypsrp`/`spnego`, **not** impacket — only the workstation
name is addressed (via `NETBIOS_COMPUTER_NAME`). The HTTP/PSRP layer is
otherwise unmodified.

---

## Patch Index

Total: **43 patches** across 3 roots.

### impacket library (`/usr/lib/python3/dist-packages/impacket/`)

| Patch ID | File | Description |
|---|---|---|
| `smb3_import` | `smb3.py` | Add `_opsec` import |
| `smb3_clientguid` | `smb3.py` | Binary ClientGuid |
| `smb2_multidialect` | `smb3.py` | Windows-style multi-dialect negotiate |
| `smb_import` | `smb.py` | Add `_opsec` import |
| `smb_native` | `smb.py` | NativeOS/NativeLanMan strings |
| `smbconn_import` | `smbconnection.py` | Add `_opsec` import |
| `smbconn_hostname` | `smbconnection.py` | Workstation name |
| `kerberoast_etype` | `krb5/kerberosv5.py` | TGS-REQ AES-first etype |
| `mssql_import` | `tds.py` | Add `_opsec` import |
| `mssql_workstation` | `tds.py` | Login7 workstation consistency |
| `mssql_prelogin_version` | `tds.py` | PreLogin version token |
| `mssql_packet_size_init` | `tds.py` | Packet size (init path) |
| `mssql_packet_size_tls` | `tds.py` | Packet size (TLS path) |
| `mssql_client_pid` | `tds.py` | Realistic ClientPID (×2 sites) |

### impacket examples (`/usr/share/doc/python3-impacket/examples/`)

| Patch ID | File | Description |
|---|---|---|
| `asrep_etype` | `GetNPUsers.py` | AS-REQ AES-first etype |
| `lookupsid_import` | `lookupsid.py` | Add `_opsec` import |
| `lookupsid_rid_batch` | `lookupsid.py` | RID batch size |
| `lookupsid_pace` | `lookupsid.py` | Inter-batch jitter |
| `getadusers_pagesize` | `GetADUsers.py` | LDAP page size 1000 |
| `wmiexec_import` | `wmiexec.py` | Add `_opsec` import |
| `wmiexec_output` | `wmiexec.py` | Output temp filename |
| `smbexec_import` | `smbexec.py` | Add `_opsec` import |
| `smbexec_output` | `smbexec.py` | Output temp filename |
| `smbexec_service` | `smbexec.py` | Transient service name |

### NetExec (`/usr/lib/python3/dist-packages/nxc/`)

| Patch ID | File | Description |
|---|---|---|
| `nxc_smb_import` | `protocols/smb.py` | Add `_opsec` import |
| `nxc_smb1_off` | `protocols/smb.py` | Skip SMB1 negotiation |
| `nxc_rid_batch` | `protocols/smb.py` | RID batch size |
| `nxc_rid_pace` | `protocols/smb.py` | Inter-batch jitter |
| `nxc_kerberos_import` | `protocols/ldap/kerberos.py` | Add `_opsec` import |
| `nxc_asrep_etype` | `protocols/ldap/kerberos.py` | AS-REQ AES-first etype |
| `nxc_misc_import` | `helpers/misc.py` | Add `_opsec` import |
| `nxc_gen_random` | `helpers/misc.py` | Normalised random string generation |
| `nxc_wmiexec_import` | `protocols/smb/wmiexec.py` | Add `_opsec` import |
| `nxc_wmiexec_shell` | `protocols/smb/wmiexec.py` | Configurable shell wrapper |
| `nxc_wmiexec_nocmd` | `protocols/smb/wmiexec.py` | No-CMD raw execution |
| `nxc_wmiexec_redirect` | `protocols/smb/wmiexec.py` | Redirect style (`>` vs `1>`) |
| `nxc_wmi_import` | `protocols/wmi/wmiexec.py` | Add `_opsec` import |
| `nxc_wmi_shell` | `protocols/wmi/wmiexec.py` | Configurable shell wrapper |
| `nxc_mmcexec_import` | `protocols/smb/mmcexec.py` | Add `_opsec` import |
| `nxc_mmcexec_redirect` | `protocols/smb/mmcexec.py` | Redirect style |
| `nxc_mssql_import` | `protocols/mssql.py` | Add `_opsec` import |
| `nxc_mssql_identity` | `protocols/mssql.py` | Pre-auth Login7 identity fields |
| `nxc_mssql_clientpid` | `protocols/mssql.py` | Pre-auth Login7 ClientPID |
