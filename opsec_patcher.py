#!/usr/bin/env python3
"""
impacket-opsec patcher
======================

De-fingerprints the *wire* behaviour of a system-wide impacket installation so
that impacket-based tooling (secretsdump, psexec, wmiexec, ntlmrelayx, the
Get*/find* AD enum scripts, ... and NetExec, which links the same impacket)
blends into normal Windows 10/11 SMB/NTLM traffic instead of shouting
"python/impacket" on the very first NEGOTIATE packet.

Design goals
------------
* Robust against version drift: every edit is matched on a *content anchor*
  (regex), never on a line number. If an anchor no longer matches, that single
  patch is skipped with a DRIFT warning instead of corrupting the file.
* Idempotent: re-running install is safe; already-applied patches are detected.
* Fully reversible: originals are backed up (with sha256) before the first
  edit, and `uninstall` restores them byte-for-byte.
* Centralised config: all tunable values live in impacket/_opsec.py (generated
  from profile.conf) and can be overridden at runtime via IMPACKET_OPSEC_*
  environment variables -- no reinstall needed to change the workstation name.

This only touches protocol *library* files. Host-side artefacts (service names,
temp files) are out of scope because the engagement runs over SOCKS where the
network fingerprint is what matters.

Usage:
    opsec_patcher.py install   [--profile profile.conf] [--impacket DIR]
                               [--workstation NAME] [--set KEY=VALUE ...]
    opsec_patcher.py verify    [--impacket DIR]
    opsec_patcher.py status    [--impacket DIR]
    opsec_patcher.py uninstall [--impacket DIR]

--workstation / --set bake profile.conf [opsec] values in at install time
without editing the file, e.g.:
    ./install.sh --workstation DESKTOP-4XE7ZQW --set ntlm_build=22631
"""
import argparse
import configparser
import hashlib
import json
import os
import re
import shutil
import sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
BACKUP_DIR = os.path.join(HERE, "backups")
MANIFEST = os.path.join(BACKUP_DIR, "manifest.json")

# ANSI colours (disabled if not a tty)
def _c(code):
    return code if sys.stdout.isatty() else ""
RED, GRN, YEL, CYN, DIM, RST = _c("\033[31m"), _c("\033[32m"), _c("\033[33m"), _c("\033[36m"), _c("\033[2m"), _c("\033[0m")

def ok(m):    print(f"{GRN}[+]{RST} {m}")
def info(m):  print(f"{CYN}[*]{RST} {m}")
def warn(m):  print(f"{YEL}[!]{RST} {m}")
def err(m):   print(f"{RED}[-]{RST} {m}")


# --------------------------------------------------------------------------- #
#  Locate impacket
# --------------------------------------------------------------------------- #
def find_impacket(explicit=None):
    if explicit:
        d = os.path.abspath(explicit)
        if os.path.isfile(os.path.join(d, "smb3.py")):
            return d
        err(f"--impacket {d} does not look like an impacket package (no smb3.py)")
        sys.exit(2)
    # Import it the way the tools do, but from a neutral cwd so we don't pick up
    # a ./impacket in the current directory.
    cwd = os.getcwd()
    try:
        os.chdir("/")
        import importlib
        mod = importlib.import_module("impacket")
        d = os.path.dirname(os.path.abspath(mod.__file__))
    except Exception as e:
        err(f"Could not import impacket: {e}")
        sys.exit(2)
    finally:
        os.chdir(cwd)
    return d

def impacket_version(impdir):
    try:
        from importlib.metadata import version
        return version("impacket")
    except Exception:
        # fall back to reading version.py-ish info
        return "unknown"

def find_examples(explicit=None, impdir=None):
    """Locate the impacket example scripts dir (the CLI tools live there)."""
    candidates = []
    if explicit:
        candidates.append(explicit)
    # derive the path from a Kali CLI wrapper (they exec .../examples/<name>.py)
    for wrapper in ("/usr/bin/impacket-GetNPUsers", "/usr/bin/impacket-secretsdump"):
        if os.path.isfile(wrapper):
            try:
                with open(wrapper) as f:
                    m = re.search(r"(/\S+/examples)\b", f.read())
                if m:
                    candidates.append(m.group(1))
            except Exception:
                pass
    candidates.append("/usr/share/doc/python3-impacket/examples")
    if impdir:
        candidates.append(os.path.join(impdir, "examples"))
    for d in candidates:
        if d and os.path.isfile(os.path.join(d, "GetNPUsers.py")):
            return os.path.abspath(d)
    # nothing validated -- return the best guess so patches report drift cleanly
    return os.path.abspath(candidates[0]) if candidates else None

def find_nxc(explicit=None):
    """Locate the installed nxc (NetExec) package dir."""
    if explicit:
        d = os.path.abspath(explicit)
        return d if os.path.isfile(os.path.join(d, "protocols", "smb.py")) else d
    cwd = os.getcwd()
    try:
        os.chdir("/")   # neutral cwd so we don't pick up ./nxc from a repo checkout
        import importlib
        mod = importlib.import_module("nxc")
        return os.path.dirname(os.path.abspath(mod.__file__))
    except Exception:
        return None
    finally:
        os.chdir(cwd)


# --------------------------------------------------------------------------- #
#  _opsec.py generation (the runtime config module dropped into impacket/)
# --------------------------------------------------------------------------- #
OPSEC_MODULE_MARKER = "# impacket-opsec runtime helpers"

def render_opsec_module(cfg):
    ws = cfg.get("workstation", "").strip()
    return f'''{OPSEC_MODULE_MARKER} (auto-generated, safe to delete)
"""Runtime de-fingerprinting values for impacket-opsec.

Every value can be overridden per-process via an environment variable
IMPACKET_OPSEC_<KEY>. Baked defaults come from profile.conf at install time.
"""
import os
import random
import string
import struct
import time

_DEFAULTS = {{
    "workstation": {ws!r},
    "native_os": {cfg.get("native_os", "Windows 11 Enterprise 26100")!r},
    "native_lanman": {cfg.get("native_lanman", "Windows 11 Enterprise 10.0")!r},
    "ntlm_major": {int(cfg.get("ntlm_major", 10))},
    "ntlm_minor": {int(cfg.get("ntlm_minor", 0))},
    "ntlm_build": {int(cfg.get("ntlm_build", 26100))},
    "smb2_capabilities": {int(str(cfg.get("smb2_capabilities", "0x47")), 0)},
    "rid_batch": {int(cfg.get("rid_batch", 250))},
    "pace_ms_min": {int(cfg.get("pace_ms_min", 150))},
    "pace_ms_max": {int(cfg.get("pace_ms_max", 600))},
    "exec_output_ext": {cfg.get("exec_output_ext", ".tmp")!r},
    "exec_service_name": {cfg.get("exec_service_name", "")!r},
    "exec_shell_prefix": {cfg.get("exec_shell_prefix", "cmd.exe /Q /c ")!r},
    "exec_redirect_style": {cfg.get("exec_redirect_style", "")!r},
    "tds_client_pid_min": {int(cfg.get("tds_client_pid_min", 1000))},
    "tds_client_pid_max": {int(cfg.get("tds_client_pid_max", 40000))},
    "tds_prelogin_version": {cfg.get("tds_prelogin_version", "16.0.1000")!r},
    "tds_packet_size": {int(cfg.get("tds_packet_size", 4096))},
}}


def _env(key, default):
    return os.environ.get("IMPACKET_OPSEC_" + key.upper(), default)


_ws_cache = None


def workstation():
    """Stable-per-process NetBIOS / NTLM workstation name."""
    global _ws_cache
    if _ws_cache is None:
        v = _env("workstation", _DEFAULTS["workstation"])
        if not v:
            v = "DESKTOP-" + "".join(random.choice(string.ascii_uppercase + string.digits) for _ in range(7))
        _ws_cache = v
    return _ws_cache


def client_guid():
    """Binary 16-byte SMB2 ClientGuid (impacket ships 16 ASCII letters)."""
    return os.urandom(16)


def salt(n):
    """Random binary salt/nonce (impacket ships ASCII letters)."""
    return os.urandom(int(n))


def ntlm_version():
    """A Windows VERSION structure for the NTLM messages."""
    from impacket.ntlm import VERSION
    v = VERSION()
    v["ProductMajorVersion"] = int(_env("ntlm_major", _DEFAULTS["ntlm_major"]))
    v["ProductMinorVersion"] = int(_env("ntlm_minor", _DEFAULTS["ntlm_minor"]))
    v["ProductBuild"] = int(_env("ntlm_build", _DEFAULTS["ntlm_build"]))
    return v


def native_os():
    return _env("native_os", _DEFAULTS["native_os"])


def native_lanman():
    return _env("native_lanman", _DEFAULTS["native_lanman"])


def smb2_capabilities():
    v = _env("smb2_capabilities", _DEFAULTS["smb2_capabilities"])
    return int(str(v), 0) if isinstance(v, str) else int(v)


def enabled():
    """Master switch for the gated NetExec behavioural patches.

    Off by default so plain `nxc` behaves vanilla; the `nxc_obf` wrapper sets
    IMPACKET_OPSEC=1 to turn the SMB1/etype/RID/random changes on. The impacket
    wire patches are NOT gated by this -- they are always active.
    """
    return str(os.environ.get("IMPACKET_OPSEC", "")).strip().lower() in ("1", "true", "yes", "on")


def asrep_ciphers():
    """AS-REQ etype preference for obf mode: AES256, AES128, RC4 (IANA numbers)."""
    return (18, 17, 23)


def rid_batch():
    """RID lookups per SAMR/LSAR call (impacket default 1000 = a loud burst)."""
    return max(1, int(_env("rid_batch", _DEFAULTS["rid_batch"])))


def pace():
    """Jittered pause to break up enumeration bursts. No-op if max <= 0."""
    lo = int(_env("pace_ms_min", _DEFAULTS["pace_ms_min"]))
    hi = int(_env("pace_ms_max", _DEFAULTS["pace_ms_max"]))
    if hi > 0:
        time.sleep(random.uniform(min(lo, hi), hi) / 1000.0)


def _rand_alnum(n, upper=False):
    pool = (string.ascii_uppercase if upper else string.ascii_lowercase) + string.digits
    return "".join(random.choice(pool) for _ in range(int(n)))


def exec_output_name():
    """Temp filename impacket uses to capture command output over SMB.

    Stock impacket ships tell-tale names -- '__<epoch>' (wmiexec) and
    '__output_<rand>' (smbexec) on ADMIN$/C$ -- both matched by public Sigma/
    Defender rules. Drop the '__' prefix; look like ordinary %TEMP% clutter.
    """
    ext = _env("exec_output_ext", _DEFAULTS["exec_output_ext"])
    return _rand_alnum(8) + ext


def exec_service_name():
    """Service name for smbexec's transient service (stock: 8 ascii letters).

    Random mixed alnum by default (a pure-letter name is itself a tell in the
    7045 service-install event); set IMPACKET_OPSEC_EXEC_SERVICE_NAME to a fixed,
    environment-plausible name to blend in further.
    """
    v = _env("exec_service_name", _DEFAULTS["exec_service_name"])
    return v or _rand_alnum(8, upper=True)


def exec_shell_prefix():
    """Shell wrapper prepended to a remote command. Stock nxc/impacket use
    'cmd.exe /Q /c '. That '/Q /c' shape, spawned by wmiprvse.exe/services.exe,
    is part of public Impacket exec signatures (e.g. Sophos
    WIN-EXE-PRC-IMPACKET-WMIEXEC). Configurable so the command line can be
    softened for testing against a specific EDR, e.g.:
        IMPACKET_OPSEC_EXEC_SHELL_PREFIX='cmd.exe /c '                       (drop /Q)
        IMPACKET_OPSEC_EXEC_SHELL_PREFIX='cmd.exe /c ping -n 4 127.0.0.1 >nul & '

    IMPORTANT: this only alters the command LINE. The wmiprvse.exe->cmd.exe
    parent-child that behavioural EDR rules key on is unchanged -- a softer
    wrapper may perturb a narrow command-line signature but will not defeat a
    process-lineage rule. Gated: only nxc_obf (IMPACKET_OPSEC=1) uses it; plain
    nxc stays on the stock wrapper.
    """
    if exec_no_cmd():
        return ""            # raw process, no cmd.exe wrapper (see exec_no_cmd)
    v = _env("exec_shell_prefix", _DEFAULTS["exec_shell_prefix"])
    # A wrapper needs exactly one separating space before the command. configparser
    # strips the trailing space from profile.conf, and env values are easy to
    # forget -- normalise so 'cmd.exe /c' never fuses into 'cmd.exe /cwhoami'.
    return v if (not v or v.endswith(" ")) else v + " "


def exec_no_cmd():
    """Fire-and-forget raw execution (IMPACKET_OPSEC_EXEC_NO_CMD=1, obf-gated).

    When on, nxc's wmiexec (a) drops the 'cmd.exe /Q /c ' wrapper -> Win32_Process
    launches the target binary directly, so there is NO wmiprvse.exe->cmd.exe
    child, and (b) appends no '1> <tempfile> 2>&1' redirect and reads no output
    file -- the two artefacts the Sophos WIN-EXE-PRC-IMPACKET-WMIEXEC rule was
    observed to key on. This is the quietest wmiexec posture, at the cost of: no
    command output returned, and only real executables run (no shell builtins,
    pipes, redirects, chaining, or env-var expansion -- those need cmd.exe).
    """
    return str(_env("exec_no_cmd", "")).strip().lower() in ("1", "true", "yes", "on")


def exec_redirect(outfile):
    """Build the stdout+stderr redirect appended to a command when output is
    collected. Stock impacket emits '1> <file> 2>&1'; the explicit '1>' (with the
    'cmd.exe /Q /c' wrapper) is what Sophos' WIN-EXE-PRC-IMPACKET-WMIEXEC rule was
    observed to key on. FalconOps goexec uses a plain '> <file> 2>&1' and evades
    that rule while still collecting output. Style selector (obf-gated):
        IMPACKET_OPSEC_EXEC_REDIRECT_STYLE=goexec  -> '> <file> 2>&1'  (plain '>')
        unset / 'stock'                            -> '1> <file> 2>&1' (impacket)
    '>' and '1>' are semantically identical (both redirect stdout); this only
    changes the token the signature can match on.
    """
    style = str(_env("exec_redirect_style", _DEFAULTS["exec_redirect_style"])).strip().lower()
    op = ">" if style in ("goexec", "plain", ">") else "1>"
    return f" {{op}} {{outfile}} 2>&1"


def client_pid():
    """A plausible Windows client PID for the TDS Login7 ClientPID field.

    impacket ships random.randint(0, 1024) -- implausibly low: real user
    processes sit in the thousands, and Windows PIDs are always multiples of 4
    (the kernel allocates the client-id table in units of 4). Default range
    1000..40000, step 4; tune via IMPACKET_OPSEC_TDS_CLIENT_PID_MIN/_MAX. The
    server ignores this field, so widening/narrowing it is risk-free.
    """
    lo = int(_env("tds_client_pid_min", _DEFAULTS["tds_client_pid_min"]))
    hi = int(_env("tds_client_pid_max", _DEFAULTS["tds_client_pid_max"]))
    lo = max(4, lo - (lo % 4))
    hi = max(lo + 4, hi)
    return random.randrange(lo, hi, 4)


def tds_prelogin_version():
    """The 6-byte PRELOGIN VERSION token sent in the TDS pre-login.

    impacket hardcodes the literal 08 00 01 55 00 00 in every handshake -- a
    fixed value that fingerprints the client regardless of the workstation name.
    Encodes a 'major.minor.build' string as major(1) + minor(1) + build(2, big-
    endian) + a 2-byte subbuild (0). The server does NOT validate this (it only
    echoes its OWN version back, which is what impacket parses), so any plausible
    value is safe. NOTE: the default 16.0.1000 is a best-effort placeholder -- for
    the tightest blend set IMPACKET_OPSEC_TDS_PRELOGIN_VERSION to a value captured
    from a real client/driver in the target environment.
    """
    s = str(_env("tds_prelogin_version", _DEFAULTS["tds_prelogin_version"])).strip()
    parts = (s.split(".") + ["0", "0", "0"])[:3]
    try:
        maj, minr, build = (int(p or 0) for p in parts)
    except ValueError:
        maj, minr, build = 16, 0, 1000
    return bytes([maj & 0xFF, minr & 0xFF]) + struct.pack(">H", build & 0xFFFF) + b"\\x00\\x00"


def tds_packet_size():
    """Login7 requested packet size (and impacket's internal TDS fragmentation
    size). impacket uses 32763, or 16383 once a TLS context is set up (nxc's
    mssql path always does). Real SSMS defaults to 4096; SQL Server accepts any
    size and dictates the effective one via ENVCHANGE anyway, so a smaller value
    just means more fragmentation. Default 4096; tune via
    IMPACKET_OPSEC_TDS_PACKET_SIZE.
    """
    return max(512, int(_env("tds_packet_size", _DEFAULTS["tds_packet_size"])))
'''


# --------------------------------------------------------------------------- #
#  Patch definitions
# --------------------------------------------------------------------------- #
# Each patch is (patch_id, filename, list_of_edits).
# An edit is a dict:
#   pattern      : regex to find (re.DOTALL not enabled unless in pattern)
#   replacement  : replacement string (may use \g<name> backrefs)
#   marker       : if this string is already in the file, the edit is considered
#                  already applied (idempotency)
#   count        : expected number of matches (default 1). Applied to all.
#   already_marker (optional): for removals -- if pattern is gone but this marker
#                  is present, treat as already-applied instead of drift.

IMPORT_LINE = "import impacket._opsec as _opsec"

def import_edit():
    # Insert the _opsec import right after the first top-level impacket import,
    # falling back to the first plain `import` line.
    return {
        "pattern": r"(?m)^(?P<anchor>(?:from impacket[\w. ]*import[^\n]*|import impacket[^\n]*))$",
        "replacement": r"\g<anchor>\n" + IMPORT_LINE,
        "marker": IMPORT_LINE,
        "count": None,            # only replace the FIRST match
        "first_only": True,
        "fallback_pattern": r"(?m)^(?P<anchor>import +\w[^\n]*)$",
    }

# Every single-line replacement carries a unique `# opsec:<id>` tag. The tag is
# the idempotency marker (never present in a fresh impacket) and doubles as a
# greppable audit breadcrumb. Multi-line/structural edits use `already_marker`.
PATCHES = [
    ("smb3_import", "smb3.py", [import_edit()]),
    ("smb3_clientguid", "smb3.py", [{
        "pattern": r"self\.ClientGuid\s*=\s*''\.join\(\[random\.choice\(string\.ascii_letters\)\s*for\s*i\s*in\s*range\(16\)\]\)",
        "replacement": "self.ClientGuid = _opsec.client_guid()  # opsec:smb3_clientguid",
        "marker": "# opsec:smb3_clientguid",
    }]),
    # --- SMB2/3 Windows-style multi-dialect NEGOTIATE (the default path) --------
    # Stock impacket, when no preferredDialect is given, offers ONLY [2.0.2,2.1,3.0]
    # with NO negotiate contexts and caps 0x40 -- a glaring impacket fingerprint
    # (a real Win10/11 client offers 2.0.2..3.1.1 + PreAuth/Encryption contexts).
    # This rewrites that else-branch to send the full Windows dialect list WITH the
    # 3.1.1 contexts, computing NegotiateContextOffset for the multi-dialect case
    # (getting this wrong is the historical STATUS_INVALID_PARAMETER). The SERVER
    # then auto-selects: pre-2016 -> <=3.0 (ignores the contexts), 2016+ -> 3.1.1.
    # Backward-compatible, so it is ALWAYS ON like the other wire patches.
    # A/B tested vs Server 2022 (DC/SRV/WIN11): full flow incl. root create + wmiexec
    # exec all OK. Salt is real random bytes (_opsec.salt); caps via _opsec
    # (default 0x47 -- MUST exclude DIRECTORY_LEASING 0x20, see profile.conf);
    # cipher stays AES-128-CCM (offering GCM makes the server pick it and impacket,
    # which is CCM-only, resets the connection).
    ("smb2_multidialect", "smb3.py", [{
        "pattern": (
            r"            else:\n"
            r"                negSession\['Dialects'\] = \[SMB2_DIALECT_002, SMB2_DIALECT_21, SMB2_DIALECT_30\]\n"
            r"            negSession\['DialectCount'\] = len\(negSession\['Dialects'\]\)"
        ),
        "replacement": (
            "            else:  # opsec:smb2_multidialect\n"
            "                _dialects = [SMB2_DIALECT_002, SMB2_DIALECT_21, SMB2_DIALECT_30, 0x0302, SMB2_DIALECT_311]\n"
            "                negSession['Dialects'] = _dialects\n"
            "                _base = 64 + 36 + 2 * len(_dialects)\n"
            "                _aligned = (_base + 7) & ~7\n"
            "                _pa = SMB2PreAuthIntegrityCapabilities()\n"
            "                _pa['HashAlgorithmCount'] = 1\n"
            "                _pa['SaltLength'] = 32\n"
            "                _pa['HashAlgorithms'] = bytes([1, 0])\n"
            "                _pa['Salt'] = _opsec.salt(32)\n"
            "                _c1 = SMB2NegotiateContext()\n"
            "                _c1['ContextType'] = SMB2_PREAUTH_INTEGRITY_CAPABILITIES\n"
            "                _c1['Data'] = _pa.getData()\n"
            "                _c1['DataLength'] = len(_c1['Data'])\n"
            "                _padc = bytes((8 - (_c1['DataLength'] % 8)) % 8)\n"
            "                _ec = SMB2EncryptionCapabilities()\n"
            "                _ec['CipherCount'] = 1\n"
            "                _ec['Ciphers'] = bytes([1, 0])\n"
            "                _c2 = SMB2NegotiateContext()\n"
            "                _c2['ContextType'] = SMB2_ENCRYPTION_CAPABILITIES\n"
            "                _c2['Data'] = _ec.getData()\n"
            "                _c2['DataLength'] = len(_c2['Data'])\n"
            "                _cd = SMB311ContextData()\n"
            "                _cd['NegotiateContextOffset'] = _aligned\n"
            "                _cd['NegotiateContextCount'] = 2\n"
            "                negSession['ClientStartTime'] = _cd.getData()\n"
            "                negSession['Padding'] = bytes(_aligned - _base)\n"
            "                negSession['NegotiateContextList'] = _c1.getData() + _padc + _c2.getData()\n"
            "                negSession['Capabilities'] = _opsec.smb2_capabilities()\n"
            "                self._Connection['Capabilities'] = _opsec.smb2_capabilities()\n"
            "            negSession['DialectCount'] = len(negSession['Dialects'])"
        ),
        "marker": "# opsec:smb2_multidialect",
    }]),
    # NOTE: smb3_capabilities, smb3_dialects, smb3_salt and smb3_transform_nonce
    # were all REMOVED. Every one changed the SMB *negotiate* (capabilities,
    # dialect list, salt/nonce) and each altered negotiated behaviour enough to
    # hit a fragile impacket path against real Windows Server 2022:
    #   - dialects->3.0.2 and/or the DIRECTORY_LEASING bit in caps 0x67 made the
    #     server report SupportsDirectoryLeasing, driving impacket into a create
    #     path with a latent UnboundLocalError ('parentDir') on root-level files
    #     -> every file/dir create (the --shares write-check, put_file, exec
    #     output) crashed AFTER a successful login;
    #   - salt/nonce swapped an ASCII str for os.urandom() bytes into fields
    #     impacket packs via value.encode() -> "'bytes' has no attribute encode".
    # Rule learned: only change SMB values that are behaviourally INERT.
    # ClientGuid (a random 16-byte value) qualifies and is kept; the negotiate
    # capabilities/dialects/salt/nonce do not, so they are left stock.
    # --- SMB1 native strings (NativeOS/LanMan, both occurrences) ---
    ("smb_import", "smb.py", [import_edit()]),
    ("smb_native", "smb.py", [{
        "pattern": r"sessionSetup\['Data'\]\['NativeOS'\]\s*=\s*'Unix'",
        "replacement": "sessionSetup['Data']['NativeOS']      = _opsec.native_os()  # opsec:smb_native_os",
        "marker": "# opsec:smb_native_os",
        "count": 2,
    }, {
        "pattern": r"sessionSetup\['Data'\]\['NativeLanMan'\]\s*=\s*'Samba'",
        "replacement": "sessionSetup['Data']['NativeLanMan']  = _opsec.native_lanman()  # opsec:smb_native_lanman",
        "marker": "# opsec:smb_native_lanman",
        "count": 2,
    }]),
    # --- NTLM VERSION: REMOVED (do not re-add without testing against Windows).
    #     Injecting a VERSION block into the SMB NTLM Type1/Type3 breaks Windows
    #     session setup with STATUS_INVALID_PARAMETER -- confirmed by isolation
    #     against Server 2022. SMB's Type1 already carries a non-empty workstation
    #     name; adding os_version on top yields an NTLMSSP message the server
    #     rejects (the impacket LDAP path works only because it uses an EMPTY
    #     workstation). Net value of the NTLM VERSION fingerprint is low vs.
    #     breaking auth, so NTLM is left as stock (no VERSION block).
    # --- hostname leak (NetBIOS session + NTLM workstation field) ---
    ("smbconn_import", "smbconnection.py", [import_edit()]),
    ("smbconn_hostname", "smbconnection.py", [{
        "pattern": r"myName\s*=\s*socket\.gethostname\(\)",
        "replacement": "myName = _opsec.workstation()  # opsec:smbconn_hostname",
        "marker": "# opsec:smbconn_hostname",
    }]),
]

# --------------------------------------------------------------------------- #
#  Enum-script hardening (behavioural IOCs the library defaults don't cover)
# --------------------------------------------------------------------------- #
# root="lib"      -> file lives in the impacket package dir
# root="examples" -> file lives in the impacket examples dir (the CLI scripts)
ENUM_PATCHES = [
    # Kerberoasting: the TGS-REQ etype list is hardcoded RC4-first (+ dead DES) in
    # getKerberosTGS, so EVERY Kerberos TGS request yields RC4 service tickets
    # (Event 4769, TicketEncryptionType 0x17 -> SigmaHQ 496a0e47-...). Offer AES
    # first like a real Windows client. Trade-off: AES roast hashes crack slower.
    ("kerberoast_etype", "krb5/kerberosv5.py", [{
        "pattern": (
            r"seq_set_iter\(reqBody, 'etype',\s*\(\s*"
            r"int\(constants\.EncryptionTypes\.rc4_hmac\.value\),\s*"
            r"int\(constants\.EncryptionTypes\.des3_cbc_sha1_kd\.value\),\s*"
            r"int\(constants\.EncryptionTypes\.des_cbc_md5\.value\),\s*"
            r"int\(cipher\.enctype\)\s*\)\s*\)"
        ),
        "replacement": (
            "seq_set_iter(reqBody, 'etype',  # opsec:kerberoast_etype\n"
            "                      (\n"
            "                          int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),\n"
            "                          int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),\n"
            "                          int(constants.EncryptionTypes.rc4_hmac.value),\n"
            "                          int(cipher.enctype)\n"
            "                       )\n"
            "                )"
        ),
        "marker": "# opsec:kerberoast_etype",
    }], "lib"),
    # AS-REP roasting: GetNPUsers requests RC4-only in the AS-REQ (Event 4768,
    # etype 0x17 + preauth 0 -> highest-confidence AS-REP signal, MITRE DET0113).
    # Offer AES first, keep RC4 last as a legacy fallback.
    ("asrep_etype", "GetNPUsers.py", [{
        "pattern": r"supportedCiphers = \(int\(constants\.EncryptionTypes\.rc4_hmac\.value\),\)",
        "replacement": ("supportedCiphers = (int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value), "
                        "int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value), "
                        "int(constants.EncryptionTypes.rc4_hmac.value),)  # opsec:asrep_etype"),
        "marker": "# opsec:asrep_etype",
    }], "examples"),
    # RID cycling: lookupsid asks for 1000 sequential SIDs per LSAR call (a burst
    # that lights up 4661/4662 mass-lookup analytics). Shrink the batch and pace it.
    ("lookupsid_import", "lookupsid.py", [import_edit()], "examples"),
    ("lookupsid_rid_batch", "lookupsid.py", [{
        "pattern": r"SIMULTANEOUS = 1000",
        "replacement": "SIMULTANEOUS = _opsec.rid_batch()  # opsec:lookupsid_rid_batch",
        "marker": "# opsec:lookupsid_rid_batch",
    }], "examples"),
    ("lookupsid_pace", "lookupsid.py", [{
        "pattern": r"(?P<i>[ \t]*)sids = list\(\)",
        "replacement": "\\g<i>_opsec.pace()  # opsec:lookupsid_pace\n\\g<i>sids = list()",
        "marker": "# opsec:lookupsid_pace",
    }], "examples"),
    # LDAP hygiene: GetADUsers pages at 100 (unusual); AD default MaxPageSize is
    # 1000. Normalise it. (The LDAP *filters* are inherent to the technique and are
    # not patched here -- see the report.)
    ("getadusers_pagesize", "GetADUsers.py", [{
        "pattern": r"SimplePagedResultsControl\(size=100\)",
        "replacement": "SimplePagedResultsControl(size=1000)  # opsec:getadusers_pagesize",
        "marker": "# opsec:getadusers_pagesize",
    }], "examples"),
    # --- Exec output artefacts (wmiexec/smbexec CLI tools) -------------------
    # Command output is captured to a temp file on ADMIN$/C$ whose name is a
    # static tell: '__<epoch>' (wmiexec) and '__output_<rand>' (smbexec). Both
    # are matched by public detections. Route the name through _opsec so the
    # '__' prefix is gone and it reads like ordinary %TEMP% clutter. The smbexec
    # transient service name (a 7045 IOC) is likewise normalised. NOT gated --
    # these are impacket CLI tools, always on, like the other example patches.
    ("wmiexec_import", "wmiexec.py", [import_edit()], "examples"),
    ("wmiexec_output", "wmiexec.py", [{
        "pattern": r"OUTPUT_FILENAME = '__' \+ str\(time\.time\(\)\)",
        "replacement": "OUTPUT_FILENAME = _opsec.exec_output_name()  # opsec:wmiexec_output",
        "marker": "# opsec:wmiexec_output",
    }], "examples"),
    ("smbexec_import", "smbexec.py", [import_edit()], "examples"),
    ("smbexec_output", "smbexec.py", [{
        "pattern": r"OUTPUT_FILENAME = '__output_' \+ ''\.join\(\[random\.choice\(string\.ascii_letters\) for i in range\(8\)\]\)",
        "replacement": "OUTPUT_FILENAME = _opsec.exec_output_name()  # opsec:smbexec_output",
        "marker": "# opsec:smbexec_output",
    }], "examples"),
    ("smbexec_service", "smbexec.py", [{
        "pattern": r"self\.__serviceName = ''\.join\(\[random\.choice\(string\.ascii_letters\) for i in range\(8\)\]\)",
        "replacement": "self.__serviceName = _opsec.exec_service_name()  # opsec:smbexec_service",
        "marker": "# opsec:smbexec_service",
    }], "examples"),
    # --- MSSQL/TDS Login7 workstation (cross-protocol consistency) -----------
    # This impacket already blends TDS: AppName defaults to an SSMS string and
    # the host to a random DESKTOP-xxxx (not 'impacket'/'kali'). The one gap is
    # consistency -- that random host differs from the workstation SMB/NTLM send
    # in the same op. Pin it to _opsec.workstation() so every protocol in a run
    # presents ONE workstation. AppName is left as the (already plausible) SSMS
    # default. The loud MSSQL surface (xp_cmdshell via sp_configure) is exec
    # behaviour, not this wire layer, and is out of scope here.
    ("mssql_import", "tds.py", [import_edit()], "lib"),
    ("mssql_workstation", "tds.py", [{
        "pattern": r'self\._workstation_id = workstation_id or f"DESKTOP-\{uuid4\(\)\.hex\[:8\]\.upper\(\)\}"',
        "replacement": 'self._workstation_id = workstation_id or _opsec.workstation()  # opsec:mssql_workstation',
        "marker": "# opsec:mssql_workstation",
    }], "lib"),
    # --- MSSQL/TDS residual wire tells (ungated wire layer, all impacket MSSQL
    # tools + nxc). None of these carry credentials or affect the workstation
    # name; they are the constant TDS-handshake bytes a protocol-aware inspector
    # fingerprints impacket by. The encryption preference (TDS_ENCRYPT_OFF) is
    # deliberately NOT touched -- forcing full-session TLS is unreliable in this
    # impacket and would expose Python's ssl JA3 (the same TLS layer this range's
    # EDR already resets on LDAPS). See README "Residual tells".
    ("mssql_prelogin_version", "tds.py", [{
        # PreLogin VERSION: hardcoded literal 08 00 01 55 00 00 -> configurable.
        "pattern": r'''prelogin\['Version'\] = b"\\x08\\x00\\x01\\x55\\x00\\x00"''',
        "replacement": "prelogin['Version'] = _opsec.tds_prelogin_version()  # opsec:mssql_prelogin_version",
        "marker": "# opsec:mssql_prelogin_version",
    }], "lib"),
    ("mssql_packet_size_init", "tds.py", [{
        # __init__ default 32763 (used by the non-TLS impacket path).
        "pattern": r"self\.packetSize = 32763",
        "replacement": "self.packetSize = _opsec.tds_packet_size()  # opsec:mssql_packet_size_init",
        "marker": "# opsec:mssql_packet_size_init",
    }], "lib"),
    ("mssql_packet_size_tls", "tds.py", [{
        # set_tls_context() override 16*1024-1 (the value nxc's mssql path sends,
        # since enum_host_info() sets up a TLS context before building Login7).
        "pattern": r"self\.packetSize = 16 \* 1024 - 1",
        "replacement": "self.packetSize = _opsec.tds_packet_size()  # opsec:mssql_packet_size_tls",
        "marker": "# opsec:mssql_packet_size_tls",
    }], "lib"),
    ("mssql_client_pid", "tds.py", [{
        # Two identical Login7 ClientPID sites (login + kerberosLogin): the
        # implausibly-low randint(0,1024) -> a realistic Windows PID. count=2.
        "pattern": r"login\['ClientPID'\] = random\.randint\(0,1024\)",
        "replacement": "login['ClientPID'] = _opsec.client_pid()  # opsec:mssql_client_pid",
        "marker": "# opsec:mssql_client_pid",
        "count": 2,
    }], "lib"),
]

# --------------------------------------------------------------------------- #
#  NetExec (nxc) patches -- root="nxc" targets the installed nxc package.
#  All are GATED on _opsec.enabled() (env IMPACKET_OPSEC=1): plain `nxc`
#  stays vanilla, the `nxc_obf` wrapper turns them on. They reuse impacket's
#  _opsec module (from impacket import _opsec), which install always drops first.
# --------------------------------------------------------------------------- #
NXC_PATCHES = [
    ("nxc_smb_import", "protocols/smb.py", [import_edit()], "nxc"),
    # SMB1-first: a real Win10/11 client never negotiates SMB1. Skip it in obf mode.
    ("nxc_smb1_off", "protocols/smb.py", [{
        "pattern": r"if self\.smbv1 is None and not no_smbv1 and not self\.args\.no_smbv1:",
        "replacement": ("if not _opsec.enabled() and self.smbv1 is None and not no_smbv1 "
                        "and not self.args.no_smbv1:  # opsec:nxc_smb1_off"),
        "marker": "# opsec:nxc_smb1_off",
    }], "nxc"),
    # RID cycling: nxc's own rid_brute bursts 1000 SIDs per LSAR call.
    ("nxc_rid_batch", "protocols/smb.py", [{
        "pattern": r"simultaneous = 1000",
        "replacement": "simultaneous = _opsec.rid_batch() if _opsec.enabled() else 1000  # opsec:nxc_rid_batch",
        "marker": "# opsec:nxc_rid_batch",
    }], "nxc"),
    ("nxc_rid_pace", "protocols/smb.py", [{
        "pattern": (r"(?P<i>[ \t]*)lsat\.hLsarLookupSids\(dce, policy_handle, sids, "
                    r"lsat\.LSAP_LOOKUP_LEVEL\.LsapLookupWksta\)"),
        "replacement": ("\\g<i>if _opsec.enabled(): _opsec.pace()  # opsec:nxc_rid_pace\n"
                        "\\g<i>lsat.hLsarLookupSids(dce, policy_handle, sids, "
                        "lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta)"),
        "marker": "# opsec:nxc_rid_pace",
    }], "nxc"),
    # AS-REP roasting: nxc builds its own AS-REQ with RC4-only (not the GetNPUsers path).
    ("nxc_kerberos_import", "protocols/ldap/kerberos.py", [import_edit()], "nxc"),
    ("nxc_asrep_etype", "protocols/ldap/kerberos.py", [{
        "pattern": r"supported_ciphers = \(int\(constants\.EncryptionTypes\.rc4_hmac\.value\),\)",
        "replacement": ("supported_ciphers = tuple(_opsec.asrep_ciphers()) if _opsec.enabled() "
                        "else (int(constants.EncryptionTypes.rc4_hmac.value),)  # opsec:nxc_asrep_etype"),
        "marker": "# opsec:nxc_asrep_etype",
    }], "nxc"),
    # gen_random_string: random.sample -> never-repeating letters, no digits (a tell).
    ("nxc_misc_import", "helpers/misc.py", [import_edit()], "nxc"),
    ("nxc_gen_random", "helpers/misc.py", [{
        "pattern": r'return "".join\(random\.sample\(string\.ascii_letters, int\(length\)\)\)',
        "replacement": ('return "".join(random.choices(string.ascii_letters + string.digits, k=int(length))) '
                        'if _opsec.enabled() else "".join(random.sample(string.ascii_letters, int(length)))  '
                        '# opsec:nxc_gen_random'),
        "marker": "# opsec:nxc_gen_random",
    }], "nxc"),
    # wmiexec shell wrapper: nxc hardcodes 'cmd.exe /Q /c '. Under wmiprvse.exe
    # this is the WIN-EXE-PRC-IMPACKET-WMIEXEC signature shape. Route it through
    # _opsec.exec_shell_prefix() so the command line can be softened per-run
    # (drop /Q, prepend a benign command, etc.) for EDR testing. Covers both
    # execute_remote and execute_fileless (both use self.__shell). GATED --
    # plain nxc keeps the stock wrapper. Behaviour-neutral by default (the helper
    # default IS 'cmd.exe /Q /c '); softening is opt-in via the env var. Does not
    # touch the wmiprvse->cmd parent-child (out of reach of a wire/CLI patch).
    ("nxc_wmiexec_import", "protocols/smb/wmiexec.py", [import_edit()], "nxc"),
    ("nxc_wmiexec_shell", "protocols/smb/wmiexec.py", [{
        "pattern": r'self\.__shell = "cmd\.exe /Q /c "',
        "replacement": ('self.__shell = _opsec.exec_shell_prefix() if _opsec.enabled() '
                        'else "cmd.exe /Q /c "  # opsec:nxc_wmiexec_shell'),
        "marker": "# opsec:nxc_wmiexec_shell",
    }], "nxc"),
    # exec_no_cmd fire-and-forget: when IMPACKET_OPSEC_EXEC_NO_CMD=1 (obf), drop
    # the output redirect (execute_remote) and skip the output read
    # (get_output_remote). Combined with exec_shell_prefix()->'' this yields a
    # raw Win32_Process.Create with no cmd.exe child and no '1> ...\Temp\... 2>&1'
    # -- the two artefacts the WMIEXEC rule keyed on. Anchors target execute_remote
    # specifically (the 'command = self.__shell + data' + newline is unique to it;
    # execute_fileless has '+ f"..."' after data).
    ("nxc_wmiexec_nocmd", "protocols/smb/wmiexec.py", [{
        "pattern": r"command = self\.__shell \+ data\n(?P<i>[ \t]*)if self\.__retOutput:",
        "replacement": ("command = self.__shell + data\n"
                        "\\g<i>if self.__retOutput and not (_opsec.enabled() and _opsec.exec_no_cmd()):  # opsec:nxc_wmiexec_nocmd"),
        "marker": "# opsec:nxc_wmiexec_nocmd",
    }, {
        "pattern": r"if self\.__retOutput is False:",
        "replacement": "if self.__retOutput is False or (_opsec.enabled() and _opsec.exec_no_cmd()):  # opsec:nxc_wmiexec_nocmd_out",
        "marker": "# opsec:nxc_wmiexec_nocmd_out",
    }], "nxc"),
    # wmi protocol (base64->registry retrieval): make its shell wrapper the same
    # configurable knob. Changes the retrieval channel away from the C$ file read
    # (helps if the rule keys on that read); note it still emits a cmd redirect to
    # a temp file, so it won't help if the rule keys on the command line.
    ("nxc_wmi_import", "protocols/wmi/wmiexec.py", [import_edit()], "nxc"),
    ("nxc_wmi_shell", "protocols/wmi/wmiexec.py", [{
        "pattern": r'self\.__shell = "cmd\.exe /Q /c "',
        "replacement": ('self.__shell = _opsec.exec_shell_prefix() if _opsec.enabled() '
                        'else "cmd.exe /Q /c "  # opsec:nxc_wmi_shell'),
        "marker": "# opsec:nxc_wmi_shell",
    }], "nxc"),
    # Redirect style: nxc hardcodes the impacket-specific '1> <file> 2>&1' in
    # execute_remote. Route it through _opsec.exec_redirect() so obf can emit
    # goexec's plain '> <file> 2>&1' (IMPACKET_OPSEC_EXEC_REDIRECT_STYLE=goexec),
    # which was observed to slip WIN-EXE-PRC-IMPACKET-WMIEXEC while keeping output.
    # Gated + default stock, so plain nxc and un-set obf are byte-identical.
    ("nxc_wmiexec_redirect", "protocols/smb/wmiexec.py", [{
        "pattern": r'command \+= f" 1> \{self\.__output\} 2>&1"',
        "replacement": ('command += (_opsec.exec_redirect(self.__output) if _opsec.enabled() '
                        'else f" 1> {self.__output} 2>&1")  # opsec:nxc_wmiexec_redirect'),
        "marker": "# opsec:nxc_wmiexec_redirect",
    }], "nxc"),
    # mmcexec (MMC20.Application DCOM) builds 'cmd.exe /Q /c <cmd> 1> ...Temp... 2>&1'
    # -- same '1>' the WMIEXEC A/B proved is the discriminator. Route the redirect
    # through _opsec.exec_redirect() so obf emits '>' too. The '/Q /c' is left as-is
    # (A/B showed it is not the trigger). Its own generic import anchor would land
    # inside a multi-line 'from impacket ... import (' block, so the _opsec import is
    # pinned to a single-line import instead. NB: mmcexec has its own MMC-lineage
    # rule (mmc.exe->cmd.exe); whether '>' alone silences it must be tested.
    ("nxc_mmcexec_import", "protocols/smb/mmcexec.py", [{
        "pattern": r"(?m)^(?P<anchor>from nxc\.helpers\.misc import gen_random_string)$",
        "replacement": "\\g<anchor>\n" + IMPORT_LINE,
        "marker": IMPORT_LINE,
    }], "nxc"),
    ("nxc_mmcexec_redirect", "protocols/smb/mmcexec.py", [{
        "pattern": r'command \+= " 1> " \+ f"\{self\.__output\}" \+ " 2>&1"',
        "replacement": ('command += (_opsec.exec_redirect(self.__output) if _opsec.enabled() '
                        'else " 1> " + f"{self.__output}" + " 2>&1")  # opsec:nxc_mmcexec_redirect'),
        "marker": "# opsec:nxc_mmcexec_redirect",
    }], "nxc"),
    # MSSQL identity: nxc's enum_host_info() builds its OWN pre-auth Login7 with
    # empty HostName/AppName -- it bypasses the patched tds.py MSSQL defaults, so
    # the FIRST Login7 on the wire (the NTLMSSP-Type1 one) carries no workstation
    # or app identity at all. That is itself a mild anomaly: a real SSMS/SqlClient
    # always sends both. Route both fields through the MSSQL object's already-
    # patched workstation_id / application_name so the enum Login7 presents the
    # SAME identity as the auth Login7 (CltIntName copies AppName downstream, so it
    # follows automatically). GATED -- plain nxc keeps the empty strings (byte-
    # identical to vanilla). Note: this closes only the identity gap; the residual
    # TDS tells (PreLogin Version bytes, packetSize 32763, encryption-off, low
    # ClientPID) are unchanged and documented in README "Residual tells".
    ("nxc_mssql_import", "protocols/mssql.py", [import_edit()], "nxc"),
    ("nxc_mssql_identity", "protocols/mssql.py", [{
        "pattern": r'login\["HostName"\] = ""',
        "replacement": ('login["HostName"] = self.conn.workstation_id.encode("utf-16le") '
                        'if _opsec.enabled() else ""  # opsec:nxc_mssql_hostname'),
        "marker": "# opsec:nxc_mssql_hostname",
    }, {
        "pattern": r'login\["AppName"\] = ""',
        "replacement": ('login["AppName"] = self.conn.application_name.encode("utf-16le") '
                        'if _opsec.enabled() else ""  # opsec:nxc_mssql_appname'),
        "marker": "# opsec:nxc_mssql_appname",
    }], "nxc"),
    # nxc's enum Login7 has its OWN low ClientPID (randint(0,1024)); gate it onto
    # the same realistic _opsec.client_pid() so the pre-auth Login7 matches the
    # auth one under obf. (PacketSize needs no nxc patch -- enum reads
    # self.conn.packetSize, which the ungated tds.py set_tls_context patch above
    # already sets to _opsec.tds_packet_size().) Plain nxc stays vanilla.
    ("nxc_mssql_clientpid", "protocols/mssql.py", [{
        "pattern": r'login\["ClientPID"\] = random\.randint\(0, 1024\)',
        "replacement": ('login["ClientPID"] = _opsec.client_pid() if _opsec.enabled() '
                        'else random.randint(0, 1024)  # opsec:nxc_mssql_clientpid'),
        "marker": "# opsec:nxc_mssql_clientpid",
    }], "nxc"),
]

# Normalise every entry to a 4-tuple (pid, fn, edits, root) and merge.
PATCHES = [(p if len(p) == 4 else (*p, "lib")) for p in PATCHES] + ENUM_PATCHES + NXC_PATCHES

TOUCHED = sorted({(root, fn) for _, fn, _, root in PATCHES})


# --------------------------------------------------------------------------- #
#  Backup / manifest
# --------------------------------------------------------------------------- #
def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def load_manifest():
    if os.path.isfile(MANIFEST):
        with open(MANIFEST) as f:
            return json.load(f)
    return {}

def save_manifest(m):
    os.makedirs(BACKUP_DIR, exist_ok=True)
    with open(MANIFEST, "w") as f:
        json.dump(m, f, indent=2)

def backup_file(base_dir, fn, root, manifest):
    src = os.path.join(base_dir, fn)
    dst = os.path.join(BACKUP_DIR, root, fn + ".orig")
    key = f"{root}:{fn}"
    if os.path.exists(dst):
        return  # already backed up -- never overwrite a pristine backup
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.copy2(src, dst)
    manifest.setdefault("backups", {})[key] = {
        "root": root,
        "fn": fn,
        "orig_sha256": sha256(dst),
        "backed_up_at": datetime.now(timezone.utc).isoformat(),
    }


# --------------------------------------------------------------------------- #
#  Edit engine
# --------------------------------------------------------------------------- #
def apply_edit(content, edit):
    """Return (new_content, status) where status in applied/already/drift.

    Order matters:
      1. own post-patch `marker` present            -> already
      2. `require_marker` (a dependency) absent      -> drift (don't touch)
      3. `pattern` (or `fallback_pattern`) matches   -> apply
      4. no match, but `already_marker` present, or
         a satisfied `require_marker` (removal done)  -> already
      5. otherwise                                    -> drift
    """
    marker = edit.get("marker")
    if marker and marker in content:
        return content, "already"

    require = edit.get("require_marker")
    if require and require not in content:
        # a dependency (e.g. the coordinated first edit) did not apply
        return content, "drift"

    pat = re.compile(edit["pattern"])
    matches = list(pat.finditer(content))
    if not matches and edit.get("fallback_pattern"):
        pat = re.compile(edit["fallback_pattern"])
        matches = list(pat.finditer(content))

    if matches:
        if edit.get("first_only"):
            m = matches[0]
            return content[:m.start()] + m.expand(edit["replacement"]) + content[m.end():], "applied"
        expected = edit.get("count", 1)
        if expected is not None and len(matches) != expected:
            return content, "drift"
        return pat.sub(edit["replacement"], content), "applied"

    # no match
    if edit.get("already_marker") and edit["already_marker"] in content:
        return content, "already"
    if require:
        # dependency satisfied and the target is already gone (idempotent removal)
        return content, "already"
    return content, "drift"


def run_patches(impdir, examplesdir, nxcdir, cfg, dry_run):
    manifest = load_manifest()
    manifest["impacket_dir"] = impdir
    manifest["examples_dir"] = examplesdir
    manifest["nxc_dir"] = nxcdir
    manifest["impacket_version"] = impacket_version(impdir)
    manifest.setdefault("applied", {})
    roots = {"lib": impdir, "examples": examplesdir, "nxc": nxcdir}

    # 1) drop the _opsec.py runtime module
    opsec_path = os.path.join(impdir, "_opsec.py")
    module_status = "applied"
    desired = render_opsec_module(cfg)
    if os.path.isfile(opsec_path):
        with open(opsec_path) as f:
            existing = f.read()
        if OPSEC_MODULE_MARKER in existing:
            module_status = "updated" if existing != desired else "already"
        else:
            err(f"{opsec_path} exists but is not ours -- refusing to overwrite")
            sys.exit(3)
    if not dry_run and module_status != "already":
        with open(opsec_path, "w") as f:
            f.write(desired)
    tag = {"applied": GRN, "updated": CYN, "already": DIM}.get(module_status, "")
    print(f"  {tag}_opsec.py{RST:>0}: {module_status}")

    # 2) group edits by (root, file) so we read/write each file once
    by_file = {}
    for pid, fn, edits, root in PATCHES:
        by_file.setdefault((root, fn), []).append((pid, edits))

    results = {}
    for (root, fn), groups in by_file.items():
        base_dir = roots.get(root)
        path = os.path.join(base_dir, fn) if base_dir else None
        if not path or not os.path.isfile(path):
            for pid, _ in groups:
                results[pid] = "drift"
                manifest["applied"][pid] = "drift"
                where = f"{root}:{fn}" if base_dir else f"{root} dir not found"
                print(f"  {RED}[!]{RST} {pid:<24} ({where})")
            continue
        with open(path) as f:
            content = f.read()
        original = content
        if not dry_run:
            backup_file(base_dir, fn, root, manifest)

        for pid, edits in groups:
            statuses = []
            for edit in edits:
                content, st = apply_edit(content, edit)
                statuses.append(st)
            # aggregate: drift if any drift, applied if any applied, else already
            if "drift" in statuses:
                agg = "drift"
            elif "applied" in statuses:
                agg = "applied"
            else:
                agg = "already"
            results[pid] = agg
            manifest["applied"][pid] = agg
            colour = {"applied": GRN, "already": DIM, "drift": RED}[agg]
            symbol = {"applied": "+", "already": "=", "drift": "!"}[agg]
            print(f"  {colour}[{symbol}]{RST} {pid:<24} ({root}:{fn})")

        if not dry_run and content != original:
            with open(path, "w") as f:
                f.write(content)

    if not dry_run:
        manifest["last_action_at"] = datetime.now(timezone.utc).isoformat()
        save_manifest(manifest)
    return results


# --------------------------------------------------------------------------- #
#  Commands
# --------------------------------------------------------------------------- #
def read_profile(path):
    cfg = configparser.ConfigParser()
    # keep case + allow empty values
    cfg.optionxform = str
    if not os.path.isfile(path):
        err(f"profile not found: {path}")
        sys.exit(2)
    cfg.read(path)
    if not cfg.has_section("opsec"):
        err("profile has no [opsec] section")
        sys.exit(2)
    return dict(cfg.items("opsec"))

def cmd_install(args):
    impdir = find_impacket(args.impacket)
    examplesdir = find_examples(getattr(args, "examples", None), impdir)
    nxcdir = find_nxc(getattr(args, "nxc", None))
    cfg = read_profile(args.profile)
    # Apply command-line overrides on top of profile.conf, before _opsec.py is
    # rendered. --workstation is a shortcut for --set workstation=...
    overrides = {}
    if getattr(args, "workstation", None) is not None:
        overrides["workstation"] = args.workstation
    for kv in getattr(args, "set", []) or []:
        if "=" not in kv:
            err(f"--set expects KEY=VALUE, got: {kv!r}")
            sys.exit(2)
        k, v = kv.split("=", 1)
        overrides[k.strip()] = v.strip()
    if overrides:
        cfg.update(overrides)
        for k, v in overrides.items():
            info(f"override: {k} = {v!r}")
    info(f"impacket: {impdir}  (v{impacket_version(impdir)})")
    info(f"examples: {examplesdir}")
    info(f"nxc:      {nxcdir}")
    if not os.access(impdir, os.W_OK) or not os.access(os.path.join(impdir, "smb3.py"), os.W_OK):
        err(f"No write permission on {impdir}. Re-run with sudo.")
        sys.exit(4)
    info(f"profile:  {args.profile}")
    print()
    results = run_patches(impdir, examplesdir, nxcdir, cfg, dry_run=False)
    print()
    drift = [p for p, s in results.items() if s == "drift"]
    if drift:
        warn(f"{len(drift)} patch(es) did not match this impacket version (DRIFT): {', '.join(drift)}")
        warn("Those IOCs are NOT fixed. Inspect manually before relying on stealth.")
    else:
        ok("All patches applied/verified.")
    info("Reminder: run  sudo apt-mark hold python3-impacket  to survive apt upgrades.")
    info("Verify on the wire with tcpdump before touching client infrastructure.")

def cmd_verify(args):
    impdir = find_impacket(args.impacket)
    examplesdir = find_examples(getattr(args, "examples", None), impdir)
    nxcdir = find_nxc(getattr(args, "nxc", None))
    info(f"impacket: {impdir}  (v{impacket_version(impdir)})")
    info(f"examples: {examplesdir}")
    info(f"nxc:      {nxcdir}")
    manifest = load_manifest()
    if manifest.get("impacket_version") and manifest["impacket_version"] != impacket_version(impdir):
        warn(f"impacket version changed since install "
             f"({manifest['impacket_version']} -> {impacket_version(impdir)}). "
             f"An apt upgrade may have reverted the patches.")
    print()
    # dry-run against current files: 'already' == still patched, 'applied' == NOT patched
    cfg = read_profile(args.profile) if os.path.isfile(args.profile) else {}
    results = run_patches(impdir, examplesdir, nxcdir, cfg or read_profile(os.path.join(HERE, "profile.conf")), dry_run=True)
    print()
    missing = [p for p, s in results.items() if s == "applied"]
    drift = [p for p, s in results.items() if s == "drift"]
    if not missing and not drift:
        ok("All patches present. Client is de-fingerprinted.")
        # also smoke-test that _opsec imports
        _smoke_test(impdir)
        return 0
    if missing:
        err(f"{len(missing)} patch(es) NOT applied (reverted?): {', '.join(missing)}")
    if drift:
        warn(f"{len(drift)} patch(es) drifted: {', '.join(drift)}")
    return 1

def _smoke_test(impdir):
    cwd = os.getcwd()
    try:
        os.chdir("/")
        sys.path.insert(0, os.path.dirname(impdir))
        import importlib
        m = importlib.import_module("impacket._opsec")
        importlib.reload(m)
        g = m.client_guid()
        assert isinstance(g, bytes) and len(g) == 16
        v = m.ntlm_version()
        info(f"_opsec ok: workstation={m.workstation()!r}, "
             f"ntlm={v['ProductMajorVersion']}.{v['ProductMinorVersion']}.{v['ProductBuild']}, "
             f"caps={hex(m.smb2_capabilities())}")
    except Exception as e:
        warn(f"_opsec smoke-test failed: {e}")
    finally:
        os.chdir(cwd)

def cmd_status(args):
    impdir = find_impacket(args.impacket)
    manifest = load_manifest()
    info(f"impacket: {impdir}  (v{impacket_version(impdir)})")
    if not manifest:
        warn("No manifest -- nothing installed from here yet.")
        return
    print(f"  installed against : impacket v{manifest.get('impacket_version')}")
    print(f"  last action       : {manifest.get('last_action_at')}")
    print(f"  backups           : {', '.join(manifest.get('backups', {}).keys()) or 'none'}")
    applied = manifest.get("applied", {})
    for pid, st in applied.items():
        colour = {"applied": GRN, "already": GRN, "drift": RED}.get(st, "")
        print(f"    {colour}{st:<8}{RST} {pid}")

def cmd_uninstall(args):
    impdir = find_impacket(args.impacket)
    examplesdir = find_examples(getattr(args, "examples", None), impdir)
    nxcdir = find_nxc(getattr(args, "nxc", None))
    roots = {"lib": impdir, "examples": examplesdir, "nxc": nxcdir}
    manifest = load_manifest()
    # Source of truth is the .orig files ON DISK, not the manifest or PATCHES.
    # This restores every file ever backed up -- including files an older version
    # of the patcher touched but the current PATCHES no longer list (e.g. a patch
    # removed after a bad release, like the old ntlm.py). The manifest may have
    # lost its "backups" map, so we never rely on it for the file list.
    backups = {}
    for r in ("lib", "examples", "nxc"):
        root_dir = os.path.join(BACKUP_DIR, r)
        if not os.path.isdir(root_dir):
            continue
        for dp, _dirs, files in os.walk(root_dir):
            for f in files:
                if f.endswith(".orig"):
                    fn = os.path.relpath(os.path.join(dp, f)[:-5], root_dir)  # strip ".orig"
                    backups[f"{r}:{fn}"] = {"root": r, "fn": fn}
    if not backups:
        err("No backups found -- cannot restore.")
        sys.exit(2)
    if not os.access(impdir, os.W_OK):
        err(f"No write permission on {impdir}. Re-run with sudo.")
        sys.exit(4)
    for key, meta in backups.items():
        root = meta.get("root") or (key.split(":", 1)[0] if ":" in key else "lib")
        fn = meta.get("fn") or (key.split(":", 1)[1] if ":" in key else key)
        src = os.path.join(BACKUP_DIR, root, fn + ".orig")
        base_dir = roots.get(root)
        if not os.path.isfile(src) or not base_dir:
            warn(f"backup missing for {root}:{fn}, skipping")
            continue
        shutil.copy2(src, os.path.join(base_dir, fn))
        ok(f"restored {root}:{fn}")
    opsec_path = os.path.join(impdir, "_opsec.py")
    if os.path.isfile(opsec_path):
        with open(opsec_path) as f:
            if OPSEC_MODULE_MARKER in f.read():
                os.remove(opsec_path)
                ok("removed _opsec.py")
    manifest["applied"] = {}
    manifest["last_action_at"] = datetime.now(timezone.utc).isoformat()
    save_manifest(manifest)
    ok("Uninstalled. (Run  sudo apt-mark unhold python3-impacket  if you held it.)")


def main():
    ap = argparse.ArgumentParser(description="De-fingerprint a system-wide impacket install.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("install", "verify", "status", "uninstall"):
        p = sub.add_parser(name)
        p.add_argument("--impacket", help="impacket package dir (default: auto-detect)")
        p.add_argument("--examples", help="impacket examples/CLI-scripts dir (default: auto-detect)")
        p.add_argument("--nxc", help="installed nxc (NetExec) package dir (default: auto-detect)")
        p.add_argument("--profile", default=os.path.join(HERE, "profile.conf"))
        if name == "install":
            # Bake profile values in at install time without editing profile.conf.
            p.add_argument("--workstation", default=None,
                           help="workstation/NetBIOS name to bake into _opsec.py "
                                "(overrides profile.conf; pass empty to force a random "
                                "DESKTOP-XXXXXXX per process)")
            p.add_argument("--set", action="append", default=[], metavar="KEY=VALUE",
                           help="override any [opsec] value at install time (repeatable), "
                                "e.g. --set ntlm_build=22631 --set smb2_capabilities=0x47 "
                                "--set tds_prelogin_version=16.0.4155")
    args = ap.parse_args()
    return {
        "install": cmd_install,
        "verify": cmd_verify,
        "status": cmd_status,
        "uninstall": cmd_uninstall,
    }[args.cmd](args) or 0


if __name__ == "__main__":
    sys.exit(main())
