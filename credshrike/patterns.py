"""Credential-detection patterns for the snaffler-style scan mode.

Two kinds of knowledge, distilled from Snaffler's default rule set:

- PATTERN list: content regexes. Each entry carries a name and a compiled
  pattern; when the pattern has a capture group, group(1) is THE SECRET and
  gets masked in snippets (context stays, value goes).
- Extension tiers: which files are worth opening, in priority order.
  "red"  = almost certainly credential-bearing, scan first
  "yellow" = plausibly interesting, scan second
  anything else = skipped by the scan (the model can still read files
  individually — this only orders/bounds the deterministic sweep).

Users extend/override via policy (scan_extra_patterns) or a YAML file
(--scan-patterns): mapping of {name: regex-with-optional-group}.
"""

from __future__ import annotations

import re

DEFAULT_PATTERNS: list[dict] = [
    {"name": "password_assignment", "pattern": r"(?i)\bpass(?:word|wd)\b\s*[:=]\s*[\"']?([^\s\"';]{4,})"},
    {"name": "pwd_assignment", "pattern": r"(?i)\bpwd\b\s*[:=]\s*[\"']?([^\s\"';]{4,})"},
    {"name": "secret_assignment", "pattern": r"(?i)\bsecret\b\s*[:=]\s*[\"']?([^\s\"';]{4,})"},
    {"name": "connection_string_password", "pattern": r"(?i)\bpassword\s*=\s*([^;\s\"']{4,})"},
    {"name": "private_key_block", "pattern": r"-----BEGIN [A-Z ]*PRIVATE KEY-----"},
    {"name": "aws_access_key", "pattern": r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"},
    {"name": "github_token", "pattern": r"\bghp_[A-Za-z0-9]{36}\b"},
    {"name": "slack_token", "pattern": r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"},
    {"name": "azure_storage_key", "pattern": r"\bAccountKey=[A-Za-z0-9+/=]{60,}"},
    # command-line credential: net use \\srv\share /user:DOMAIN\user password
    # (group = the SECRET so masking hides the password, username stays visible)
    {"name": "net_use_credential", "pattern": r"(?i)/user:[A-Za-z0-9_.\\$-]+\s+([^\s\"\x27]{4,})"},
    # --- Snaffler relay-rule regexes (per-language + specialty) -------------
    {"name": "jdbc_password",
     "pattern": r"(?i)jdbc:[a-z0-9]+://[^\s\"';]*password=([^\s\"';]{3,})"},
    {"name": "php_db_connect",
     "pattern": r"(?i)(?:mysql|mysqli|pg|postgres)_connect\([^)]{0,140}['\"]([^'\"]{3,})['\"]\s*[,)]"},
    {"name": "python_db_connect",
     'pattern': r'(?i)\b(?:pymysql|psycopg2|mysql\.connector)\.connect\(.{0,200}?password=[\x22\x27]{0,2}([^,)\s\x22\x27]{3,40})'},
    {"name": "dbi_dsn_password",
     "pattern": r"(?i)DBI->connect\([^)]{0,160}['\"]([^'\"]{3,})['\"]\s*[,)]"},
    {"name": "unattend_password",
     "pattern": r"(?is)<(?:Administrator)?Password>\s*<Value>([^<]{4,})</Value>"},
    {"name": "machinekey_validation",
     "pattern": r"(?i)<machineKey[^>]*validationKey=\"([A-Za-z0-9]{40,})\""},
    {"name": "rdp_dpapi_password",
     "pattern": r"(?i)password\s*51\s*:[ab]:\s*([A-Za-z0-9+/=]{20,})"},
    {"name": "cisco_enable_secret",
     "pattern": r"(?i)(?:enable\s+secret|username\s+\S+\s+password)\s+(?:5\s+)?(\S+)"},

]

# --- file triage tiers ------------------------------------------------------ #
RED_EXTS = {".kdbx", ".key", ".pem", ".ppk", ".pfx", ".p12", ".rdp", ".vnc", ".env"}
RED_NAME_SUBSTRINGS = ("password", "passwort", "passw", "secret", "credential",
                       "unattend", "sysprep", "web.config", "app.config",
                       "connectionstring", "id_rsa", "keytab")
YELLOW_EXTS = {".config", ".xml", ".ini", ".cfg", ".conf", ".ps1", ".psm1", ".bat",
               ".cmd", ".vbs", ".sql", ".txt", ".yaml", ".yml", ".json", ".csv",
               ".py", ".sh", ".hta", ".asp", ".aspx", ".php", ".jsp", ".reg",
               ".log"}

# structured-data files: regex can't see their secrets (a 'user,pass' CSV row
# has no keyword to match), so the sweep surfaces them for the AI to READ
DATA_EXTS = {".csv", ".tsv", ".json"}

TIERS = {"red": (RED_EXTS, RED_NAME_SUBSTRINGS), "yellow": (YELLOW_EXTS, ())}


def is_data_file(name: str) -> bool:
    return name.lower().endswith(tuple(DATA_EXTS))


def classify_file(name: str, tiers=("red", "yellow")) -> str | None:
    """Return the tier of a file name ('red' > 'yellow') or None (skip)."""
    lowered = name.lower()
    for tier in tiers:
        exts, subs = TIERS[tier]
        if lowered.endswith(tuple(exts)) or any(s in lowered for s in subs):
            return tier
    return None


def compile_patterns(extra: dict | None = None, use_defaults: bool = True) -> list[dict]:
    """Merge default + user patterns into compiled entries
    [{name, regex, compiled}]. User entries with the same name replace
    the built-in one (order preserved: defaults first, extras after)."""
    entries: list[dict] = []
    if use_defaults:
        for entry in DEFAULT_PATTERNS:
            entries.append({"name": entry["name"], "regex": entry["pattern"],
                            "compiled": re.compile(entry["pattern"])})
    for name, pattern in (extra or {}).items():
        entries.append({"name": name, "regex": pattern, "compiled": re.compile(pattern)})
    return entries


# =========================================================================== #
# Snaffler-structured triage (agent's smb_scan_share — the snaffler preset)
#
# Four layers, mirroring upstream Snaffler's default rule set:
#   1. DISCARD          — never look at again (binary junk + known FPs)
#   2. ARTIFACT_*       — the file IS the secret: report, never read
#   3. RELAY_*          — the ONLY entry into content reading (then regex+AI)
#   4. green contains   — wide-net name match, reported when nothing else hit
# CredShrike keeps two extras Snaffler lacks: .key/.vnc stay readable and
# CSV/TSV/JSON are surfaced to the AI as data_files (regex can't see rows).
# =========================================================================== #
DISCARD_EXTS = {
    # images / fonts / styling / schema / misc junk (Snaffler's 27)
    ".png", ".jpg", ".jpeg", ".bmp", ".gif", ".ico", ".svg", ".tif", ".tiff",
    ".webp", ".psd", ".ai",
    ".ttf", ".otf", ".woff", ".woff2", ".eot", ".fon",
    ".css", ".less", ".scss",
    ".xsd", ".xsl", ".xslt", ".admx", ".adml", ".lock",
}
DISCARD_NAMES = {   # known false positives (matched on the basename, lowered)
    "jmxremote.password.template", "sceregvl.inf",
}

# --- layer 2: the file itself is evidence — REPORT WITHOUT READING --------- #
ARTIFACT_EXTS = {   # tier -> extensions
    "black": {".kdbx", ".kdb", ".psafe3", ".kwallet", ".keychain",
              ".agilekeychain", ".ppk"},
    "red": {".vmdk", ".vdi", ".vhd", ".vhdx", ".dmp", ".cscfg", ".ucs",
            ".tfvars", ".cred", ".pass"},
    "yellow": {".mdf", ".sdf", ".sqldump", ".bak", ".pcap", ".cap", ".pcapng",
               ".rdg", ".rtsz", ".rtsx", ".ovpn", ".tvopt", ".sdtid",
               ".wim", ".ova", ".ovf", ".keytab", ".ccache"},
}
ARTIFACT_NAMES = {  # tier -> exact basenames (lowered); lsass*.dmp special
    "black": {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "ntds.dit",
              "system", "sam", "security", "memory.dmp", "hiberfil.sys",
              "shadow", "passwd", "running-config", "startup-config",
              "psmapp.cred", "vault.ini", "pvconfiguration.xml",
              "pvconfig.xml", "pvwa.ini", "mobaxterm.ini", "confcons.xml"},
    "red": {".git-credentials", "bitlockerlapspasswords.csv",
            "localsettings.php", "database.yml", "knife.rb",
            "credentials.xml", "filezilla.xml", "proftpdpasswd",
            ".pgpass", "sqlstudio.bin", ".dbeaver-data-sources.xml",
            ".htpasswd", "logins.json", "key4.db"},
}
ARTIFACT_NAME_STEMS = {"passwords", "pass", "accounts", "secrets"}  # stem.*
ARTIFACT_PATHS = {  # tier -> path substrings (posix, lowered)
    "black": ("/.ssh/", "/.aws/"),
    "red": ("customsettings.ini", "smstemp", ),
}

# --- layer 3.5: relay triggers — the only files whose CONTENT is read ------ #
RELAY_EXTS = (            # union over all 19 upstream triggers
    {".xml", ".json", ".txt", ".yaml", ".yml", ".sql", ".log", ".env",
     ".ini", ".cfg", ".conf", ".config", ".reg", ".csv", ".tsv",
     ".properties", ".toml", ".settings", ".plist", ".autologon"},
    {".ps1", ".psd1", ".psm1"},
    {".cs", ".aspx", ".asp", ".ashx", ".asmx", ".cshtml", ".razor"},
    {".vbs", ".vbe", ".wsf", ".wsc", ".hta"},
    {".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs", ".vue", ".svelte",
     ".coffee", ".json5"},
    {".java", ".jsp", ".jspx", ".do", ".cfm"},
    {".php", ".php3", ".php4", ".php5", ".php7", ".phtml"},
    {".py", ".rb", ".pl", ".bat", ".cmd"},
    {".sh", ".bash", ".zsh", ".ksh", ".csh", ".bashrc", ".zshrc", ".profile",
     ".bash_profile", ".bash_history", ".zsh_history", ".netrc", ".cshrc"},
    # certs / keys (incl. CredShrike extras .key/.vnc kept from the old RED tier)
    {".pem", ".der", ".pfx", ".p12", ".key", ".vnc", ".rdp"},
)
RELAY_EXTS = set().union(*RELAY_EXTS)
RELAY_NAMES = {          # exact basenames (lowered)
    "consolehost_history.txt", "logins.json", "unattend.xml", "autounattend.xml",
    "sysprep.xml", "sysprep.inf",
}
RELAY_NAME_CONTAINS = ("cisco", "router", "firewall", "switch",
                       "unattend", "sysprep")   # net-config + unattend family
RELAY_CERT_ENDINGS = ("_rsa", "_dsa", "_ed25519", "_ecdsa")

# --- layer 4: wide-net contains (green) ------------------------------------- #
GREEN_CONTAINS = ("passw", "secret", "credential", "thycotic", "cyberark",
                  "connectionstring")           # + CredShrike extra


def triage(path: str) -> dict:
    """Snaffler-structured classification of one walked file.

    Returns one of:
      {"kind": "discard", "reason": ...}
      {"kind": "artifact", "tier": black|red|yellow, "reason": ...}
      {"kind": "relay"}                          — read + regex + AI
      {"kind": "green", "reason": ...}           — report-only wide-net hit
      {"kind": None}                             — nothing matched, skip
    """
    posix = (path or "").replace("\\", "/").lower().strip("/")
    name = posix.rsplit("/", 1)[-1]
    stem = name.split(".", 1)[0]
    ext = "." + name.rsplit(".", 1)[-1] if "." in name else ""

    if name in DISCARD_NAMES:
        return {"kind": "discard", "reason": f"known false positive: {name}"}
    if ext in DISCARD_EXTS:
        return {"kind": "discard", "reason": f"junk extension {ext}"}

    relay = (name in RELAY_NAMES or ext in RELAY_EXTS
             or any(name.endswith(ending) for ending in RELAY_CERT_ENDINGS)
             or any(word in name for word in RELAY_NAME_CONTAINS))

    # --- artifact layers (file itself is the evidence; never read) --------
    # priority: lsass*.dmp > exact names (Psmapp.cred is BLACK even though the
    # .cred extension alone is only red) > extensions > name stems > paths
    if name.startswith("lsass") and name.endswith(".dmp"):
        return {"kind": "artifact", "tier": "black", "reason": "lsass dump"}
    for tier in ("black", "red"):
        if name in ARTIFACT_NAMES[tier]:
            # logins.json etc: artifact name on a readable ext -> read too
            return {"kind": "artifact", "tier": tier,
                    "reason": f"known artifact name {name}",
                    **({"read": True} if relay else {})}
    for tier in ("black", "red", "yellow"):
        if ext in ARTIFACT_EXTS[tier]:
            return {"kind": "artifact", "tier": tier,
                    "reason": f"artifact extension {ext}"}
    stem_hit = stem in ARTIFACT_NAME_STEMS
    for tier in ("black", "red"):
        for needle in ARTIFACT_PATHS[tier]:
            if needle in posix:
                return {"kind": "artifact", "tier": tier,
                        "reason": f"path contains '{needle}'"}

    # --- relay triggers (content reading) ----------------------------------
    # artifact by NAME/STEM but readable ext (passwords.txt, logins.json):
    # report the artifact flag AND read it — CredShrike's AI benefits from
    # the content, upstream Snaffler would only have reported it
    if stem_hit and not relay:
        return {"kind": "artifact", "tier": "red",
                "reason": f"credential-ish name stem '{stem}'"}
    if relay:
        for tier in ("black", "red"):
            if name in ARTIFACT_NAMES[tier]:
                return {"kind": "artifact", "tier": tier,
                        "reason": f"known artifact name {name}", "read": True}
        if stem_hit:
            return {"kind": "artifact", "tier": "red",
                    "reason": f"credential-ish name stem '{stem}'", "read": True}
        return {"kind": "relay"}

    # --- green wide net: report-only (ext not readable anyway) ------------
    for word in GREEN_CONTAINS:
        if word in name:
            return {"kind": "green", "reason": f"name wide-net match ('{word}')"}
    return {"kind": None}
