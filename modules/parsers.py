"""Output parsers for the tools admap runs.

Kept side-effect free so they can be tested against captured output. Formats
drift between tool versions, so each parser skips lines it doesn't recognise.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass


@dataclass
class ParsedUser:
    username: str
    rid: int | None = None
    description: str = ""


@dataclass
class ParsedShare:
    name: str
    readable: bool = False
    writable: bool = False
    comment: str = ""


@dataclass
class ParsedAsrep:
    username: str
    hash: str


# nxc lines are "PROTO IP PORT HOST <payload>"; strip the prefix, parse payload
_NXC_PREFIX = re.compile(
    r"^\s*\w+\s+\d{1,3}(?:\.\d{1,3}){3}\s+\d+\s+\S+\s+(.*)$"
)


def _nxc_payloads(output: str) -> list[str]:
    payloads = []
    for line in output.splitlines():
        m = _NXC_PREFIX.match(line)
        if m:
            payloads.append(m.group(1).rstrip())
    return payloads


def parse_nxc_rid_brute(output: str) -> tuple[list[ParsedUser], str | None]:
    # rows like "500: CORP\Administrator (SidTypeUser)"
    users: list[ParsedUser] = []
    domain: str | None = None
    row = re.compile(r"^(\d+):\s+([^\\]+)\\(.+?)\s+\(SidType(\w+)\)")
    for payload in _nxc_payloads(output):
        m = row.match(payload)
        if not m:
            continue
        rid, dom, name, sidtype = int(m.group(1)), m.group(2), m.group(3), m.group(4)
        domain = domain or dom
        if sidtype == "User" and not name.endswith("$"):  # skip machine accounts
            users.append(ParsedUser(username=name, rid=rid))
    return users, domain


def parse_nxc_users(output: str) -> list[ParsedUser]:
    # --users table: "<name> <last pw set> <badpw> <description>"
    users: list[ParsedUser] = []
    for payload in _nxc_payloads(output):
        if payload.startswith("-Username-") or set(payload) <= set("- "):
            continue
        if payload.startswith("[") or "\\" in payload.split()[0:1][:1]:
            continue
        tok = payload.split()
        if not tok:
            continue
        name = tok[0]
        if not re.match(r"^[A-Za-z0-9._$-]+$", name) or name.endswith("$"):
            continue
        desc = ""
        m = re.search(r"\s\d+\s+(.*)$", payload)
        if m:
            desc = m.group(1).strip()
        users.append(ParsedUser(username=name, description=desc))
    return users


def parse_nxc_shares(output: str) -> list[ParsedShare]:
    # --shares table: "<share> <permissions> <remark>"
    shares: list[ParsedShare] = []
    for payload in _nxc_payloads(output):
        if payload.startswith("Share") or set(payload) <= set("- "):
            continue
        tok = payload.split(None, 2)
        if not tok:
            continue
        name = tok[0]
        perms = tok[1].upper() if len(tok) > 1 else ""
        remark = tok[2] if len(tok) > 2 else ""
        if perms and not re.match(r"^(READ|WRITE|,)+$", perms):
            # no permissions column, so what we read was the remark
            remark = (tok[1] + " " + remark).strip() if len(tok) > 1 else remark
            perms = ""
        shares.append(ParsedShare(
            name=name,
            readable="READ" in perms,
            writable="WRITE" in perms,
            comment=remark,
        ))
    return shares


def parse_kerbrute_userenum(output: str) -> list[str]:
    out = []
    for m in re.finditer(r"VALID USERNAME:\s+([^\s@]+)(?:@\S+)?", output):
        out.append(m.group(1))
    return out


def parse_asrep_hashes(output: str) -> list[ParsedAsrep]:
    # hashcat format: "$krb5asrep$23$user@DOMAIN:<hash>"
    out = []
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("$krb5asrep$"):
            m = re.search(r"\$krb5asrep\$\d+\$([^@]+)@", line)
            out.append(ParsedAsrep(username=m.group(1) if m else "?", hash=line))
    return out


@dataclass
class ParsedCred:
    username: str
    password: str
    domain: str = ""


def _split_list(inner: str) -> list[str]:
    return [tok.strip().strip("'\"") for tok in inner.split(",") if tok.strip()]


def parse_gpp(output: str) -> list[ParsedCred]:
    # gpp modules print index-aligned "Usernames: [...]" / "Passwords: [...]"
    users: list[str] = []
    passwords: list[str] = []
    domains: list[str] = []
    for p in _nxc_payloads(output):
        mu = re.search(r"Usernames?:\s*\[(.*?)\]", p)
        mp = re.search(r"Passwords?:\s*\[(.*?)\]", p)
        md = re.search(r"Domains?:\s*\[(.*?)\]", p)
        if mu:
            users += _split_list(mu.group(1))
        if mp:
            passwords += _split_list(mp.group(1))
        if md:
            domains += _split_list(md.group(1))
    creds: list[ParsedCred] = []
    for i, u in enumerate(users):
        if not u:
            continue
        creds.append(ParsedCred(
            username=u,
            password=passwords[i] if i < len(passwords) else "",
            domain=domains[i] if i < len(domains) else "",
        ))
    return creds


def parse_laps(output: str) -> list[tuple[str, str]]:
    # returns (computer, local admin password) pairs
    out: list[tuple[str, str]] = []
    for p in _nxc_payloads(output):
        mc = re.search(r"Computer:\s*(\S+)", p)
        mp = re.search(r"Password:\s*(\S+)", p)
        if mc and mp:
            out.append((mc.group(1).rstrip("$"), mp.group(1)))
    return out


@dataclass
class AuthResult:
    proto: str
    host: str
    hostname: str
    valid: bool = False
    pwned: bool = False
    locked: bool = False


_AUTH_LINE = re.compile(
    r"^\s*(\w+)\s+(\d{1,3}(?:\.\d{1,3}){3})\s+\d+\s+(\S+)\s+(.*)$"
)


def parse_nxc_auth(output: str) -> list[AuthResult]:
    # one result per host line: [+] valid, [-] failed, (Pwn3d!) admin, LOCKED
    out: list[AuthResult] = []
    for line in output.splitlines():
        m = _AUTH_LINE.match(line)
        if not m:
            continue
        proto, ip, host, payload = m.group(1), m.group(2), m.group(3), m.group(4)
        up = payload.upper()
        valid = "[+]" in payload
        failed = "[-]" in payload
        locked = "LOCKED" in up
        if not (valid or failed or locked):
            continue
        out.append(AuthResult(proto=proto.lower(), host=ip, hostname=host,
                              valid=valid, pwned="PWN3D" in up, locked=locked))
    return out


def parse_spn_users(output: str) -> list[str]:
    # GetUserSPNs table: SPN column then SamAccountName; take distinct names
    users: list[str] = []
    for line in output.splitlines():
        tok = line.split()
        if len(tok) >= 2 and "/" in tok[0] and re.match(r"^[A-Za-z0-9._-]+$", tok[1]):
            if tok[1] not in users:
                users.append(tok[1])
    return users


@dataclass
class SpiderHit:
    share: str
    path: str
    size: str = ""
    level: str = "medium"    # "high" | "medium"
    reason: str = ""


# filename/path substrings that usually mean secrets
_HIGH_NAMES = [
    "unattend", "sysprep", "autologon", "autologin", "password", "passwd",
    "cred", "secret", "vault", "id_rsa", "id_dsa", ".git-credentials", ".npmrc",
    "web.config", "groups.xml", "scheduledtasks.xml", "printers.xml",
    "drives.xml", "datasources.xml", "_history", "standalone.xml",
]
_HIGH_EXT = {".kdbx", ".pfx", ".p12", ".ppk", ".pem", ".key",
             ".ova", ".vmdk", ".vhdx"}
_MED_EXT = {".config", ".xml", ".ps1", ".bat", ".cmd", ".vbs", ".ini", ".conf",
            ".yml", ".yaml", ".json", ".bak", ".old", ".rdp", ".sql", ".txt"}


def classify_file(path: str) -> tuple[str, str] | None:
    lower = path.replace("\\", "/").lower()
    for n in _HIGH_NAMES:
        if n in lower:
            return "high", f"name match: {n}"
    ext = os.path.splitext(lower)[1]
    if ext in _HIGH_EXT:
        return "high", f"high-value extension: {ext}"
    if ext in _MED_EXT:
        return "medium", f"extension: {ext}"
    return None


def parse_spider_json(data: dict) -> list[SpiderHit]:
    # spider_plus output: {share: {filepath: {size, ...}}}
    hits: list[SpiderHit] = []
    for share, files in data.items():
        if not isinstance(files, dict):
            continue
        for path, meta in files.items():
            c = classify_file(path)
            if not c:
                continue
            size = meta.get("size", "") if isinstance(meta, dict) else ""
            hits.append(SpiderHit(share=share, path=path, size=str(size),
                                  level=c[0], reason=c[1]))
    return hits
