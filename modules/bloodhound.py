"""BloodHound ingest: read a collection .zip into engagement state.

Enriches users, resolves LocalAdmins through nested group membership so we
know which computers a held cred is admin on, and detects DCSync rights on the
domain object. Handles both legacy SharpHound and BloodHound CE layouts, which
nest member SIDs and LocalAdmins differently."""
from __future__ import annotations

import json
import os
import zipfile
from dataclasses import dataclass

from ..core.config import Config
from ..core.log import get_logger
from ..core.models import ADUser, Credential, Finding, Phase, Severity
from ..core.runner import Runner
from ..core.state import State

log = get_logger(__name__)


def _member_sid(m: dict) -> str | None:
    return m.get("ObjectIdentifier") or m.get("MemberId")


def _members(record: dict, key: str) -> list[str]:
    # Members/LocalAdmins may be a plain list (legacy) or {'Results': [...]} (CE)
    val = record.get(key)
    if isinstance(val, dict):
        items = val.get("Results", [])
    elif isinstance(val, list):
        items = val
    else:
        items = []
    return [s for s in (_member_sid(i) for i in items) if s]


@dataclass
class BHUser:
    username: str
    domain: str
    sid: str
    enabled: bool = True
    dont_require_preauth: bool = False
    has_spn: bool = False
    unconstrained: bool = False
    admincount: bool = False
    description: str = ""


def parse_users(records: list[dict]) -> list[BHUser]:
    out: list[BHUser] = []
    for r in records:
        p = r.get("Properties", {}) or {}
        name = (p.get("name") or "").strip()
        if not name:
            continue
        out.append(BHUser(
            username=name.split("@")[0],
            domain=p.get("domain", "") or (name.split("@")[1] if "@" in name else ""),
            sid=r.get("ObjectIdentifier", ""),
            enabled=bool(p.get("enabled", True)),
            dont_require_preauth=bool(p.get("dontreqpreauth", False)),
            has_spn=bool(p.get("hasspn", False) or p.get("serviceprincipalnames")),
            unconstrained=bool(p.get("unconstraineddelegation", False)),
            admincount=bool(p.get("admincount", False)),
            description=p.get("description") or "",
        ))
    return out


def build_group_members(groups: list[dict]) -> dict[str, list[str]]:
    # sid -> member sids; a sid appearing as a key means it's a group
    gm: dict[str, list[str]] = {}
    for g in groups:
        sid = g.get("ObjectIdentifier")
        if sid:
            gm[sid] = _members(g, "Members")
    return gm


def expand_to_users(principal_sids, group_members: dict[str, list[str]],
                    _seen: set | None = None) -> set[str]:
    # expand principals down to leaf SIDs, following nested groups; cycle-safe
    if _seen is None:
        _seen = set()
    leaves: set[str] = set()
    for sid in principal_sids:
        if sid in _seen:
            continue
        _seen.add(sid)
        if sid in group_members:
            leaves |= expand_to_users(group_members[sid], group_members, _seen)
        else:
            leaves.add(sid)
    return leaves


def build_admin_map(computers: list[dict],
                    group_members: dict[str, list[str]]) -> dict[str, set[str]]:
    # user_sid -> {computer name} where the user is a local admin
    admin_map: dict[str, set[str]] = {}
    for c in computers:
        name = (c.get("Properties", {}) or {}).get("name", "") or c.get("ObjectIdentifier", "")
        admin_sids = _members(c, "LocalAdmins")
        for user_sid in expand_to_users(admin_sids, group_members):
            admin_map.setdefault(user_sid, set()).add(name)
    return admin_map


def dcsync_principal_sids(domains: list[dict]) -> set[str]:
    # combined CE 'DCSync' right, or legacy GetChanges + GetChangesAll
    out: set[str] = set()
    for d in domains:
        rights: dict[str, set[str]] = {}
        for ace in d.get("Aces", []) or []:
            sid = ace.get("PrincipalSID")
            if not sid:
                continue
            rights.setdefault(sid, set()).add(ace.get("RightName") or "")
        for sid, rset in rights.items():
            if "DCSync" in rset or (
                "GetChanges" in rset
                and ("GetChangesAll" in rset or "GetChangesInFilteredSet" in rset)
            ):
                out.add(sid)
    return out


def load_zip(path: str) -> dict[str, list[dict]]:
    data: dict[str, list[dict]] = {}
    with zipfile.ZipFile(path) as z:
        for n in z.namelist():
            if not n.endswith(".json"):
                continue
            try:
                obj = json.loads(z.read(n))
            except Exception:
                continue
            typ = (obj.get("meta") or {}).get("type")
            if not typ:
                for t in ("users", "computers", "groups", "domains"):
                    if t in n.lower():
                        typ = t
                        break
            if typ:
                data.setdefault(typ, []).extend(obj.get("data", []) or [])
    return data


def find_latest_zip(dirs: list[str]) -> str | None:
    cands: list[str] = []
    for d in dirs:
        if not os.path.isdir(d):
            continue
        for f in os.listdir(d):
            if f.lower().endswith(".zip"):
                cands.append(os.path.join(d, f))
    valid = []
    for c in cands:
        try:
            with zipfile.ZipFile(c) as z:
                if any(n.lower().endswith(".json") and "users" in n.lower()
                       for n in z.namelist()):
                    valid.append(c)
        except Exception:
            continue
    return max(valid, key=os.path.getmtime) if valid else None


def run(cfg: Config, state: State, runner: Runner, zip_path: str | None = None) -> None:
    zip_path = zip_path or find_latest_zip([".", cfg.loot_dir])
    if not zip_path:
        log.warning("no BloodHound .zip found; run the authed collection first")
        return
    log.info("ingesting BloodHound data: %s", zip_path)
    data = load_zip(zip_path)

    users = parse_users(data.get("users", []))
    group_members = build_group_members(data.get("groups", []))
    admin_map = build_admin_map(data.get("computers", []), group_members)
    dcsync_sids = expand_to_users(dcsync_principal_sids(data.get("domains", [])),
                                  group_members)

    for u in users:
        state.upsert_user(ADUser(
            username=u.username, domain=u.domain, sid=u.sid, enabled=u.enabled,
            is_admin=u.admincount,
            description=u.description,
            dont_require_preauth=u.dont_require_preauth,
            trusted_for_delegation=u.unconstrained,
            spn="(kerberoastable)" if u.has_spn else None,
        ))

    unconstrained = [u.username for u in users if u.unconstrained]
    if unconstrained:
        state.add_finding(Finding(
            category="kerberos", title="Unconstrained delegation account(s)",
            detail="Accounts trusted for unconstrained delegation: "
                   + ", ".join(unconstrained),
            severity=Severity.HIGH, source_module="bloodhound",
            mindmap_node="Authed > Kerberos delegation > Unconstrained",
            phase=Phase.AUTHED,
        ))

    # map held creds -> admin_on (drives secretsdump / dcsync rules)
    sid_by_user = {u.username.lower(): u.sid for u in users}
    dc_short = {(h.hostname or "").split(".")[0].upper(): h.ip
                for h in state.dcs() if h.hostname}

    for cred in state.credentials():
        sid = sid_by_user.get(cred.username.lower())
        if not sid:
            continue
        admin_on: set[str] = set(cred.admin_on) | admin_map.get(sid, set())

        if sid in dcsync_sids:
            admin_on |= set(dc_short.values())
            state.add_finding(Finding(
                category="acl", title=f"DCSync rights: {cred.username}",
                detail="Held account can replicate the domain (GetChanges/All).",
                severity=Severity.CRITICAL, source_module="bloodhound",
                mindmap_node="Privileged > Domain dominance > DCSync (ACL)",
                phase=Phase.PRIVILEGED,
            ))

        # match BH computer FQDNs to known DC IPs
        for comp in list(admin_on):
            short = comp.split(".")[0].upper()
            if short in dc_short:
                admin_on.add(dc_short[short])

        if admin_on != set(cred.admin_on):
            cred.admin_on = sorted(admin_on)
            state.add_credential(cred)
            log.info("%s is local admin on %d host(s)", cred.username, len(admin_on))
