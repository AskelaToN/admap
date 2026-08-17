"""SQLite engagement state. One DB file per engagement.

Upserts are idempotent so modules can be re-run safely as more creds turn up.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .models import (
    ADUser,
    Credential,
    Domain,
    Finding,
    Host,
    SecretType,
    Severity,
    Share,
    Phase,
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS hosts (
    ip TEXT PRIMARY KEY,
    hostname TEXT, os TEXT, domain TEXT,
    is_dc INTEGER DEFAULT 0,
    smb_signing INTEGER,            -- NULL unknown, 1 required, 0 not required
    ports TEXT DEFAULT '[]',
    notes TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS domains (
    name TEXT PRIMARY KEY,
    sid TEXT, functional_level TEXT,
    dc_hosts TEXT DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS users (
    username TEXT, domain TEXT,
    sid TEXT, rid INTEGER,
    enabled INTEGER DEFAULT 1,
    is_admin INTEGER DEFAULT 0,
    description TEXT DEFAULT '',
    dont_require_preauth INTEGER DEFAULT 0,
    trusted_for_delegation INTEGER DEFAULT 0,
    spn TEXT,
    PRIMARY KEY (username, domain)
);
CREATE TABLE IF NOT EXISTS credentials (
    username TEXT, domain TEXT,
    secret TEXT, secret_type TEXT,
    source TEXT DEFAULT '',
    validated INTEGER DEFAULT 0,
    admin_on TEXT DEFAULT '[]',
    notes TEXT DEFAULT '',
    PRIMARY KEY (username, domain, secret, secret_type)
);
CREATE TABLE IF NOT EXISTS shares (
    host TEXT, name TEXT,
    readable INTEGER DEFAULT 0,
    writable INTEGER DEFAULT 0,
    comment TEXT DEFAULT '',
    PRIMARY KEY (host, name)
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT, title TEXT, detail TEXT DEFAULT '',
    severity TEXT DEFAULT 'info',
    source_module TEXT DEFAULT '',
    evidence TEXT DEFAULT '',
    mindmap_node TEXT DEFAULT '',
    phase TEXT DEFAULT 'unauth',
    UNIQUE (category, title, mindmap_node)
);
"""


class State:
    def __init__(self, path: str | Path = "engagement.db") -> None:
        self.path = str(path)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        try:
            yield self._conn
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def close(self) -> None:
        self._conn.close()

    # hosts
    def upsert_host(self, h: Host) -> None:
        with self._tx() as c:
            c.execute(
                """INSERT INTO hosts (ip, hostname, os, domain, is_dc, smb_signing, ports, notes)
                   VALUES (?,?,?,?,?,?,?,?)
                   ON CONFLICT(ip) DO UPDATE SET
                     hostname=COALESCE(excluded.hostname, hosts.hostname),
                     os=COALESCE(excluded.os, hosts.os),
                     domain=COALESCE(excluded.domain, hosts.domain),
                     is_dc=MAX(hosts.is_dc, excluded.is_dc),
                     smb_signing=COALESCE(excluded.smb_signing, hosts.smb_signing),
                     ports=excluded.ports,
                     notes=CASE WHEN excluded.notes != '' THEN excluded.notes ELSE hosts.notes END
                """,
                (h.ip, h.hostname, h.os, h.domain, int(h.is_dc),
                 None if h.smb_signing is None else int(h.smb_signing),
                 json.dumps(sorted(set(h.ports))), h.notes),
            )

    def hosts(self) -> list[Host]:
        rows = self._conn.execute("SELECT * FROM hosts").fetchall()
        return [
            Host(
                ip=r["ip"], hostname=r["hostname"], os=r["os"], domain=r["domain"],
                is_dc=bool(r["is_dc"]),
                smb_signing=None if r["smb_signing"] is None else bool(r["smb_signing"]),
                ports=json.loads(r["ports"]), notes=r["notes"],
            )
            for r in rows
        ]

    def dcs(self) -> list[Host]:
        return [h for h in self.hosts() if h.is_dc]

    # domains
    def upsert_domain(self, d: Domain) -> None:
        with self._tx() as c:
            c.execute(
                """INSERT INTO domains (name, sid, functional_level, dc_hosts)
                   VALUES (?,?,?,?)
                   ON CONFLICT(name) DO UPDATE SET
                     sid=COALESCE(excluded.sid, domains.sid),
                     functional_level=COALESCE(excluded.functional_level, domains.functional_level),
                     dc_hosts=excluded.dc_hosts""",
                (d.name, d.sid, d.functional_level, json.dumps(d.dc_hosts)),
            )

    def domains(self) -> list[Domain]:
        rows = self._conn.execute("SELECT * FROM domains").fetchall()
        return [
            Domain(name=r["name"], sid=r["sid"], functional_level=r["functional_level"],
                   dc_hosts=json.loads(r["dc_hosts"]))
            for r in rows
        ]

    # users
    def upsert_user(self, u: ADUser) -> None:
        with self._tx() as c:
            c.execute(
                """INSERT INTO users
                   (username, domain, sid, rid, enabled, is_admin, description,
                    dont_require_preauth, trusted_for_delegation, spn)
                   VALUES (?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(username, domain) DO UPDATE SET
                     sid=COALESCE(excluded.sid, users.sid),
                     rid=COALESCE(excluded.rid, users.rid),
                     enabled=excluded.enabled,
                     is_admin=MAX(users.is_admin, excluded.is_admin),
                     description=CASE WHEN excluded.description != '' THEN excluded.description ELSE users.description END,
                     dont_require_preauth=MAX(users.dont_require_preauth, excluded.dont_require_preauth),
                     trusted_for_delegation=MAX(users.trusted_for_delegation, excluded.trusted_for_delegation),
                     spn=COALESCE(excluded.spn, users.spn)""",
                (u.username, u.domain, u.sid, u.rid, int(u.enabled), int(u.is_admin),
                 u.description, int(u.dont_require_preauth),
                 int(u.trusted_for_delegation), u.spn),
            )

    def users(self) -> list[ADUser]:
        rows = self._conn.execute("SELECT * FROM users").fetchall()
        return [
            ADUser(
                username=r["username"], domain=r["domain"], sid=r["sid"], rid=r["rid"],
                enabled=bool(r["enabled"]), is_admin=bool(r["is_admin"]),
                description=r["description"],
                dont_require_preauth=bool(r["dont_require_preauth"]),
                trusted_for_delegation=bool(r["trusted_for_delegation"]),
                spn=r["spn"],
            )
            for r in rows
        ]

    # credentials
    def add_credential(self, cr: Credential) -> None:
        with self._tx() as c:
            c.execute(
                """INSERT INTO credentials
                   (username, domain, secret, secret_type, source, validated, admin_on, notes)
                   VALUES (?,?,?,?,?,?,?,?)
                   ON CONFLICT(username, domain, secret, secret_type) DO UPDATE SET
                     validated=MAX(credentials.validated, excluded.validated),
                     admin_on=excluded.admin_on,
                     notes=CASE WHEN excluded.notes != '' THEN excluded.notes ELSE credentials.notes END""",
                (cr.username, cr.domain, cr.secret, cr.secret_type.value, cr.source,
                 int(cr.validated), json.dumps(cr.admin_on), cr.notes),
            )

    def credentials(self, validated_only: bool = False) -> list[Credential]:
        q = "SELECT * FROM credentials"
        if validated_only:
            q += " WHERE validated=1"
        rows = self._conn.execute(q).fetchall()
        return [
            Credential(
                username=r["username"], domain=r["domain"], secret=r["secret"],
                secret_type=SecretType(r["secret_type"]), source=r["source"],
                validated=bool(r["validated"]), admin_on=json.loads(r["admin_on"]),
                notes=r["notes"],
            )
            for r in rows
        ]

    # shares
    def upsert_share(self, s: Share) -> None:
        with self._tx() as c:
            c.execute(
                """INSERT INTO shares (host, name, readable, writable, comment)
                   VALUES (?,?,?,?,?)
                   ON CONFLICT(host, name) DO UPDATE SET
                     readable=MAX(shares.readable, excluded.readable),
                     writable=MAX(shares.writable, excluded.writable),
                     comment=CASE WHEN excluded.comment != '' THEN excluded.comment ELSE shares.comment END""",
                (s.host, s.name, int(s.readable), int(s.writable), s.comment),
            )

    def shares(self) -> list[Share]:
        rows = self._conn.execute("SELECT * FROM shares").fetchall()
        return [
            Share(host=r["host"], name=r["name"], readable=bool(r["readable"]),
                  writable=bool(r["writable"]), comment=r["comment"])
            for r in rows
        ]

    # findings
    def add_finding(self, f: Finding) -> None:
        with self._tx() as c:
            c.execute(
                """INSERT INTO findings
                   (category, title, detail, severity, source_module, evidence, mindmap_node, phase)
                   VALUES (?,?,?,?,?,?,?,?)
                   ON CONFLICT(category, title, mindmap_node) DO UPDATE SET
                     detail=excluded.detail, severity=excluded.severity,
                     evidence=excluded.evidence""",
                (f.category, f.title, f.detail, f.severity.value, f.source_module,
                 f.evidence, f.mindmap_node, f.phase.value),
            )

    def findings(self) -> list[Finding]:
        rows = self._conn.execute("SELECT * FROM findings ORDER BY id").fetchall()
        return [
            Finding(
                category=r["category"], title=r["title"], detail=r["detail"],
                severity=Severity(r["severity"]), source_module=r["source_module"],
                evidence=r["evidence"], mindmap_node=r["mindmap_node"],
                phase=Phase(r["phase"]),
            )
            for r in rows
        ]

    def current_phase(self) -> Phase:
        creds = self.credentials(validated_only=True)
        if any(c.admin_on for c in creds):
            return Phase.PRIVILEGED
        if creds:
            return Phase.AUTHED
        return Phase.UNAUTH
