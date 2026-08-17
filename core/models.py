"""Dataclasses mirroring the SQLite schema in state.py."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Phase(str, Enum):
    UNAUTH = "unauth"        # on the network, no valid creds
    AUTHED = "authed"        # valid domain user
    PRIVILEGED = "privileged"  # local admin somewhere / high-value account


class SecretType(str, Enum):
    PASSWORD = "password"
    NT_HASH = "nt_hash"
    AES_KEY = "aes_key"
    TICKET = "ticket"        # .ccache / kirbi
    NTLM_PAIR = "ntlm_pair"  # LM:NT


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Host:
    ip: str
    hostname: Optional[str] = None
    os: Optional[str] = None
    domain: Optional[str] = None
    is_dc: bool = False
    smb_signing: Optional[bool] = None   # None unknown, True required, False relay target
    ports: list[int] = field(default_factory=list)
    notes: str = ""


@dataclass
class Domain:
    name: str
    sid: Optional[str] = None
    functional_level: Optional[str] = None
    dc_hosts: list[str] = field(default_factory=list)


@dataclass
class ADUser:
    username: str
    domain: str
    sid: Optional[str] = None
    rid: Optional[int] = None
    enabled: bool = True
    is_admin: bool = False
    description: str = ""
    dont_require_preauth: bool = False    # AS-REP roastable
    trusted_for_delegation: bool = False  # unconstrained delegation
    spn: Optional[str] = None             # has SPN -> kerberoastable


@dataclass
class Credential:
    username: str
    domain: str
    secret: str
    secret_type: SecretType = SecretType.PASSWORD
    source: str = ""                     # module/finding that produced it
    validated: bool = False              # confirmed against the domain?
    admin_on: list[str] = field(default_factory=list)  # hosts where local admin
    notes: str = ""


@dataclass
class Share:
    host: str
    name: str
    readable: bool = False
    writable: bool = False
    comment: str = ""


@dataclass
class Finding:
    category: str                        # "adcs", "kerberos", "smb", ...
    title: str
    detail: str = ""
    severity: Severity = Severity.INFO
    source_module: str = ""
    evidence: str = ""                   # output snippet / log path
    mindmap_node: str = ""
    phase: Phase = Phase.UNAUTH


@dataclass
class Recommendation:
    title: str
    action: str
    suggested_cmd: str = ""
    tool: str = ""
    mindmap_node: str = ""
    severity: Severity = Severity.INFO
    rationale: str = ""
    unlocks: str = ""
