"""Kerberos delegation detection via impacket-findDelegation.

The DelegationType column contains spaces, so we match on the known phrases
instead of splitting on whitespace. Flags unconstrained accounts on the user
record and records constrained targets as findings."""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..core.config import Config
from ..core.log import get_logger
from ..core.models import ADUser, Finding, Phase, Severity
from ..core.runner import Runner
from ..core.state import State

log = get_logger(__name__)


@dataclass
class ParsedDelegation:
    account: str
    account_type: str          # Person | Computer
    deleg_type: str
    rights_to: str = ""        # target SPN(s), or N/A for unconstrained

    @property
    def is_unconstrained(self) -> bool:
        return self.deleg_type.lower().startswith("unconstrained")

    @property
    def protocol_transition(self) -> bool:
        return "protocol transition" in self.deleg_type.lower()


_ROW = re.compile(
    r"^(?P<acct>\S+)\s+(?P<atype>Person|Computer)\s+"
    r"(?P<dtype>Unconstrained|Constrained w/ Protocol Transition|Constrained)\s+"
    r"(?P<rights>.+?)\s*$"
)


def parse_finddelegation(output: str) -> list[ParsedDelegation]:
    out: list[ParsedDelegation] = []
    for line in output.splitlines():
        m = _ROW.match(line.strip())
        if not m:
            continue
        out.append(ParsedDelegation(
            account=m.group("acct"), account_type=m.group("atype"),
            deleg_type=m.group("dtype"), rights_to=m.group("rights").strip(),
        ))
    return out


def run(cfg: Config, state: State, runner: Runner) -> None:
    if not cfg.has_creds() or not runner.have("impacket-findDelegation"):
        log.warning("need creds + impacket-findDelegation; skipping delegation")
        return
    dc = cfg.dc_ip or (state.dcs()[0].ip if state.dcs() else None)
    cred = f"{cfg.username}:{cfg.password}" if cfg.password else cfg.username
    hashflag = "" if cfg.password else f" -hashes :{cfg.nt_hash}"
    log.info("enumerating Kerberos delegation")
    res = runner.run(
        f"impacket-findDelegation {cfg.domain}/{cred}{hashflag} -dc-ip {dc}",
        label="delegation",
    )

    for d in parse_finddelegation(res.stdout):
        if d.is_unconstrained:
            state.upsert_user(ADUser(username=d.account, domain=cfg.domain or "",
                                     trusted_for_delegation=True))
            state.add_finding(Finding(
                category="kerberos", title=f"Unconstrained delegation: {d.account}",
                detail=f"{d.account_type} trusted for unconstrained delegation.",
                severity=Severity.HIGH, source_module="delegation",
                evidence=str(res.logfile),
                mindmap_node="Authed > Kerberos delegation > Unconstrained",
                phase=Phase.AUTHED,
            ))
        else:
            pt = " (protocol transition)" if d.protocol_transition else ""
            state.add_finding(Finding(
                category="kerberos",
                title=f"Constrained delegation: {d.account}",
                detail=f"Allowed to delegate to: {d.rights_to}{pt}",
                severity=Severity.HIGH, source_module="delegation",
                evidence=str(res.logfile),
                mindmap_node="Authed > Kerberos delegation > Constrained",
                phase=Phase.AUTHED,
            ))
