"""Host/port sweep, DC identification, SMB signing check."""
from __future__ import annotations

import re

from ..core.config import Config
from ..core.log import get_logger
from ..core.models import Finding, Host, Phase, Severity
from ..core.runner import Runner
from ..core.state import State

log = get_logger(__name__)

# AD-relevant ports only, keeps the scan quick
AD_PORTS = "53,88,135,139,389,445,464,636,3268,3269,5985,9389"


def run(cfg: Config, state: State, runner: Runner) -> None:
    targets = " ".join(cfg.targets)
    if not targets:
        log.warning("no targets configured; skipping discovery")
        return

    log.info("scanning AD ports on %s", targets)
    res = runner.run(
        f"nmap -Pn -p {AD_PORTS} --open -oG - {targets}", label="nmap_ad"
    )
    _parse_nmap_grepable(res.stdout, state)

    # kerberos + ldap open -> DC
    for h in state.hosts():
        if 88 in h.ports and 389 in h.ports:
            h.is_dc = True
            state.upsert_host(h)
            state.add_finding(Finding(
                category="recon", title=f"Domain Controller: {h.ip}",
                detail="Kerberos + LDAP open.", severity=Severity.INFO,
                source_module="discovery",
                mindmap_node="Recon > Identify DCs", phase=Phase.UNAUTH,
            ))

    if runner.have("nxc") and state.hosts():
        smb_hosts = " ".join(h.ip for h in state.hosts() if 445 in h.ports)
        if smb_hosts:
            sres = runner.run(f"nxc smb {smb_hosts} --gen-relay-list /dev/null",
                              label="smb_signing")
            _parse_smb_signing(sres.stdout, state)


def _parse_nmap_grepable(out: str, state: State) -> None:
    for line in out.splitlines():
        m = re.match(r"Host:\s+(\S+)\s+\((.*?)\)", line)
        if not m or "Ports:" not in line:
            continue
        ip = m.group(1)
        hostname = m.group(2) or None
        ports = [int(p) for p in re.findall(r"(\d+)/open", line)]
        state.upsert_host(Host(ip=ip, hostname=hostname, ports=ports))


def _parse_smb_signing(out: str, state: State) -> None:
    # nxc prints signing:False for relay-able hosts
    for line in out.splitlines():
        m = re.search(r"(\d+\.\d+\.\d+\.\d+).*signing:(True|False)", line)
        if not m:
            continue
        ip, signing = m.group(1), m.group(2) == "True"
        for h in state.hosts():
            if h.ip == ip:
                h.smb_signing = signing
                state.upsert_host(h)
                if not signing:
                    state.add_finding(Finding(
                        category="smb", title=f"SMB signing not required: {ip}",
                        detail="Potential NTLM relay target.",
                        severity=Severity.MEDIUM, source_module="discovery",
                        mindmap_node="Recon > SMB signing / relay targets",
                        phase=Phase.UNAUTH,
                    ))
