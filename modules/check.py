"""Validate held credentials over SMB / WinRM without risking lockouts.

An unvalidated cred gets exactly one auth attempt, against the DC only. If it
fails we stop and never touch another host, so an account can only ever pick up
a single failed logon here. We fan out to other hosts only after the cred is
confirmed valid, and valid logons don't increment badPwdCount. LAPS/local creds
are never tested against the DC.
"""
from __future__ import annotations

from ..core.config import Config
from ..core.log import get_logger
from ..core.models import Finding, Phase, SecretType, Severity
from ..core.runner import Runner
from ..core.state import State
from . import parsers

log = get_logger(__name__)


def _flags(cred, domain) -> str:
    secret = f"-H {cred.secret}" if cred.secret_type == SecretType.NT_HASH \
        else f"-p {cred.secret}"
    base = f"-u {cred.username} {secret}"
    if domain and cred.source != "laps":
        base += f" -d {domain}"
    return base


def _is_local(cred) -> bool:
    # LAPS creds are a computer's local admin, not a domain account
    return cred.source == "laps"


def run(cfg: Config, state: State, runner: Runner) -> None:
    if not runner.have("nxc"):
        log.warning("need netexec; skipping check")
        return
    if not (state.dcs() or cfg.dc_ip):
        log.warning("no DC known; run discovery first")
        return
    dc = cfg.dc_ip or state.dcs()[0].ip
    smb_hosts = [h.ip for h in state.hosts() if 445 in h.ports] or [dc]
    winrm_hosts = [h.ip for h in state.hosts() if 5985 in h.ports]
    for cred in state.credentials():
        _check(cfg, state, runner, cred, dc, smb_hosts, winrm_hosts)


def _check(cfg, state, runner, cred, dc, smb_hosts, winrm_hosts) -> None:
    if _is_local(cred):
        return
    flags = _flags(cred, cfg.domain)

    # single validation attempt against the DC only
    probe = runner.run(f"nxc smb {dc} {flags}", label=f"check_{cred.username}")
    res = parsers.parse_nxc_auth(probe.stdout)
    r = res[0] if res else None

    if r and r.locked:
        log.warning("%s is locked out; not testing further", cred.username)
        state.add_finding(Finding(
            category="access", title=f"Account locked: {cred.username}",
            detail="Do not retry.", severity=Severity.MEDIUM,
            source_module="check", mindmap_node="Authed > Credential validation",
            phase=Phase.UNAUTH))
        return

    if not (r and r.valid):
        log.warning("%s failed on DC (single attempt); no fan-out", cred.username)
        state.add_finding(Finding(
            category="access", title=f"Credential invalid: {cred.username}",
            detail="One DC auth attempt failed; stopped here (lockout-safe).",
            severity=Severity.LOW, source_module="check",
            mindmap_node="Authed > Credential validation", phase=Phase.UNAUTH))
        return

    # valid: safe to fan out, every login below succeeds
    log.info("%s validated on the DC", cred.username)
    admin_on = set(cred.admin_on)
    if r.pwned:
        admin_on.add(dc)

    others = [h for h in smb_hosts if h != dc]
    if others:
        smb = runner.run(f"nxc smb {' '.join(others)} {flags}",
                         label=f"check_smb_{cred.username}")
        for a in parsers.parse_nxc_auth(smb.stdout):
            if a.pwned:
                admin_on.add(a.host)

    winrm_ok = []
    if winrm_hosts:
        w = runner.run(f"nxc winrm {' '.join(winrm_hosts)} {flags}",
                       label=f"check_winrm_{cred.username}")
        for a in parsers.parse_nxc_auth(w.stdout):
            if a.valid:
                winrm_ok.append(a.host)

    cred.validated = True
    cred.admin_on = sorted(admin_on)
    state.add_credential(cred)
    state.add_finding(Finding(
        category="access", title=f"Credential valid: {cred.username}",
        detail=f"Local admin on: {', '.join(sorted(admin_on)) or 'none'}",
        severity=Severity.INFO, source_module="check",
        mindmap_node="Authed > Credential validation", phase=Phase.AUTHED))
    for host in winrm_ok:
        state.add_finding(Finding(
            category="access", title=f"WinRM shell: {host}",
            detail=f"{cred.username} can log in over WinRM.",
            severity=Severity.HIGH, source_module="check",
            evidence=f"{host}|{cred.username}",
            mindmap_node="Authed > Lateral movement > WinRM", phase=Phase.AUTHED))
