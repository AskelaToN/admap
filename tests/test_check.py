"""Credential check: nxc auth parsing + the lockout-safe validation flow."""
from admap.advisor import advise
from admap.core.config import Config
from admap.core.models import Credential, Host, SecretType
from admap.core.runner import CmdResult
from admap.core.state import State
from admap.modules import check
from admap.modules.parsers import parse_nxc_auth


class FakeRunner:
    """Records commands, returns queued stdout, so we can assert call count."""

    def __init__(self, outputs):
        self.outputs = list(outputs)
        self.calls = []

    def have(self, tool):
        return True

    def run(self, cmd, label="cmd", timeout=None):
        self.calls.append(cmd)
        out = self.outputs.pop(0) if self.outputs else ""
        return CmdResult(cmd=cmd, returncode=0, stdout=out, stderr="", duration=0.0)


def _state(hosts):
    s = State(":memory:")
    for h in hosts:
        s.upsert_host(h)
    return s


DC = Host(ip="10.0.0.10", hostname="DC01", is_dc=True, ports=[88, 389, 445])
WS = Host(ip="10.0.0.11", hostname="WS01", ports=[445, 5985])


def test_parse_nxc_auth():
    out = (
        "SMB   10.0.0.10 445 DC01 [+] corp.local\\bob:pw\n"
        "SMB   10.0.0.11 445 WS01 [+] corp.local\\bob:pw (Pwn3d!)\n"
        "SMB   10.0.0.12 445 WS02 [-] corp.local\\bob:pw STATUS_LOGON_FAILURE\n"
    )
    res = {a.host: a for a in parse_nxc_auth(out)}
    assert res["10.0.0.10"].valid and not res["10.0.0.10"].pwned
    assert res["10.0.0.11"].pwned
    assert not res["10.0.0.12"].valid


def test_invalid_cred_makes_exactly_one_attempt():
    # the lockout guarantee: a wrong password never fans out
    s = _state([DC, WS])
    s.add_credential(Credential("bob", "corp", "wrong", validated=False))
    r = FakeRunner(["SMB 10.0.0.10 445 DC01 [-] corp.local\\bob:wrong STATUS_LOGON_FAILURE"])
    check.run(Config(domain="corp", dc_ip="10.0.0.10"), s, r)
    assert len(r.calls) == 1                 # DC probe only, no fan-out
    assert not s.credentials()[0].validated


def test_locked_account_not_retried():
    s = _state([DC, WS])
    s.add_credential(Credential("bob", "corp", "pw", validated=False))
    r = FakeRunner(["SMB 10.0.0.10 445 DC01 [-] corp.local\\bob:pw STATUS_ACCOUNT_LOCKED_OUT"])
    check.run(Config(domain="corp", dc_ip="10.0.0.10"), s, r)
    assert len(r.calls) == 1
    assert any("Account locked" in f.title for f in s.findings())


def test_valid_cred_fans_out_and_records_admin_and_winrm():
    s = _state([DC, WS])
    s.add_credential(Credential("bob", "corp", "pw", validated=False))
    r = FakeRunner([
        "SMB   10.0.0.10 445 DC01 [+] corp.local\\bob:pw",              # DC probe ok
        "SMB   10.0.0.11 445 WS01 [+] corp.local\\bob:pw (Pwn3d!)",     # admin on WS
        "WINRM 10.0.0.11 5985 WS01 [+] corp.local\\bob:pw (Pwn3d!)",    # winrm on WS
    ])
    check.run(Config(domain="corp", dc_ip="10.0.0.10"), s, r)
    cred = s.credentials()[0]
    assert cred.validated
    assert "10.0.0.11" in cred.admin_on
    titles = [f.title for f in s.findings()]
    assert any("WinRM shell: 10.0.0.11" in t for t in titles)
    # advisor surfaces the evil-winrm step
    assert any("WinRM shell on 10.0.0.11" in rec.title for rec in advise(s))


def test_local_laps_cred_never_hits_dc():
    s = _state([DC, WS])
    s.add_credential(Credential("administrator", "WS01", "lapspw",
                                secret_type=SecretType.PASSWORD, source="laps",
                                validated=True, admin_on=["WS01"]))
    r = FakeRunner([])
    check.run(Config(domain="corp", dc_ip="10.0.0.10"), s, r)
    assert len(r.calls) == 0                 # local cred is never tested vs the DC
