"""State store + advisor integration tests (in-memory DB)."""
from admap.advisor import advise
from admap.core.models import (
    ADUser, Credential, Host, Phase, SecretType,
)
from admap.core.state import State


def _state():
    return State(":memory:")


def test_phase_progression():
    s = _state()
    assert s.current_phase() == Phase.UNAUTH
    s.add_credential(Credential("bob", "corp", "pw", validated=True))
    assert s.current_phase() == Phase.AUTHED
    s.add_credential(Credential("adm", "corp", "pw", validated=True,
                                admin_on=["10.0.0.5"]))
    assert s.current_phase() == Phase.PRIVILEGED


def test_host_upsert_is_idempotent():
    s = _state()
    s.upsert_host(Host(ip="10.0.0.1", ports=[445]))
    s.upsert_host(Host(ip="10.0.0.1", ports=[445, 88, 389], is_dc=True))
    hosts = s.hosts()
    assert len(hosts) == 1
    assert hosts[0].is_dc and set(hosts[0].ports) == {88, 389, 445}


def test_advisor_asrep_on_flagged_user():
    s = _state()
    s.upsert_host(Host(ip="10.0.0.1", is_dc=True, ports=[88, 389, 445]))
    s.upsert_user(ADUser(username="svc", domain="corp",
                         dont_require_preauth=True))
    titles = [r.title for r in advise(s)]
    assert any("AS-REP roast: svc" in t for t in titles)


def test_advisor_dcsync_when_admin_on_dc():
    s = _state()
    s.upsert_host(Host(ip="10.0.0.1", hostname="DC01", is_dc=True,
                       ports=[88, 389, 445]))
    s.add_credential(Credential("adm", "corp", "pw", validated=True,
                                admin_on=["10.0.0.1"]))
    recs = advise(s)
    assert any("DCSync" in r.title for r in recs)
    # critical findings rank first
    assert recs[0].severity.value in ("critical", "high")


def test_advisor_survives_empty_state():
    assert advise(_state()) == []
