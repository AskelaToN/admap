"""Advisor fills {dc}/{domain}/{user}/{pw}/{targets} from state into commands."""
from admap.advisor import advise
from admap.core.models import ADUser, Credential, Host
from admap.core.state import State


def _state():
    s = State(":memory:")
    s.upsert_host(Host(ip="10.0.0.10", hostname="DC01", is_dc=True,
                       domain="corp.local", ports=[88, 389, 445]))
    return s


def test_unauth_cmds_have_real_dc_and_domain():
    s = _state()
    s.upsert_user(ADUser("bob", "corp.local", dont_require_preauth=True))
    cmds = " ".join(r.suggested_cmd for r in advise(s))
    assert "10.0.0.10" in cmds          # {dc} filled
    assert "corp.local" in cmds         # {domain} filled
    assert "{dc}" not in cmds           # nothing left as a template
    assert "{domain}" not in cmds


def test_authed_cmds_have_user_and_pw():
    s = _state()
    s.add_credential(Credential("bob", "corp.local", "s3cret", validated=True))
    recs = advise(s)
    bh = next(r for r in recs if r.title == "Collect BloodHound data")
    assert "-u bob" in bh.suggested_cmd
    assert "-p s3cret" in bh.suggested_cmd
    assert "{user}" not in bh.suggested_cmd and "{pw}" not in bh.suggested_cmd


def test_unknown_placeholder_stays_a_template():
    # no creds held: {user}/{pw} have no value, so they stay visible as templates
    s = _state()
    s.upsert_user(ADUser("bob", "corp.local"))
    recs = advise(s)
    spray = next((r for r in recs if "spray" in r.title.lower()), None)
    assert spray is not None
    assert "{pw}" in spray.suggested_cmd   # left as a template, not blanked out
