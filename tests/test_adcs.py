"""ADCS: Certipy JSON parsing + advisor ESC playbook."""
from admap.advisor import advise
from admap.core.models import Credential, Finding, Host, Phase, Severity
from admap.core.state import State
from admap.modules.adcs import parse_certipy_json

CERTIPY = {
    "Certificate Authorities": {
        "0": {
            "CA Name": "CORP-CA",
            "DNS Name": "ca.corp.local",
            "[!] Vulnerabilities": {
                "ESC8": "Web Enrollment is enabled and Request Disposition is Issue",
            },
        }
    },
    "Certificate Templates": {
        "0": {
            "Template Name": "UserAuth",
            "Enabled": True,
            "[!] Vulnerabilities": {
                "ESC1": "Enrollee supplies subject and template allows client auth",
            },
        },
        "1": {
            "Template Name": "Machine",   # no vulnerabilities key -> skipped
            "Enabled": True,
        },
    },
}


def test_parse_certipy_json():
    parsed = parse_certipy_json(CERTIPY)
    by_esc = {p.esc: p for p in parsed}
    assert set(by_esc) == {"ESC1", "ESC8"}
    assert by_esc["ESC1"].name == "UserAuth" and by_esc["ESC1"].kind == "template"
    assert by_esc["ESC8"].name == "CORP-CA" and by_esc["ESC8"].kind == "ca"


def _state_with_adcs():
    s = State(":memory:")
    s.upsert_host(Host(ip="10.0.0.10", is_dc=True, ports=[88, 389, 445]))
    s.add_credential(Credential("bob", "corp", "pw", validated=True))
    s.add_finding(Finding(category="adcs", title="ADCS ESC1: UserAuth",
                          detail="...", severity=Severity.HIGH,
                          mindmap_node="Authed > ADCS > ESC1", phase=Phase.AUTHED))
    s.add_finding(Finding(category="adcs", title="ADCS ESC8: CORP-CA",
                          detail="...", severity=Severity.HIGH,
                          mindmap_node="Authed > ADCS > ESC8", phase=Phase.AUTHED))
    return s


def test_advisor_emits_per_esc_playbook():
    recs = advise(_state_with_adcs())
    titles = [r.title for r in recs]
    assert any("Abuse ESC1 on 'UserAuth'" in t for t in titles)
    assert any("Abuse ESC8 on 'CORP-CA'" in t for t in titles)

    esc1 = next(r for r in recs if "ESC1" in r.title)
    # placeholders for held creds are preserved for copy-paste; template filled
    assert "-template UserAuth" in esc1.suggested_cmd
    assert "{domain}" in esc1.suggested_cmd
    assert esc1.severity == Severity.CRITICAL

    # generic enumeration prompt must NOT appear once findings exist
    assert not any("Enumerate ADCS for ESC misconfigs" in t for t in titles)
