"""Share-spider triage: file classification, JSON parse, advisor loot rule."""
from admap.advisor import advise
from admap.core.models import Credential, Finding, Host, Phase, Severity
from admap.core.state import State
from admap.modules.parsers import classify_file, parse_spider_json

SPIDER = {
    "SYSVOL": {
        "corp.local/Policies/{GUID}/Groups.xml": {"size": "1.2 KB"},
        "corp.local/scripts/logon.bat": {"size": "300 B"},
    },
    "Backups": {
        "vault.kdbx": {"size": "8 KB"},
        "notes/readme.md": {"size": "1 KB"},          # not interesting
    },
}


def test_classify_high_and_medium():
    assert classify_file("x/Groups.xml")[0] == "high"      # name match
    assert classify_file("x/vault.kdbx")[0] == "high"      # extension
    assert classify_file("x/logon.bat")[0] == "medium"
    assert classify_file("x/readme.md") is None


def test_parse_spider_json():
    hits = parse_spider_json(SPIDER)
    by_path = {h.path.rsplit("/", 1)[-1]: h for h in hits}
    assert "readme.md" not in by_path
    assert by_path["Groups.xml"].level == "high"
    assert by_path["vault.kdbx"].share == "Backups"
    assert by_path["logon.bat"].level == "medium"


def test_advisor_loot_rule_for_high_signal():
    s = State(":memory:")
    s.upsert_host(Host(ip="10.0.0.10", is_dc=True, ports=[88, 389, 445]))
    s.add_credential(Credential("bob", "corp", "pw", validated=True))
    s.add_finding(Finding(
        category="loot",
        title="Sensitive file: \\\\10.0.0.20\\Backups\\vault.kdbx",
        detail="high-value extension: .kdbx (8 KB)",
        severity=Severity.HIGH, source_module="authed",
        evidence="10.0.0.20|Backups|vault.kdbx",
        mindmap_node="Authed > Shares > Sensitive files", phase=Phase.AUTHED))
    rec = next(r for r in advise(s) if "vault.kdbx" in r.title)
    assert "smbclient //10.0.0.20/Backups" in rec.suggested_cmd
    assert 'get "vault.kdbx"' in rec.suggested_cmd
