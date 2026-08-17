"""Delegation: findDelegation parsing + advisor rules."""
from admap.advisor import advise
from admap.core.models import Credential, Finding, Host, Phase, Severity
from admap.core.state import State
from admap.modules.delegation import parse_finddelegation

FINDDELEG = """\
Findings
AccountName  AccountType  DelegationType                      DelegationRightsTo
-----------  -----------  ----------------------------------  ------------------------------
DC01$        Computer     Unconstrained                       N/A
websvc       Person       Constrained w/ Protocol Transition  cifs/dc01.corp.local
sqlsvc       Person       Constrained                         MSSQLSvc/db.corp.local:1433
"""


def test_parse_finddelegation():
    rows = {r.account: r for r in parse_finddelegation(FINDDELEG)}
    assert set(rows) == {"DC01$", "websvc", "sqlsvc"}
    assert rows["DC01$"].is_unconstrained
    assert rows["websvc"].protocol_transition
    assert not rows["sqlsvc"].is_unconstrained
    assert rows["sqlsvc"].rights_to.startswith("MSSQLSvc/")


def test_advisor_constrained_delegation():
    s = State(":memory:")
    s.upsert_host(Host(ip="10.0.0.10", is_dc=True, ports=[88, 389, 445]))
    s.add_credential(Credential("bob", "corp", "pw", validated=True))
    s.add_finding(Finding(
        category="kerberos", title="Constrained delegation: sqlsvc",
        detail="Allowed to delegate to: MSSQLSvc/db.corp.local:1433",
        severity=Severity.HIGH,
        mindmap_node="Authed > Kerberos delegation > Constrained",
        phase=Phase.AUTHED))
    titles = [r.title for r in advise(s)]
    assert any("Constrained delegation abuse: sqlsvc" in t for t in titles)
