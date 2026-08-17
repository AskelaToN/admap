"""Parser tests against captured tool output (no live DC needed)."""
from admap.modules import parsers

# --- captured samples ------------------------------------------------------

NXC_RID = """\
SMB    10.10.10.10   445   DC01   [*] Windows Server 2019 Build 17763 (name:DC01) (domain:corp.local)
SMB    10.10.10.10   445   DC01   498: CORP\\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB    10.10.10.10   445   DC01   500: CORP\\Administrator (SidTypeUser)
SMB    10.10.10.10   445   DC01   501: CORP\\Guest (SidTypeUser)
SMB    10.10.10.10   445   DC01   1000: CORP\\DC01$ (SidTypeUser)
SMB    10.10.10.10   445   DC01   1103: CORP\\jdoe (SidTypeUser)
"""

NXC_USERS = """\
SMB    10.10.10.10   445   DC01   [+] corp.local\\guest:
SMB    10.10.10.10   445   DC01   -Username-        -Last PW Set-       -BadPW- -Description-
SMB    10.10.10.10   445   DC01   Administrator     2024-01-01 00:00:00 0       Built-in account for administering
SMB    10.10.10.10   445   DC01   jdoe              2024-02-02 00:00:00 0       Regular user
"""

NXC_SHARES = """\
SMB    10.10.10.10   445   DC01   Share           Permissions     Remark
SMB    10.10.10.10   445   DC01   -----           -----------     ------
SMB    10.10.10.10   445   DC01   ADMIN$                          Remote Admin
SMB    10.10.10.10   445   DC01   NETLOGON        READ            Logon server share
SMB    10.10.10.10   445   DC01   Users           READ,WRITE
"""

KERBRUTE = """\
2024/01/01 12:00:00 >  [+] VALID USERNAME:  jdoe@corp.local
2024/01/01 12:00:01 >  [+] VALID USERNAME:  admin@corp.local
2024/01/01 12:00:02 >  Done! Tested 100 usernames
"""

ASREP = """\
[*] Getting TGT for jdoe
$krb5asrep$23$jdoe@CORP.LOCAL:abcd1234$deadbeef
"""

SPN = """\
ServicePrincipalName          Name       MemberOf   PasswordLastSet
----------------------------  ---------  ---------  ------------------
MSSQLSvc/db.corp.local:1433   sqlsvc                2024-01-01
HTTP/web.corp.local           websvc                2024-01-01
"""


def test_rid_brute():
    users, domain = parsers.parse_nxc_rid_brute(NXC_RID)
    names = {u.username for u in users}
    assert domain == "CORP"
    assert "Administrator" in names and "jdoe" in names
    assert "DC01$" not in names  # machine accounts excluded


def test_users_table():
    users = parsers.parse_nxc_users(NXC_USERS)
    names = {u.username for u in users}
    assert names == {"Administrator", "jdoe"}
    admin = next(u for u in users if u.username == "Administrator")
    assert "Built-in" in admin.description


def test_shares():
    shares = {s.name: s for s in parsers.parse_nxc_shares(NXC_SHARES)}
    assert shares["NETLOGON"].readable and not shares["NETLOGON"].writable
    assert shares["Users"].readable and shares["Users"].writable
    assert not shares["ADMIN$"].readable


def test_kerbrute():
    assert parsers.parse_kerbrute_userenum(KERBRUTE) == ["jdoe", "admin"]


def test_asrep():
    hashes = parsers.parse_asrep_hashes(ASREP)
    assert len(hashes) == 1 and hashes[0].username == "jdoe"


def test_spn():
    assert parsers.parse_spn_users(SPN) == ["sqlsvc", "websvc"]
