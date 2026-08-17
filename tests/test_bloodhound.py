"""BloodHound ingest tests: pure parsers + a full-zip integration run."""
import json
import zipfile

from admap.core.config import Config
from admap.core.models import Credential, Host
from admap.core.runner import Runner
from admap.core.state import State
from admap.modules import bloodhound as bh

# --- synthetic graph -------------------------------------------------------
# jdoe (U1) -> member of Helpdesk (G1) -> LocalAdmin on WS01
# adm  (U2) -> has DCSync on the domain
# svc  (U3) -> hasspn + dontreqpreauth + unconstrained delegation

USERS = [
    {"ObjectIdentifier": "U1", "Properties": {"name": "JDOE@CORP.LOCAL",
     "domain": "CORP.LOCAL", "enabled": True}},
    {"ObjectIdentifier": "U2", "Properties": {"name": "ADM@CORP.LOCAL",
     "domain": "CORP.LOCAL", "enabled": True, "admincount": True}},
    {"ObjectIdentifier": "U3", "Properties": {"name": "SVC@CORP.LOCAL",
     "domain": "CORP.LOCAL", "hasspn": True, "dontreqpreauth": True,
     "unconstraineddelegation": True}},
]
GROUPS = [
    {"ObjectIdentifier": "G1", "Members": [{"ObjectIdentifier": "U1",
     "ObjectType": "User"}]},
]
COMPUTERS = [
    {"ObjectIdentifier": "C1", "Properties": {"name": "WS01.CORP.LOCAL"},
     "LocalAdmins": {"Results": [{"ObjectIdentifier": "G1",
      "ObjectType": "Group"}], "Collected": True}},
    {"ObjectIdentifier": "C2", "Properties": {"name": "DC01.CORP.LOCAL"},
     "LocalAdmins": {"Results": [], "Collected": True}},
]
DOMAINS = [
    {"ObjectIdentifier": "D1", "Properties": {"name": "CORP.LOCAL"},
     "Aces": [
        {"PrincipalSID": "U2", "RightName": "GetChanges"},
        {"PrincipalSID": "U2", "RightName": "GetChangesAll"},
     ]},
]


def test_nested_group_admin_resolution():
    gm = bh.build_group_members(GROUPS)
    admin_map = bh.build_admin_map(COMPUTERS, gm)
    # jdoe is admin on WS01 *via* the Helpdesk group
    assert admin_map["U1"] == {"WS01.CORP.LOCAL"}


def test_dcsync_detection_pairs_rights():
    assert bh.dcsync_principal_sids(DOMAINS) == {"U2"}


def test_user_flags_parsed():
    users = {u.username: u for u in bh.parse_users(USERS)}
    assert users["SVC"].has_spn
    assert users["SVC"].dont_require_preauth
    assert users["SVC"].unconstrained


def _write_zip(path):
    def blob(typ, records):
        return json.dumps({"meta": {"type": typ, "count": len(records),
                                    "version": 5}, "data": records})
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("20250101_users.json", blob("users", USERS))
        z.writestr("20250101_groups.json", blob("groups", GROUPS))
        z.writestr("20250101_computers.json", blob("computers", COMPUTERS))
        z.writestr("20250101_domains.json", blob("domains", DOMAINS))


def test_full_ingest_sets_admin_on_and_dcsync(tmp_path):
    zpath = tmp_path / "bh.zip"
    _write_zip(zpath)

    s = State(":memory:")
    s.upsert_host(Host(ip="10.0.0.10", hostname="DC01.CORP.LOCAL", is_dc=True,
                       ports=[88, 389, 445]))
    s.add_credential(Credential("jdoe", "CORP.LOCAL", "pw", validated=True))
    s.add_credential(Credential("adm", "CORP.LOCAL", "pw", validated=True))

    bh.run(Config(), s, Runner(loot_dir=str(tmp_path / "loot")), zip_path=str(zpath))

    creds = {c.username: c for c in s.credentials()}
    # jdoe resolved to local admin on WS01 through the group
    assert "WS01.CORP.LOCAL" in creds["jdoe"].admin_on
    # adm's DCSync mapped the DC's IP into admin_on -> DCSync rule will fire
    assert "10.0.0.10" in creds["adm"].admin_on

    # user flags flowed into state
    svc = next(u for u in s.users() if u.username == "SVC")
    assert svc.dont_require_preauth and svc.spn == "(kerberoastable)"

    # findings recorded
    titles = [f.title for f in s.findings()]
    assert any("DCSync rights: adm" in t for t in titles)
    assert any("Unconstrained delegation" in t for t in titles)
