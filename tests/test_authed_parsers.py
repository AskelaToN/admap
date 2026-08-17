"""GPP + LAPS parser tests."""
from admap.modules import parsers

GPP = """\
SMB   10.10.10.10  445  DC01  [*] Windows Server 2019
SMB   10.10.10.10  445  DC01  [+] Found credentials in SYSVOL\\...\\Groups.xml
SMB   10.10.10.10  445  DC01  Usernames: ['svc_backup', 'localadmin']
SMB   10.10.10.10  445  DC01  Passwords: ['Backup2024!', 'L0cal!']
"""

GPP_AUTOLOGIN = """\
SMB   10.10.10.10  445  DC01  [+] Found autologin credentials
SMB   10.10.10.10  445  DC01  Usernames: ['autopilot']
SMB   10.10.10.10  445  DC01  Passwords: ['Auto123']
SMB   10.10.10.10  445  DC01  Domains: ['CORP']
"""

LAPS = """\
SMB   10.10.10.20  445  WS01  [+] corp.local\\bob:pw (Pwn3d!)
SMB   10.10.10.20  445  WS01  Computer: WS01$   Password: aB3!xY9zLapsPw
"""


def test_gpp_index_aligned():
    creds = parsers.parse_gpp(GPP)
    assert [(c.username, c.password) for c in creds] == [
        ("svc_backup", "Backup2024!"),
        ("localadmin", "L0cal!"),
    ]


def test_gpp_autologin_with_domain():
    creds = parsers.parse_gpp(GPP_AUTOLOGIN)
    assert len(creds) == 1
    assert creds[0].username == "autopilot" and creds[0].domain == "CORP"


def test_laps():
    pairs = parsers.parse_laps(LAPS)
    assert pairs == [("WS01", "aB3!xY9zLapsPw")]
