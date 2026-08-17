# admap

AD enumeration orchestrator with an attack-path advisor, loosely following the
Orange Cyberdefense AD mindmap.

It runs enumeration tools, parses their output into a single engagement DB, and
tells you what to do next. It does not exploit anything - the advisor prints
copy-paste commands for you to run by hand. Password spraying and LLMNR/NBT-NS
poisoning are off by default because of lockout and noise.

## Layout

```
admap/
  core/            state, models, tool runner, config, logging
    models.py      dataclasses for the SQLite schema
    state.py       engagement DB (idempotent upserts)
    runner.py      subprocess wrapper + --dry-run + PATH checks
    config.py
    log.py
  advisor/
    rules.py       one rule per mindmap branch -> Recommendations
    advisor.py     runs the rules, ranks by severity
  modules/
    parsers.py     output parsers (netexec / kerbrute / impacket / certipy)
    discovery.py   port sweep, DC id, SMB signing
    unauth.py      null SMB, RID, LDAP anon, kerbrute, AS-REP
    authed.py      BloodHound, kerberoast, GPP, LAPS, share spider
    bloodhound.py  ingest collection .zip -> admin paths, delegation, DCSync
    adcs.py        certipy ESC enum
    delegation.py  findDelegation
  report.py        markdown + json report
  cli.py
  tests/           pytest suite (parsers, state, advisor, ingest)
```

## Usage

```bash
python -m admap init --targets 10.10.10.0/24 --domain corp.local --dc 10.10.10.10
python -m admap run discovery
python -m admap run unauth
python -m admap advise

# once you have a credential
python -m admap creds --user bob --password 'Passw0rd!'
python -m admap auto
python -m admap report
```

`--dry-run` on any command prints the tool invocations instead of running them.

## Adding a branch

Write a `_r_*` function in `advisor/rules.py` and add it to `ALL_RULES`. If you
need to collect the data first, add a wrapper in `modules/` and a parser in
`modules/parsers.py`.

## Requirements

Stdlib-only Python. It shells out to nmap, netexec, impacket, kerbrute,
ldapsearch, bloodhound-python and certipy (see `requirements.txt`). Missing
tools are skipped, not fatal.
