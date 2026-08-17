# admap - Docker build reference

admap is an enumeration **orchestrator**: it runs stdlib Python and shells out to
standard AD tooling. It does not exploit anything. This image bundles admap plus
every tool it calls so it runs self-contained (a "fat" image).

**Host OS is irrelevant.** The image is Debian-based (`python:3.12-slim`) and
ships its own complete userspace; it runs identically on an Ubuntu Docker host, a
Kali host, or anything else. The host only provides the Docker engine. There is
**no Kali dependency** here - every tool is installed explicitly (apt + pipx +
release binary), so nothing relies on Kali metapackages.

## Tools inside the image

| Tool | Why admap needs it | Source | Install method |
|------|--------------------|--------|----------------|
| Python 3.10+ | runs admap (stdlib only) | https://www.python.org | base image (`python:3.12-slim`) |
| nmap | discovery / port + service scan | https://github.com/nmap/nmap | apt: `nmap` |
| NetExec (`nxc`) | SMB null session, RID cycling, share/user enum, credential check over SMB/WinRM | https://github.com/Pennyw0rth/NetExec | pipx from git |
| Impacket | GetNPUsers (AS-REP roast), GetUserSPNs (Kerberoast), secretsdump (DCSync), findDelegation | https://github.com/fortra/impacket | pipx: `impacket` |
| kerbrute | Kerberos username enumeration (no lockout) | https://github.com/ropnop/kerbrute | release binary |
| ldap-utils (`ldapsearch`) | anonymous LDAP bind | https://www.openldap.org | apt: `ldap-utils` |
| BloodHound.py (`bloodhound-python`) | AD graph collection | https://github.com/dirkjanm/BloodHound.py | pipx: `bloodhound` |
| Certipy (`certipy`) | ADCS ESC misconfig enumeration | https://github.com/ly4k/Certipy | pipx: `certipy-ad` |
| smbclient (Samba) | advisor-suggested share loot | https://www.samba.org | apt: `smbclient` |
| admap | the orchestrator + advisor | https://github.com/AskelaToN/admap | git clone |

### Optional (admap only *prints* these as manual next steps; it never runs them)
Include only if you want the full manual workflow in the same image.

| Tool | Source | Install method |
|------|--------|----------------|
| evil-winrm | https://github.com/Hackplayers/evil-winrm | `gem install evil-winrm` (needs ruby) |
| hashcat | https://github.com/hashcat/hashcat | apt: `hashcat` (offline cracking) |

## Build

```bash
docker build -t admap .
```

Expected size: **~1.5-2.5 GB** on disk (NetExec's dependency tree is the bulk).
First build is slow (compiles/pulls the Python deps); rebuilds are layer-cached.

## Run

admap reaches a live domain and writes output files, so two flags matter:

- `--network host` - the container must reach the target AD (SMB/LDAP/Kerberos).
  Kerberos is sensitive to name resolution, so host networking is the safe default.
- `-v "$PWD":/work -w /work` - so loot, `asrep.hashes`, and the BloodHound zip
  land on the host and survive the container exiting.

```bash
# initialise an engagement (writes admap.config.json + engagement.db into $PWD)
docker run --rm --network host -v "$PWD":/work -w /work admap \
    init --targets 10.129.95.210 --domain htb.local --dc 10.129.95.210

# unauthenticated enumeration
docker run --rm --network host -v "$PWD":/work -w /work admap run unauth

# after cracking a hash offline, hand the cred back and validate (lockout-safe)
docker run --rm --network host -v "$PWD":/work -w /work admap \
    creds --user svc-alfresco --password 's3rvice'
docker run --rm --network host -v "$PWD":/work -w /work admap run check

# see recommended next steps
docker run --rm --network host -v "$PWD":/work -w /work admap advise
```

Tip: alias the long prefix so operators type `admap run unauth` etc.

```bash
alias admap='docker run --rm --network host -v "$PWD":/work -w /work admap'
```

## Gotchas to check on first build

1. **Impacket script names.** admap calls the Kali-style `impacket-GetNPUsers`
   etc. PyPI installs them as `GetNPUsers.py`. The Dockerfile symlinks the four
   admap uses and **fails the build loudly** if any is missing, so a broken
   Impacket install cannot slip through. Verify after build with
   `docker run --rm --entrypoint sh admap -c 'ls -l /usr/local/bin/impacket-*'`
   (`--entrypoint sh` is needed because the image entrypoint is `python -m admap`).
2. **NetExec + Impacket dependency conflicts.** Handled by pipx (separate venvs).
   Do not collapse them into a single `pip install`.
3. **Networking.** Without `--network host`, the container cannot reach the DC and
   every module returns empty. On non-Linux Docker hosts, host networking behaves
   differently - map/route to the target network explicitly.
4. **Output persistence.** Without the `-v ... -w /work` mount, the DB, hashes,
   and BloodHound zip stay inside the container and are lost on `--rm`.
