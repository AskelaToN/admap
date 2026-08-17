# admap - fat image: the orchestrator plus every tool it shells out to.
# Build:  docker build -t admap .
# Run:    docker run --rm --network host -v "$PWD":/work -w /work admap auto
#
# Design: each Python tool goes in its own isolated venv via pipx so NetExec and
# Impacket can't fight over shared dependency versions. System tools come from apt.

FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PIPX_HOME=/opt/pipx \
    PIPX_BIN_DIR=/usr/local/bin \
    PYTHONPATH=/opt \
    PATH="/usr/local/bin:${PATH}"

# System tools admap calls directly, plus build/runtime deps for the Python tools.
# NetExec pulls Rust-backed wheels (e.g. aardwolf), so rustc/cargo + pkg-config
# and the -dev headers below are required at build time.
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        ldap-utils \
        smbclient \
        krb5-user \
        dnsutils \
        git \
        curl \
        ca-certificates \
        build-essential \
        python3-dev \
        libssl-dev \
        libffi-dev \
        libkrb5-dev \
        pkg-config \
        rustc \
        cargo \
        pipx \
    && rm -rf /var/lib/apt/lists/*

# Python security tools, each isolated. --system-site-packages off by default.
RUN pipx install git+https://github.com/Pennyw0rth/NetExec.git \
    && pipx install impacket \
    && pipx install certipy-ad \
    && pipx install bloodhound

# admap expects the Kali-style "impacket-<Script>" names; PyPI/pipx installs them
# as "<Script>.py" into PIPX_BIN_DIR (/usr/local/bin above). Symlink the four
# scripts admap uses so its have() checks pass. Fails the build loudly if a
# script is missing, so a broken install can't slip through silently.
RUN set -eux; \
    for s in GetNPUsers GetUserSPNs secretsdump findDelegation; do \
        test -e "/usr/local/bin/$s.py"; \
        ln -sf "/usr/local/bin/$s.py" "/usr/local/bin/impacket-$s"; \
    done

# kerbrute: single static Go binary, grab the release.
RUN curl -fsSL -o /usr/local/bin/kerbrute \
        https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64 \
    && chmod +x /usr/local/bin/kerbrute

# admap itself (pure stdlib; the repo root IS the package, so it lives under /opt).
RUN git clone https://github.com/AskelaToN/admap.git /opt/admap

WORKDIR /work
ENTRYPOINT ["python", "-m", "admap"]
CMD ["--help"]
