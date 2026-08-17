"""ADCS enumeration. Runs certipy in find mode and records one finding per
vulnerable (ESC, template). Doesn't request or forge certs - the abuse steps
come from the advisor."""
from __future__ import annotations

import glob
import json
import os
import re
from dataclasses import dataclass

from ..core.config import Config
from ..core.log import get_logger
from ..core.models import Finding, Phase, Severity
from ..core.runner import Runner
from ..core.state import State

log = get_logger(__name__)


@dataclass
class ParsedAdcs:
    esc: str
    name: str            # template or CA name
    description: str = ""
    kind: str = "template"   # "template" | "ca"


def _iter_records(section) -> list[dict]:
    # certipy sections are either {'0': {...}} or a list
    if isinstance(section, dict):
        return [v for v in section.values() if isinstance(v, dict)]
    if isinstance(section, list):
        return [v for v in section if isinstance(v, dict)]
    return []


def _vulns(record: dict) -> dict[str, str]:
    for k, v in record.items():
        if "vulnerabilit" in k.lower() and isinstance(v, dict):
            return {esc: (d if isinstance(d, str) else " ".join(map(str, d)))
                    for esc, d in v.items()}
    return {}


def parse_certipy_json(data: dict) -> list[ParsedAdcs]:
    results: list[ParsedAdcs] = []
    for t in _iter_records(data.get("Certificate Templates", {})):
        name = t.get("Template Name") or t.get("name") or "?"
        for esc, desc in _vulns(t).items():
            results.append(ParsedAdcs(esc=esc.strip(), name=name,
                                      description=desc, kind="template"))
    for c in _iter_records(data.get("Certificate Authorities", {})):
        name = c.get("CA Name") or c.get("name") or "?"
        for esc, desc in _vulns(c).items():
            results.append(ParsedAdcs(esc=esc.strip(), name=name,
                                      description=desc, kind="ca"))
    return results


def _find_output_json(prefix: str, search_dirs: list[str]) -> str | None:
    patterns = [f"{prefix}*Certipy*.json", f"{prefix}*.json"]
    cands: list[str] = []
    for d in search_dirs:
        for pat in patterns:
            cands.extend(glob.glob(os.path.join(d, pat)))
    cands = [c for c in cands if os.path.isfile(c)]
    return max(cands, key=os.path.getmtime) if cands else None


def run(cfg: Config, state: State, runner: Runner) -> None:
    if not cfg.has_creds() or not runner.have("certipy"):
        log.warning("need creds + certipy; skipping adcs")
        return
    dc = cfg.dc_ip or (state.dcs()[0].ip if state.dcs() else None)
    secret = f"-p {cfg.password}" if cfg.password else f"-hashes :{cfg.nt_hash}"
    log.info("enumerating ADCS (vulnerable templates only)")
    runner.run(
        f"certipy find -u {cfg.username}@{cfg.domain} {secret} -dc-ip {dc} "
        "-vulnerable -json -output adcs", label="certipy",
    )

    jpath = _find_output_json("adcs", [".", cfg.loot_dir])
    if not jpath:
        log.warning("certipy JSON output not found; nothing to parse")
        return
    try:
        data = json.loads(open(jpath, encoding="utf-8").read())
    except Exception as e:
        log.error("could not read certipy json %s: %s", jpath, e)
        return

    findings = parse_certipy_json(data)
    for r in findings:
        esc = r.esc if re.match(r"ESC\d+", r.esc) else f"ESC({r.esc})"
        state.add_finding(Finding(
            category="adcs", title=f"ADCS {esc}: {r.name}",
            detail=r.description or f"{r.kind} vulnerable to {esc}",
            severity=Severity.HIGH, source_module="adcs",
            evidence=jpath,
            mindmap_node=f"Authed > ADCS > {esc}", phase=Phase.AUTHED,
        ))
    log.info("recorded %d ADCS vulnerability finding(s)", len(findings))
