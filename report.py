"""Markdown + JSON report of the engagement state."""
from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from .advisor import advise
from .core.state import State


def to_markdown(state: State) -> str:
    recs = advise(state)
    L: list[str] = ["# AD Engagement Report", ""]

    L += [f"**Phase:** {state.current_phase().value}", ""]

    L += ["## Hosts", "", "| IP | Host | DC | SMB signing | Ports |",
          "|----|------|----|-----------|-------|"]
    for h in state.hosts():
        sign = "" if h.smb_signing is None else ("req" if h.smb_signing else "NOT req")
        L.append(f"| {h.ip} | {h.hostname or ''} | {'yes' if h.is_dc else ''} "
                 f"| {sign} | {','.join(map(str, h.ports))} |")

    L += ["", "## Credentials", "", "| User | Domain | Type | Valid | Admin on |",
          "|------|--------|------|-------|----------|"]
    for c in state.credentials():
        L.append(f"| {c.username} | {c.domain} | {c.secret_type.value} | "
                 f"{'yes' if c.validated else ''} | {', '.join(c.admin_on)} |")

    L += ["", "## Findings", ""]
    for f in state.findings():
        L.append(f"- **[{f.severity.value}] {f.title}** - {f.detail} "
                 f"_({f.mindmap_node})_")

    L += ["", "## Recommended next steps", ""]
    for i, r in enumerate(recs, 1):
        L += [f"{i}. **{r.title}** ({r.severity.value}) - {r.action}",
              f"   - `{r.suggested_cmd}`"]

    return "\n".join(L) + "\n"


def write(state: State, out_prefix: str = "report") -> tuple[str, str]:
    md_path = f"{out_prefix}.md"
    json_path = f"{out_prefix}.json"
    Path(md_path).write_text(to_markdown(state), encoding="utf-8")

    data = {
        "phase": state.current_phase().value,
        "hosts": [asdict(h) for h in state.hosts()],
        "users": [asdict(u) for u in state.users()],
        "credentials": [_cred_dict(c) for c in state.credentials()],
        "findings": [_finding_dict(f) for f in state.findings()],
        "recommendations": [asdict(r) for r in advise(state)],
    }
    Path(json_path).write_text(json.dumps(data, indent=2, default=str),
                               encoding="utf-8")
    return md_path, json_path


def _cred_dict(c) -> dict:
    d = asdict(c)
    d["secret_type"] = c.secret_type.value
    return d


def _finding_dict(f) -> dict:
    d = asdict(f)
    d["severity"] = f.severity.value
    d["phase"] = f.phase.value
    return d
