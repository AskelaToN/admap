"""Run every rule against the state and rank the results."""
from __future__ import annotations

from ..core.models import Recommendation, Severity
from ..core.state import State
from .rules import ALL_RULES

_SEV_ORDER = {
    Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
    Severity.LOW: 3, Severity.INFO: 4,
}


def _placeholders(state: State) -> dict[str, str]:
    """Real values for {dc}/{domain}/{targets}/{user}/{pw}, when state has them."""
    vals: dict[str, str] = {}

    dcs = state.dcs()
    if dcs:
        vals["{dc}"] = dcs[0].ip

    hosts = state.hosts()
    if hosts:
        vals["{targets}"] = " ".join(h.ip for h in hosts)

    domain = next((d.name for d in state.domains()), None)
    if not domain:
        domain = next((h.domain for h in hosts if h.domain), None)
    if not domain:
        domain = next((c.domain for c in state.credentials() if c.domain), None)
    if not domain:
        domain = next((u.domain for u in state.users() if u.domain), None)
    if domain:
        vals["{domain}"] = domain

    # prefer a validated cred; a password fills {pw}, a hash fills {hash}
    creds = state.credentials(validated_only=True) or state.credentials()
    if creds:
        c = creds[0]
        vals["{user}"] = c.username
        vals["{pw}"] = c.secret
    return vals


def _fill(cmd: str, vals: dict[str, str]) -> str:
    for token, value in vals.items():
        cmd = cmd.replace(token, value)
    return cmd


def advise(state: State) -> list[Recommendation]:
    recs: list[Recommendation] = []
    seen: set[str] = set()
    for rule in ALL_RULES:
        try:
            for rec in rule.check(state):
                key = (rec.title, rec.mindmap_node)
                if key in seen:
                    continue
                seen.add(str(key))
                recs.append(rec)
        except Exception:  # one broken rule shouldn't kill the rest
            continue
    recs.sort(key=lambda r: _SEV_ORDER.get(r.severity, 9))
    vals = _placeholders(state)
    for rec in recs:
        rec.suggested_cmd = _fill(rec.suggested_cmd, vals)
    return recs


def render(state: State, recs: list[Recommendation]) -> str:
    phase = state.current_phase()
    lines = [
        "",
        "=" * 70,
        f"  ADMAP ADVISOR  -  current phase: {phase.value.upper()}",
        f"  hosts={len(state.hosts())}  users={len(state.users())}  "
        f"creds={len(state.credentials(validated_only=True))}  "
        f"findings={len(state.findings())}",
        "=" * 70,
    ]
    if not recs:
        lines.append("\n  No recommendations yet. Run some enumeration modules first.\n")
        return "\n".join(lines)

    icon = {Severity.CRITICAL: "!!", Severity.HIGH: "! ", Severity.MEDIUM: "* ",
            Severity.LOW: "- ", Severity.INFO: "  "}
    for i, r in enumerate(recs, 1):
        lines += [
            "",
            f"[{i}] {icon.get(r.severity, '  ')}{r.title}   ({r.severity.value})",
            f"     path : {r.mindmap_node}",
            f"     why  : {r.rationale}",
            f"     do   : {r.action}",
            f"     cmd  : {r.suggested_cmd}",
            f"     gets : {r.unlocks}",
        ]
    lines.append("")
    return "\n".join(lines)
