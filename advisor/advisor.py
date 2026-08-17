"""Run every rule against the state and rank the results."""
from __future__ import annotations

from ..core.models import Recommendation, Severity
from ..core.state import State
from .rules import ALL_RULES

_SEV_ORDER = {
    Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
    Severity.LOW: 3, Severity.INFO: 4,
}


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
