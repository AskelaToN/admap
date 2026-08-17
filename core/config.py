"""Engagement config: scope and the creds currently held. The DB holds
everything discovered; this stays small."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class Config:
    # scope
    targets: list[str] = field(default_factory=list)  # IPs / CIDRs / hostnames
    dc_ip: Optional[str] = None
    domain: Optional[str] = None

    # held credential (optional; drives authed/privileged modules)
    username: Optional[str] = None
    password: Optional[str] = None
    nt_hash: Optional[str] = None

    # runtime
    db_path: str = "engagement.db"
    loot_dir: str = "loot"
    dry_run: bool = False
    timeout: int = 900

    # off by default: spray can lock accounts, poison is loud
    allow_spray: bool = False
    allow_poison: bool = False

    @classmethod
    def load(cls, path: str | Path) -> "Config":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(**data)

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.__dict__, indent=2), encoding="utf-8")

    def has_creds(self) -> bool:
        return bool(self.username and (self.password or self.nt_hash))
