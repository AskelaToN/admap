"""Logged subprocess wrapper with a global dry-run switch.

Modules build commands and run them through here; output is saved under the
loot dir. The advisor never calls run() - it only prints suggested commands.
"""
from __future__ import annotations

import shlex
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .log import get_logger

log = get_logger(__name__)


@dataclass
class CmdResult:
    cmd: str
    returncode: int
    stdout: str
    stderr: str
    duration: float
    logfile: Optional[str] = None


class Runner:
    def __init__(self, loot_dir: str | Path = "loot", dry_run: bool = False,
                 timeout: int = 900) -> None:
        self.loot_dir = Path(loot_dir)
        self.loot_dir.mkdir(parents=True, exist_ok=True)
        self.dry_run = dry_run
        self.timeout = timeout
        self._counter = 0

    def run(self, cmd: str | list[str], label: str = "cmd",
            timeout: Optional[int] = None) -> CmdResult:
        cmd_str = cmd if isinstance(cmd, str) else " ".join(shlex.quote(c) for c in cmd)
        argv = shlex.split(cmd_str) if isinstance(cmd, str) else cmd

        if self.dry_run:
            log.info("[dry-run] %s", cmd_str)
            return CmdResult(cmd=cmd_str, returncode=0, stdout="", stderr="",
                             duration=0.0, logfile=None)

        self._counter += 1
        logfile = self.loot_dir / f"{self._counter:03d}_{label}.log"
        log.info("run: %s", cmd_str)
        start = time.monotonic()
        try:
            proc = subprocess.run(
                argv, capture_output=True, text=True,
                timeout=timeout or self.timeout,
            )
            out, err, rc = proc.stdout, proc.stderr, proc.returncode
        except FileNotFoundError:
            msg = f"tool not found: {argv[0]}"
            log.error(msg)
            return CmdResult(cmd=cmd_str, returncode=127, stdout="", stderr=msg,
                             duration=0.0)
        except subprocess.TimeoutExpired:
            msg = f"timeout after {timeout or self.timeout}s"
            log.warning(msg)
            return CmdResult(cmd=cmd_str, returncode=124, stdout="", stderr=msg,
                             duration=float(timeout or self.timeout))

        dur = time.monotonic() - start
        logfile.write_text(
            f"$ {cmd_str}\n\n=== STDOUT ===\n{out}\n=== STDERR ===\n{err}\n",
            encoding="utf-8",
        )
        return CmdResult(cmd=cmd_str, returncode=rc, stdout=out, stderr=err,
                         duration=dur, logfile=str(logfile))

    def have(self, tool: str) -> bool:
        from shutil import which
        return which(tool) is not None
