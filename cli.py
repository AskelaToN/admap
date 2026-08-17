"""admap command line.

    python -m admap init   --targets 10.10.10.0/24 --domain corp.local --dc 10.10.10.10
    python -m admap creds  --user bob --password 'Passw0rd!'   # or --hash <nt>
    python -m admap run discovery
    python -m admap run unauth
    python -m admap auto        # run the modules that fit the current state
    python -m admap advise      # print next-step recommendations
    python -m admap report

Global flags: --db, --loot, --dry-run, -v
"""
from __future__ import annotations

import argparse
import sys

from .advisor import advise, render
from .core.config import Config
from .core.log import get_logger, set_verbose
from .core.models import Credential, SecretType
from .core.runner import Runner
from .core.state import State
from .modules import MODULES

log = get_logger(__name__)
CONFIG_FILE = "admap.config.json"


def _load_cfg(args) -> Config:
    try:
        cfg = Config.load(CONFIG_FILE)
    except FileNotFoundError:
        cfg = Config()
    if getattr(args, "db", None):
        cfg.db_path = args.db
    if getattr(args, "loot", None):
        cfg.loot_dir = args.loot
    if getattr(args, "dry_run", False):
        cfg.dry_run = True
    return cfg


def _runner(cfg: Config) -> Runner:
    return Runner(loot_dir=cfg.loot_dir, dry_run=cfg.dry_run, timeout=cfg.timeout)


def cmd_init(args, cfg: Config, state: State) -> None:
    cfg.targets = args.targets or cfg.targets
    cfg.domain = args.domain or cfg.domain
    cfg.dc_ip = args.dc or cfg.dc_ip
    cfg.save(CONFIG_FILE)
    log.info("engagement initialised: targets=%s domain=%s dc=%s",
             cfg.targets, cfg.domain, cfg.dc_ip)


def cmd_creds(args, cfg: Config, state: State) -> None:
    cfg.username = args.user
    cfg.password = args.password
    cfg.nt_hash = args.hash
    cfg.save(CONFIG_FILE)
    state.add_credential(Credential(
        username=args.user, domain=cfg.domain or "",
        secret=args.password or args.hash or "",
        secret_type=SecretType.PASSWORD if args.password else SecretType.NT_HASH,
        source="manual", validated=False,
    ))
    log.info("stored credentials for %s (run 'admap check' to validate)", args.user)


def cmd_run(args, cfg: Config, state: State) -> None:
    mod = MODULES.get(args.module)
    if not mod:
        log.error("unknown module '%s'. available: %s", args.module,
                  ", ".join(MODULES))
        sys.exit(2)
    mod.run(cfg, state, _runner(cfg))
    print(render(state, advise(state)))


def cmd_auto(args, cfg: Config, state: State) -> None:
    runner = _runner(cfg)
    order = ["discovery", "unauth"]
    if cfg.has_creds():
        order += ["check", "authed", "bloodhound", "adcs", "delegation"]
    for name in order:
        log.info("=== module: %s ===", name)
        MODULES[name].run(cfg, state, runner)
    print(render(state, advise(state)))


def cmd_advise(args, cfg: Config, state: State) -> None:
    print(render(state, advise(state)))


def cmd_report(args, cfg: Config, state: State) -> None:
    from . import report
    md, js = report.write(state, out_prefix=args.out)
    log.info("wrote %s and %s", md, js)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="admap", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--db", help="engagement DB path")
    p.add_argument("--loot", help="loot/log directory")
    p.add_argument("--dry-run", action="store_true", help="print commands, don't run")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init", help="set targets/domain/dc")
    s.add_argument("--targets", nargs="+")
    s.add_argument("--domain")
    s.add_argument("--dc")
    s.set_defaults(func=cmd_init)

    s = sub.add_parser("creds", help="store a held credential")
    s.add_argument("--user", required=True)
    s.add_argument("--password")
    s.add_argument("--hash", help="NT hash")
    s.set_defaults(func=cmd_creds)

    s = sub.add_parser("run", help="run a single module")
    s.add_argument("module", choices=list(MODULES))
    s.set_defaults(func=cmd_run)

    s = sub.add_parser("auto", help="run modules that fit current state")
    s.set_defaults(func=cmd_auto)

    s = sub.add_parser("advise", help="print recommended next steps")
    s.set_defaults(func=cmd_advise)

    s = sub.add_parser("report", help="write markdown + json report")
    s.add_argument("--out", default="report")
    s.set_defaults(func=cmd_report)

    return p


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    set_verbose(getattr(args, "verbose", False))
    cfg = _load_cfg(args)
    state = State(cfg.db_path)
    try:
        args.func(args, cfg, state)
    finally:
        state.close()


if __name__ == "__main__":
    main()
