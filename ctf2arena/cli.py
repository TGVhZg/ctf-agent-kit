"""Command line entry point: ``python -m ctf2arena <command>``.

The CLI is the thin shell over the library. Two conventions worth knowing:

* credentials are read from ``CTF2_TOKEN`` only - there is no ``--token`` flag, on purpose,
  because flags leak through shell history and process listings;
* dangerous operations (``submit``, ``env start``) require an explicit ``--yes`` even
  though the API has its own ``confirmation`` field, so that a copy-pasted command cannot
  spend an attempt.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .catalog import Catalog
from .errors import Ctf2Error, PolicyViolation
from .session import AgentSession


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ctf2arena",
        description="Policy-guarded client for the CTF2 Agent Arena.",
    )
    parser.add_argument("--version", action="version", version=f"ctf2arena {__version__}")
    parser.add_argument("--trace", action="store_true", help="log requests (secrets redacted)")
    parser.add_argument(
        "--competition",
        action="store_true",
        help="allow competition operations (owner must have enabled competitions)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    ops = sub.add_parser("ops", help="list catalog operations")
    ops.add_argument("--agent-only", action="store_true")
    ops.add_argument("--filter", default="", help="substring on operation_id")
    ops.add_argument("--json", action="store_true")

    sub.add_parser("whoami", help="Agent identity, results, quotas")

    nxt = sub.add_parser("next", help="recommended unsolved challenges")
    nxt.add_argument("--limit", type=int, default=10)
    nxt.add_argument("--category", default=None)
    nxt.add_argument("--difficulty", default=None)
    nxt.add_argument("--source", default="all", choices=["all", "practice", "competition"])

    sub.add_parser("grounds", help="list practice grounds")

    ch = sub.add_parser("challenges", help="list challenges in a practice ground")
    ch.add_argument("ground_id")
    ch.add_argument("--category", default=None)
    ch.add_argument("--difficulty", default=None)
    ch.add_argument("--all", action="store_true", help="include already-solved")

    rd = sub.add_parser("read", help="read a challenge statement + skill recommendation")
    rd.add_argument("ground_id")
    rd.add_argument("challenge_id")
    rd.add_argument("--json", action="store_true")

    fe = sub.add_parser("fetch", help="download an attachment (signed URL, 5 min)")
    fe.add_argument("ground_id")
    fe.add_argument("challenge_id")
    fe.add_argument("file_id")
    fe.add_argument("--out", default="plays")
    fe.add_argument("--name", default=None)

    env = sub.add_parser("env", help="manage the challenge environment")
    env.add_argument("action", choices=["start", "status", "wait", "extend", "destroy"])
    env.add_argument("ground_id")
    env.add_argument("challenge_id")
    env.add_argument("--yes", action="store_true", help="required for start")

    sb = sub.add_parser("submit", help="submit a confirmed flag")
    sb.add_argument("ground_id")
    sb.add_argument("challenge_id")
    sb.add_argument("flag")
    sb.add_argument("--sub-flag-id", default=None)
    sb.add_argument("--yes", action="store_true", help="confirm this exact flag")

    nt = sub.add_parser("note", help="record a replay note")
    nt.add_argument("challenge_id")
    nt.add_argument("kind", choices=["plan", "finding", "result"])
    nt.add_argument("content", nargs="+")

    tr = sub.add_parser("triage", help="recommend skills without touching the network")
    tr.add_argument("--category", default=None)
    tr.add_argument("--text", default="", help="title/description signals")

    wr = sub.add_parser("writeup", help="render a writeup from a JSON record")
    wr.add_argument("json_path")
    wr.add_argument("--out", default="writeups")

    rt = sub.add_parser("retro", help="aggregate the attempt ledger")
    rt.add_argument("--memory", default="memory")

    at = sub.add_parser("attempt", help="append an attempt to the ledger")
    at.add_argument("--id", dest="challenge_id", required=True)
    at.add_argument("--name", default="")
    at.add_argument("--category", default="")
    at.add_argument("--difficulty", default="")
    at.add_argument("--result", default="failed",
                    choices=["solved", "failed", "partial", "abandoned"])
    at.add_argument("--minutes", type=float, default=None)
    at.add_argument("--blocker", default="")
    at.add_argument("--technique", default="")
    at.add_argument("--route", default="", help="comma-separated leading skills")
    at.add_argument("--memory", default="memory")

    return parser


def _session(args) -> AgentSession:
    from .client import Client
    from .policy import Guard

    trace = (lambda line: print(f"[trace] {line}", file=sys.stderr)) if args.trace else None
    client = Client(guard=Guard(allow_competition=args.competition), trace=trace)
    return AgentSession(client)


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        return _dispatch(args)
    except PolicyViolation as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    except Ctf2Error as exc:
        print(f"error: {exc}", file=sys.stderr)
        if exc.code == "missing_credential":
            print(
                "hint: export CTF2_TOKEN to an Agent token from the CTF2 Agent console.",
                file=sys.stderr,
            )
        return 1
    except KeyboardInterrupt:
        return 130


def _dispatch(args) -> int:
    command = args.command

    if command == "triage":
        from .triage import recommend

        rec = recommend(args.category, args.text)
        print(rec)
        for reason in rec.reasons:
            print(f"  {reason}")
        return 0

    if command == "ops":
        catalog = Catalog.load()
        rows = [op for op in catalog if not args.agent_only or op.is_agent_only]
        if args.filter:
            rows = [op for op in rows if args.filter in op.operation_id]
        if args.json:
            print(json.dumps(
                [
                    {
                        "operation_id": op.operation_id,
                        "method": op.method,
                        "path": op.path,
                        "scope": op.scope,
                        "risk_level": op.risk_level,
                        "idempotency": op.idempotency,
                        "agent_only": op.is_agent_only,
                    }
                    for op in rows
                ],
                indent=2,
                ensure_ascii=False,
            ))
        else:
            for op in rows:
                marker = "*" if op.is_agent_only else " "
                print(f"{marker} {op.method:6s} {op.risk_level:6s} {op.operation_id}")
            print(f"\n{len(rows)} operation(s); * = Agent credentials only")
        return 0

    if command == "writeup":
        from .writeup import Step, Writeup

        data = json.loads(Path(args.json_path).read_text(encoding="utf-8"))
        steps = [Step(**s) for s in data.pop("steps", [])]
        writeup = Writeup(steps=steps, **data)
        path = writeup.save(args.out)
        print(f"wrote {path}")
        return 0

    if command == "retro":
        from .evolution import Ledger, build_retro

        attempts = Ledger(args.memory).load()
        print(build_retro(attempts).render())
        return 0

    if command == "attempt":
        from .evolution import Attempt, Ledger

        route = [part.strip() for part in args.route.split(",") if part.strip()]
        attempt = Attempt(
            challenge_id=args.challenge_id,
            challenge_name=args.name,
            category=args.category,
            difficulty=args.difficulty,
            result=args.result,
            minutes=args.minutes,
            blocker=args.blocker,
            technique=args.technique,
            route=route,
        )
        print(f"recorded in {Ledger(args.memory).append(attempt)}")
        return 0

    # ---- everything below needs a credential -------------------------------
    session = _session(args)
    client = session.client

    if command == "whoami":
        _print(session.whoami())
        return 0

    if command == "next":
        for challenge in session.next_challenges(
            limit=args.limit,
            category=args.category,
            difficulty=args.difficulty,
            source=args.source,
        ):
            print(f"- {challenge}")
        return 0

    if command == "grounds":
        for ground in session.practice_grounds():
            print(f"- {ground.get('name')}  id={ground.get('id')}")
        return 0

    if command == "challenges":
        for challenge in session.practice_challenges(
            args.ground_id,
            category=args.category,
            difficulty=args.difficulty,
            unsolved_only=not args.all,
        ):
            print(f"- {challenge}")
        return 0

    if command == "read":
        detail = session.get_challenge(args.ground_id, args.challenge_id)
        if args.json:
            _print(detail)
            return 0
        _print(detail)
        _print_triage(detail)
        return 0

    if command == "fetch":
        path = session.fetch_attachment(
            args.ground_id, args.challenge_id, args.file_id, args.out, filename=args.name
        )
        print(f"saved {path} ({path.stat().st_size} bytes)")
        return 0

    if command == "env":
        if args.action == "start":
            if not args.yes:
                print("refusing to start an environment without --yes", file=sys.stderr)
                return 2
            print(json.dumps(session.start_environment(args.ground_id, args.challenge_id),
                             indent=2, ensure_ascii=False))
        elif args.action == "status":
            state = session.environment(args.ground_id, args.challenge_id)
            print(json.dumps(state, indent=2, ensure_ascii=False))
            for url in AgentSession.access_urls(state):
                print(f"access: {url}")
        elif args.action == "wait":
            state = session.wait_ready(args.ground_id, args.challenge_id)
            for url in AgentSession.access_urls(state):
                print(f"access: {url}")
        elif args.action == "extend":
            print(json.dumps(session.extend_environment(args.ground_id, args.challenge_id),
                             indent=2, ensure_ascii=False))
        else:
            print(json.dumps(session.destroy_environment(args.ground_id, args.challenge_id),
                             indent=2, ensure_ascii=False))
        return 0

    if command == "submit":
        if not args.yes:
            print(
                "refusing to submit without --yes; re-run with the exact confirmed flag.",
                file=sys.stderr,
            )
            return 2
        result = session.submit(
            args.ground_id,
            args.challenge_id,
            args.flag,
            confirmation=True,
            sub_flag_id=args.sub_flag_id,
        )
        print(json.dumps(result, indent=2, ensure_ascii=False))
        print(f"stats: {client.stats}")
        return 0

    if command == "note":
        print(json.dumps(session.note(args.challenge_id, args.kind, " ".join(args.content)),
                         indent=2, ensure_ascii=False))
        return 0

    print(f"unhandled command {command!r}", file=sys.stderr)
    return 2


def _print(value) -> None:
    if isinstance(value, (dict, list)):
        print(json.dumps(value, indent=2, ensure_ascii=False))
    else:
        print(value)


def _print_triage(detail: dict) -> None:
    from .triage import recommend

    text = " ".join(
        str(detail.get(key) or "")
        for key in ("name", "title", "description", "category", "difficulty")
    )
    rec = recommend(detail.get("category"), text)
    print("\n-- suggested skills --")
    print(f"  {rec}")
    for reason in rec.reasons:
        print(f"  {reason}")
    files = detail.get("files") or []
    if files:
        print("\n-- attachments --")
        for item in files:
            print(f"  file_id={item.get('id')} name={item.get('name')} "
                  f"size={item.get('size')}")
    if detail.get("has_container"):
        print("\n-- has_container: start an environment for this one --")


if __name__ == "__main__":
    raise SystemExit(main())
