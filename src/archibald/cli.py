"""archibald scan | eval | serve"""

from __future__ import annotations

import argparse
import ipaddress
import os
import sys
from pathlib import Path

from archibald import __version__
from archibald.fetch import FetchError
from archibald.models import Verdict

LEVEL_RANK = {"clean": 0, "suspicious": 1, "likely": 2, "injection": 3}
DEFAULT_CORPUS = Path(__file__).resolve().parents[2] / "corpus"


def _render(verdict: Verdict) -> str:
    out = [f"{verdict.level.upper()}  score {verdict.score}/100  ·  {verdict.summary}"]
    for f in verdict.findings:
        hidden = " [hidden]" if f.hidden else ""
        out.append(f"  {f.severity:<8} {f.rule}{hidden}")
        out.append(f"           {f.location}")
        out.append(f"           “{f.evidence[:160]}”")
    for note in verdict.notes:
        out.append(f"  note: {note}")
    return "\n".join(out)


def _scan(args: argparse.Namespace) -> int:
    from archibald.scan import scan_bytes, scan_string, scan_url

    target: str = args.target
    try:
        if target.startswith(("http://", "https://")):
            verdict = scan_url(target, any_port=args.any_port)
        elif target == "-":
            verdict = scan_string(sys.stdin.read(), args.kind)
        else:
            path = Path(target)
            if args.kind in ("text", "html"):
                verdict = scan_string(path.read_text(encoding="utf-8", errors="replace"), args.kind)
            else:
                verdict = scan_bytes(path.read_bytes(), path.name)
    except FetchError as exc:
        print(f"archibald: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"archibald: {exc}", file=sys.stderr)
        return 2

    print(verdict.model_dump_json(indent=2) if args.json else _render(verdict))
    # Exit non-zero at or above --fail-at, so this can gate a pipeline that feeds
    # untrusted documents to an agent.
    return 1 if LEVEL_RANK[verdict.level] >= LEVEL_RANK[args.fail_at] else 0


def _eval(args: argparse.Namespace) -> int:
    from archibald.evaluate import evaluate, format_report

    print(format_report(evaluate(Path(args.corpus))))
    return 0


def _serve(args: argparse.Namespace) -> int:
    import uvicorn

    host = args.host
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = host == "localhost"
    if not loopback:
        print(
            "archibald: refusing to bind to a non-loopback address. The URL scanner "
            "fetches pages on request; exposed, it is a way into your network. "
            "Pass --allow-remote if you have put it behind something that handles that.",
            file=sys.stderr,
        )
        if not args.allow_remote:
            return 2
    if args.allow_remote:
        # Read by the app's own guard (server.py), which otherwise refuses any
        # peer or Host header that is not loopback.
        os.environ["ARCHIBALD_ALLOW_REMOTE"] = "1"
    print(f"Archibald {__version__} — http://{host}:{args.port}")
    uvicorn.run("archibald.server:app", host=host, port=args.port, log_level="warning")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="archibald", description="Prompt-injection detector")
    parser.add_argument("--version", action="version", version=f"archibald {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a file, a URL, or stdin (-)")
    scan.add_argument("target")
    scan.add_argument(
        "--kind",
        choices=["auto", "text", "html"],
        default="auto",
        help="force how text input is read (files are sniffed by content)",
    )
    scan.add_argument("--json", action="store_true", help="print the full JSON verdict")
    scan.add_argument(
        "--fail-at",
        choices=list(LEVEL_RANK),
        default="likely",
        help="exit 1 at or above this level (default: likely)",
    )
    scan.add_argument(
        "--any-port",
        action="store_true",
        help="allow URLs on ports other than 80 and 443",
    )
    scan.set_defaults(func=_scan)

    ev = sub.add_parser("eval", help="precision/recall against the labelled corpus")
    ev.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    ev.set_defaults(func=_eval)

    serve = sub.add_parser("serve", help="run the web UI")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8741)
    serve.add_argument("--allow-remote", action="store_true")
    serve.set_defaults(func=_serve)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
