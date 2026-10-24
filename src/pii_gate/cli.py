"""Command line: hook, check, scan, install, uninstall, status."""
from __future__ import annotations

import argparse
import bisect
import codecs
import os
import re
import sys
from pathlib import Path
from typing import Callable, Iterable, List, Optional, Tuple

from . import __version__, hook, installer
from .config import ConfigError, candidates, load
from .engine import Engine, describe

SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv", ".tox", ".mypy_cache"}
MAX_BYTES = 5 * 1024 * 1024


def _print(text: str = "") -> None:
    sys.stdout.write(text + "\n")


def _err(text: str) -> None:
    sys.stderr.write(text + "\n")


def _is_text(data: bytes) -> bool:
    return b"\x00" not in data[:8192]


def _decode(data: bytes) -> Optional[str]:
    """File bytes to text, or None for binary-looking data. UTF-16 with a BOM (what Windows
    PowerShell 5.1 writes with `>`) is text even though half of its bytes are NUL."""
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", errors="replace")
    if not _is_text(data):
        return None
    return data.decode("utf-8-sig", errors="replace")


def _iter_files(roots: Iterable[str]) -> Iterable[Path]:
    for root in roots:
        p = Path(root)
        if p.is_file():
            yield p
            continue
        for dirpath, dirnames, filenames in os.walk(p):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.endswith(".egg-info")]
            for name in filenames:
                yield Path(dirpath) / name


def cmd_check(args) -> int:
    cfg = load(cwd=os.getcwd())
    engine = Engine(cfg)
    text = sys.stdin.read() if args.stdin else " ".join(args.text)
    rep = engine.scan_command(text) if args.command else engine.scan_text(text)
    for line in describe(rep.blocking):
        _print("BLOCK  " + line)
    for line in describe(rep.warnings):
        _print("warn   " + line)
    if not rep.blocking and not rep.warnings:
        _print("clean")
    return 1 if rep.blocked else 0


def _report_findings(engine: Engine, label: str, text: str,
                     line_of: Optional[Callable[[int], Optional[int]]] = None) -> int:
    """Scan `text` once (so statements split over lines are seen whole) and print one line per
    finding as `label:line: BLOCK rule (note, "sample")`. Returns the number of blocking findings."""
    rep = engine.scan_text(text)
    if line_of is None:
        breaks = [i for i, ch in enumerate(text) if ch == "\n"]

        def line_of(offset: int) -> Optional[int]:
            return bisect.bisect_left(breaks, offset) + 1

    rows = [(line_of(f.start), 0, "BLOCK", f) for f in rep.blocking]
    rows += [(line_of(f.start), 1, "warn ", f) for f in rep.warnings]
    for n, _, kind, f in sorted(rows, key=lambda r: (r[0] or 0, r[1], r[3].start)):
        where = f"{label}:{n}" if n else label
        _print(f'{where}: {kind} {f.rule} ({f.note}, "{f.sample}")')
    return len(rep.blocking)


def _path_variants(path: str) -> List[str]:
    out: List[str] = []
    for p in (os.path.abspath(path), os.path.realpath(path)):
        if p not in out:
            out.append(p)
    return out


def _allowed(engine: Engine, path: str, root: str) -> bool:
    """allow_paths check that survives symlinked temp dirs and Windows 8.3 short names."""
    return any(engine.path_allowed(p, r) for p in _path_variants(path) for r in _path_variants(root))


def _unquote_git_path(path: str) -> str:
    """git still C-quotes paths with control characters, quotes or backslashes."""
    if len(path) >= 2 and path[0] == path[-1] == '"':
        raw = codecs.escape_decode(path[1:-1].encode("utf-8"))[0]
        return raw.decode("utf-8", errors="replace")
    return path


_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def parse_staged_diff(diff: str) -> List[Tuple[str, List[Tuple[int, str]]]]:
    """Added lines per file from `git diff -U0 --no-renames --src-prefix=a/ --dst-prefix=b/`.

    A `+++ ` line is a file header only right after a `--- ` line of a `diff --git` header;
    inside a hunk every `+` line is content, even one whose text starts with `++`.
    Returns [(path, [(line_number, text), ...]), ...]; deleted files are left out."""
    files: List[Tuple[str, List[Tuple[int, str]]]] = []
    current: Optional[List[Tuple[int, str]]] = None
    state = "none"  # none | header | minus | hunk
    lineno = 0
    for line in diff.split("\n"):
        if line.startswith("diff --git "):
            state, current = "header", None
            continue
        if state == "header" and line.startswith("--- "):
            state = "minus"
            continue
        if state == "minus" and line.startswith("+++ "):
            path = _unquote_git_path(line[4:].rstrip("\t"))
            if path == "/dev/null":
                current = None
            else:
                current = []
                files.append((path[2:] if path.startswith("b/") else path, current))
            state = "header"
            continue
        m = _HUNK.match(line)
        if m and state != "none":
            state, lineno = "hunk", int(m.group(1))
            continue
        if state == "hunk" and line.startswith("+"):
            if current is not None:
                current.append((lineno, line[1:].rstrip("\r")))
            lineno += 1
    return files


def _scan_staged(engine: Engine, root: str) -> int:
    """Blocking findings in the lines added to the git index, or -1 when git fails."""
    import subprocess

    def git(*argv: str):
        return subprocess.run(["git", "-c", "core.quotePath=false", *argv], capture_output=True, check=False)

    top = git("rev-parse", "--show-toplevel")
    if top.returncode != 0:
        _err(top.stderr.decode("utf-8", errors="replace").rstrip() or "pii-gate: not a git repository")
        return -1
    toplevel = top.stdout.decode("utf-8", errors="replace").strip()
    diff = git("diff", "--cached", "-U0", "--no-color", "--no-renames", "--no-ext-diff",
               "--src-prefix=a/", "--dst-prefix=b/")
    if diff.returncode != 0:
        _err(diff.stderr.decode("utf-8", errors="replace").rstrip())
        return -1
    blocked = 0
    for path, added in parse_staged_diff(diff.stdout.decode("utf-8", errors="replace")):
        if not added or _allowed(engine, os.path.join(toplevel, path), root):
            continue
        starts: List[int] = []
        pos = 0
        for _, t in added:
            starts.append(pos)
            pos += len(t) + 1
        numbers = [n for n, _ in added]
        text = "\n".join(t for _, t in added)
        blocked += _report_findings(engine, path, text,
                                    lambda off: numbers[bisect.bisect_right(starts, off) - 1])
    return blocked


def _listing(paths: List[str], limit: int = 20) -> str:
    shown = ", ".join(paths[:limit])
    return shown + (f", ... ({len(paths) - limit} more)" if len(paths) > limit else "")


def cmd_scan(args) -> int:
    cwd = os.getcwd()
    cfg = load(cwd=cwd)
    engine = Engine(cfg)
    root = cfg.project_root or cwd
    blocked = 0
    skipped: List[str] = []
    unreadable: List[str] = []
    if args.staged:
        blocked = _scan_staged(engine, root)
        if blocked < 0:
            return 2
    else:
        roots = args.paths or ["."]
        missing = [r for r in roots if not os.path.exists(r)]
        for r in missing:
            _err(f"pii-gate: {r}: no such file or directory")
        if missing:
            return 2
        for path in _iter_files(roots):
            rel = str(path)
            if _allowed(engine, rel, root):
                continue
            try:
                if path.stat().st_size > args.max_bytes:
                    skipped.append(rel)
                    continue
                data = path.read_bytes()
            except OSError:
                unreadable.append(rel)
                continue
            text = _decode(data)
            if text is None:
                skipped.append(rel)
                continue
            blocked += _report_findings(engine, rel, text)
    if skipped:
        _err(f"skipped: {len(skipped)} file(s) (too large or binary): {_listing(skipped)}")
    if unreadable:
        _err(f"skipped: {len(unreadable)} file(s) (unreadable): {_listing(unreadable)}")
    summary = f"{'BLOCKED' if blocked else 'clean'}: {blocked} blocking finding(s)"
    if skipped or unreadable:
        summary += f", {len(skipped) + len(unreadable)} file(s) skipped (listed on stderr)"
    _print(summary)
    return 1 if blocked else 0


def cmd_install(args) -> int:
    agents = list(installer.AGENTS) if args.agent == "all" else [args.agent]
    program, prog_args = installer.hook_program()
    if prog_args and prog_args[0] != "hook":
        _print("warning: the pii-gate console script was not found next to the interpreter; "
               "falling back to python -m with the working directory kept off sys.path")
    for agent in agents:
        path = installer.install(agent, project=args.project)
        _print(f"{agent}: hook written to {path}")
        if agent == "codex":
            _print("        run `codex`, then `/hooks` to review and trust the hook; Codex skips untrusted or"
                   " changed hooks, so repeat this after every reinstall")
        if agent == "gemini":
            _print("        start `gemini` and confirm the new hook when it asks (project hooks are fingerprinted)")
    return 0


def cmd_uninstall(args) -> int:
    agents = list(installer.AGENTS) if args.agent == "all" else [args.agent]
    for agent in agents:
        path = installer.uninstall(agent, project=args.project)
        _print(f"{agent}: pii-gate entries removed from {path}")
    return 0


def cmd_status(args) -> int:
    cwd = os.getcwd()
    try:
        cfg = load(cwd=cwd)
        _print(f"config: {cfg.source}")
        _print(f"project root: {cfg.project_root or '(none)'}")
        _print("rules : " + ", ".join(f"{r}={cfg.level(r)}" for r in sorted(cfg.levels)))
    except ConfigError as exc:
        _print(f"config: ERROR {exc}")
    _print("config files consulted ([x] = exists):")
    for path in candidates(cwd):
        _print(f"  [{'x' if path.is_file() else ' '}] {path}")
    for line in installer.status():
        _print(line)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pii-gate", description="Fail-closed personal-data gate for AI coding agents.")
    p.add_argument("--version", action="version", version=f"pii-gate {__version__}")
    sub = p.add_subparsers(dest="cmd")
    sub.required = True

    h = sub.add_parser("hook", help="run as a Codex CLI / Claude Code hook (reads JSON on stdin)")
    h.add_argument("--fail-open", action="store_true", help="allow on internal errors (default: block)")
    h.set_defaults(func=lambda a: hook.main(fail_open=True if a.fail_open else None))

    c = sub.add_parser("check", help="check a piece of text; exit 1 if it would be blocked")
    c.add_argument("text", nargs="*")
    c.add_argument("--stdin", action="store_true", help="read the text from stdin")
    c.add_argument("--command", action="store_true", help="treat the text as a shell command (exfil/tamper rules too)")
    c.set_defaults(func=cmd_check)

    s = sub.add_parser("scan", help="scan files (or --staged git changes); exit 1 on blocking findings")
    s.add_argument("paths", nargs="*")
    s.add_argument("--staged", action="store_true", help="scan lines added in the git index (pre-commit)")
    s.add_argument("--max-bytes", type=int, default=MAX_BYTES, metavar="N",
                   help=f"skip (and report) files larger than N bytes (default {MAX_BYTES})")
    s.set_defaults(func=cmd_scan)

    for name, fn in (("install", cmd_install), ("uninstall", cmd_uninstall)):
        i = sub.add_parser(name, help=f"{name} the hook for codex, claude, gemini or all")
        i.add_argument("agent", choices=[*installer.AGENTS, "all"])
        i.add_argument("--project", action="store_true",
                       help="write into ./.codex, ./.claude (settings.local.json) or ./.gemini instead of your home")
        i.set_defaults(func=fn)

    st = sub.add_parser("status", help="show active config and where the hook is installed")
    st.set_defaults(func=cmd_status)
    return p


def _tolerant_streams() -> None:
    """A filename or sample outside the console code page (cp1254, cp1252...) must not crash."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="backslashreplace")
        except (AttributeError, ValueError):
            pass


def main(argv: Optional[List[str]] = None) -> int:
    _tolerant_streams()
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except ConfigError as exc:
        sys.stderr.write(f"pii-gate config error: {exc}\n")
        return 2
    except ValueError as exc:  # e.g. installer: malformed settings JSON
        sys.stderr.write(f"pii-gate: {exc}\n")
        return 2
