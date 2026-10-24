"""Writes the hook entries into Codex CLI, Claude Code and Gemini CLI configuration files.

The hook is never launched with a plain `python -m pii_gate`: `-m` puts the agent's working
directory first on sys.path, so a `pii_gate/` folder or a `json.py` written into the project would
be imported instead of the installed code. The interpreter is started with `-P` (3.11+, "safe
path") or, on older versions, with a one-liner that removes the working directory from sys.path
before importing the gate.

Claude Code gets the exec form (command + args, no shell) with `onFailure: "block"`, so a hook that
cannot start or times out blocks the call instead of letting it through. Codex has no such switch;
its shell-form command is wrapped so that a missing interpreter still exits 2.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

MARKER = "pii-gate"
MARKERS = ("pii-gate", "pii_gate")
TIMEOUT = 20          # seconds (Codex, Claude); Gemini takes milliseconds
AGENTS = ("codex", "claude", "gemini")
_SAFE_MODULE_RUN = "import sys; sys.path.pop(0); from pii_gate.hook import main; sys.exit(main())"


def hook_program(python: Optional[str] = None) -> Tuple[str, List[str]]:
    """(executable, arguments) that run the hook without the working directory on sys.path.

    The interpreter is preferred over the `pii-gate` console script: on Windows the script is a
    launcher that starts a second process, which doubles the start-up time of every hook call.
    """
    exe = python or sys.executable
    if sys.version_info >= (3, 11):
        return exe, ["-P", "-m", "pii_gate", "hook"]
    return exe, ["-c", _SAFE_MODULE_RUN]


def _quote(arg: str) -> str:
    return arg if arg and all(c.isalnum() or c in "-_./:\\" for c in arg) else '"' + arg.replace('"', '\\"') + '"'


def hook_command(python: Optional[str] = None) -> str:
    """POSIX shell form of the same command. A launch failure still exits 2 with a reason."""
    program, args = hook_program(python)
    inner = " ".join(_quote(a) for a in (program, *args))
    return f'{inner} || {{ echo "pii-gate hook failed to start; blocking" >&2; exit 2; }}'


def hook_command_windows(python: Optional[str] = None) -> str:
    """cmd.exe form for Codex on Windows (`commandWindows`)."""
    program, args = hook_program(python)
    inner = " ".join(_quote(a) for a in (program, *args))
    return f'{inner} || (echo pii-gate hook failed to start; blocking 1>&2 & exit /b 2)'


def target(agent: str, project: bool, cwd: Optional[str] = None, home: Optional[str] = None) -> Path:
    base = Path(cwd or Path.cwd()) if project else Path(home or Path.home())
    if agent == "codex":
        return base / ".codex" / "hooks.json"
    if agent == "claude":
        # The command embeds an absolute interpreter path, so the per-project file is the personal
        # settings.local.json, which Claude Code keeps out of version control.
        return base / ".claude" / ("settings.local.json" if project else "settings.json")
    if agent == "gemini":
        return base / ".gemini" / "settings.json"
    raise ValueError("agent must be one of " + ", ".join(AGENTS))


def _entry(agent: str, python: Optional[str] = None) -> Dict:
    if agent == "claude":
        program, args = hook_program(python)
        handler = {"type": "command", "command": program, "args": args, "timeout": TIMEOUT, "onFailure": "block"}
        return {"PreToolUse": [{"hooks": [handler]}], "UserPromptSubmit": [{"hooks": [dict(handler)]}]}
    if agent == "codex":
        handler = {"type": "command", "command": hook_command(python), "commandWindows": hook_command_windows(python),
                   "timeout": TIMEOUT, "statusMessage": MARKER}
        return {"PreToolUse": [{"matcher": ".*", "hooks": [handler]}], "UserPromptSubmit": [{"hooks": [dict(handler)]}]}
    if agent == "gemini":
        # Plain command, no shell wrapper: Gemini treats a launch failure as a warning either way,
        # and the wrapper syntax would not survive cmd.exe on Windows.
        program, args = hook_program(python)
        command = " ".join(_quote(a) for a in (program, *args))
        handler = {"name": MARKER, "type": "command", "command": command, "timeout": TIMEOUT * 1000}
        return {"BeforeTool": [{"matcher": "*", "hooks": [handler]}], "BeforeAgent": [{"hooks": [dict(handler)]}]}
    raise ValueError("agent must be one of " + ", ".join(AGENTS))


def _has_marker(group: Dict) -> bool:
    hooks = group.get("hooks", [])
    if not isinstance(hooks, list):
        return False
    for h in hooks:
        if isinstance(h, dict):
            args = h.get("args", [])
            text = " ".join([str(h.get("command", "")), str(h.get("commandWindows", "")), str(h.get("name", "")),
                             *(map(str, args) if isinstance(args, list) else [])])
            if any(m in text for m in MARKERS):
                return True
    return False


def _read(path: Path) -> Dict:
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig") or "{}")
    except ValueError as exc:
        raise ValueError(f"{path}: not valid JSON ({exc}); fix or move the file first") from exc
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return data


def _write(path: Path, data: Dict) -> None:
    """Atomic replace, non-ASCII kept as is."""
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=path.name, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _hooks(data: Dict, path: Path) -> Dict:
    hooks = data.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError(f"{path}: 'hooks' is not an object")
    return hooks


def install(agent: str, project: bool = False, cwd: Optional[str] = None, home: Optional[str] = None,
            python: Optional[str] = None) -> Path:
    path = target(agent, project, cwd, home)
    data = _read(path)
    hooks = _hooks(data, path)
    for event, groups in _entry(agent, python).items():
        existing = hooks.setdefault(event, [])
        if not isinstance(existing, list):
            raise ValueError(f"{path}: hooks.{event} is not a list")
        # Replace any earlier pii-gate entry so that upgrades pick up the new command shape.
        existing[:] = [g for g in existing if not (isinstance(g, dict) and _has_marker(g))]
        existing.extend(groups)
    _write(path, data)
    return path


def uninstall(agent: str, project: bool = False, cwd: Optional[str] = None, home: Optional[str] = None) -> Path:
    path = target(agent, project, cwd, home)
    if not path.is_file():
        return path
    data = _read(path)
    hooks = data.get("hooks", {})
    if not isinstance(hooks, dict):
        return path
    for event in list(hooks):
        if not isinstance(hooks[event], list):
            continue
        hooks[event] = [g for g in hooks[event] if not (isinstance(g, dict) and _has_marker(g))]
        if not hooks[event]:
            del hooks[event]
    if not hooks:
        data.pop("hooks", None)
    _write(path, data)
    return path


def _program_of(group: Dict) -> Optional[str]:
    for h in group.get("hooks", []):
        if isinstance(h, dict) and _has_marker({"hooks": [h]}):
            command = str(h.get("command", ""))
            if h.get("args"):
                return command
            command = command.strip()
            if command.startswith('"'):
                return command[1:command.find('"', 1)]
            return command.split(" ")[0]
    return None


def status(cwd: Optional[str] = None, home: Optional[str] = None) -> List[str]:
    lines = []
    for agent in AGENTS:
        for project in (False, True):
            path = target(agent, project, cwd, home)
            state = "missing"
            if path.is_file():
                try:
                    hooks = _read(path).get("hooks", {})
                    found = [e for e, groups in hooks.items() if isinstance(groups, list)
                             and any(_has_marker(g) for g in groups if isinstance(g, dict))]
                    if found:
                        state = "installed (" + ", ".join(found) + ")"
                        programs = {_program_of(g) for groups in hooks.values() if isinstance(groups, list)
                                    for g in groups if isinstance(g, dict) and _has_marker(g)}
                        missing = [p for p in programs if p and not (Path(p).is_file() or shutil.which(p))]
                        if missing:
                            state += f" BUT the hook program is missing: {missing[0]} - run `pii-gate install {agent}`"
                    else:
                        state = "present, no pii-gate entry"
                except ValueError as exc:
                    state = f"unreadable: {exc}"
            lines.append(f"{agent:6} {'project' if project else 'user   '} {path}: {state}")
    return lines
