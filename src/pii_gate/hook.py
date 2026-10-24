"""Hook entry point shared by Codex CLI, Claude Code and Gemini CLI.

All three agents send one JSON object on stdin and treat exit code 2 as "block, and show stderr as
the reason". Exit 0 with no output means "no objection". Anything unexpected inside this process
(bad JSON, a bug in a detector, an unreadable config, an oversized payload) blocks too, unless
fail_open is set: a gate that fails open is not a gate. What happens when the hook cannot start at
all or times out is up to the agent; the installer sets Claude Code's `onFailure: "block"` and wraps
the Codex command so that a missing interpreter still exits 2.
"""
from __future__ import annotations

import json
import os
import posixpath
import re
import sys
from dataclasses import dataclass
from typing import Any, List, Optional, Tuple

from . import log as decision_log
from .config import Config, ConfigError, load
from .detectors import Finding, mask
from .engine import Engine, Report, describe
from .exfil import tamper_path

PATH_KEYS = ("file_path", "path", "notebook_path", "filePath")
COMMAND_KEYS = ("command", "cmd", "commands", "script")
SHELL_TOOLS = ("Bash", "PowerShell", "Monitor", "shell", "local_shell", "exec_command", "run_shell_command")
# Local file writers: their content is scanned and allow_paths applies. A remote writer (an MCP
# "create file in repository" tool) is scanned like any other tool and allow_paths does not apply.
LOCAL_WRITE_TOOLS = ("Edit", "MultiEdit", "Write", "NotebookEdit", "apply_patch", "write_file", "replace")
READ_TOOLS = ("Read", "NotebookRead", "read_file", "read_many_files")
# Tools that take a local file and send it somewhere: the content is not in the payload, only the path.
FILE_SEND_TOOLS = ("Artifact", "SendUserFile")
BROWSE_TOOLS = ("Grep", "Glob", "LS", "glob", "grep_search", "search_file_content", "list_directory")
PROMPT_EVENTS = ("UserPromptSubmit", "BeforeAgent")
TOOL_EVENTS = ("PreToolUse", "BeforeTool")
MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_PAYLOAD_BYTES = 8 * 1024 * 1024     # scanning runs at roughly 1 s/MB; the agents' timeout is 20 s
# Codex apply_patch grammar: "*** Add File: p", "*** Update File: p", "*** Delete File: p", "*** Move to: p".
_PATCH_FILE = re.compile(r"^\*\*\* (?:Add File|Update File|Delete File|Move to):\s*(.+?)\s*$", re.M)


@dataclass
class Outcome:
    exit_code: int
    stderr: str = ""
    stdout: str = ""
    counts: Optional[dict] = None


def _strings(value: Any, out: List[str]) -> None:
    """Every string in a JSON value, including dict keys and numbers (an ID can travel as an int)."""
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, bool) or value is None:
        return
    elif isinstance(value, (int, float)):
        out.append(str(value))
    elif isinstance(value, dict):
        for k, v in value.items():
            _strings(str(k), out)
            _strings(v, out)
    elif isinstance(value, list):
        for v in value:
            _strings(v, out)


def _added_lines(patch: str) -> str:
    """Every `+` line of an apply_patch body is content; there are no `+++` headers in that grammar."""
    return "\n".join(line[1:] for line in patch.splitlines() if line.startswith("+"))


def _command_text(tool_input: dict) -> Optional[str]:
    """The shell command of a shell-like tool: a string, or an argv list joined with spaces."""
    for key in COMMAND_KEYS:
        value = tool_input.get(key)
        if isinstance(value, str):
            return value
        if isinstance(value, list) and value and all(isinstance(v, (str, int, float)) for v in value):
            return " ".join(str(v) for v in value)
    return None


def _agent(payload: dict) -> str:
    if "turn_id" in payload or "model" in payload:
        return "codex"
    if "prompt_id" in payload or "scratchpad_dir" in payload or "permission_mode" in payload:
        return "claude"
    if str(payload.get("hook_event_name", "")).startswith(("Before", "After")) or "timestamp" in payload:
        return "gemini"
    return "agent"


def _reason(event: str, tool: str, rep: Report) -> str:
    head = f"pii-gate blocked this {tool or event} call." if event in TOOL_EVENTS else "pii-gate blocked this prompt."
    lines = ["  - " + line for line in describe(rep.blocking)]
    tail = ("This call was stopped because it may carry personal data or secrets out of this session. "
            "Remove them. If this is synthetic test data, the user can allow it in .pii-gate.json "
            "(allow_values, allow_paths); the agent may not edit that file.")
    return "\n".join([head, *lines, tail])


def _resolve(path: str, cwd: Optional[str]) -> str:
    if cwd and not os.path.isabs(path):
        return os.path.join(cwd, path)
    return path


def _read_text(path: str) -> Optional[str]:
    """File content for scanning, or None when it is missing, binary or too large."""
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            return None
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return None
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="replace")
    if b"\x00" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace")


def _file_findings(engine: Engine, rule: str, paths: List[str], cwd: Optional[str], what: str) -> List[Finding]:
    """One finding per file whose content holds block-level personal data or secrets."""
    out: List[Finding] = []
    for p in paths:
        text = _read_text(_resolve(p, cwd))
        if text is None:
            continue
        inner = [f for f in engine.findings(text, sql=False) if engine.config.level(f.rule) == "block"]
        if not inner:
            continue
        counts = Report().counts(inner)
        summary = ", ".join(f"{k}x{v}" for k, v in sorted(counts.items()))
        out.append(Finding(rule, 0, 0, inner[0].sample, f"{what} contains {summary}"))
    return out


def evaluate(payload: dict, cfg: Config) -> Tuple[Report, str, str]:
    """Returns (report, event, tool). Pure apart from reading files named by read/send tools."""
    engine = Engine(cfg)
    event = str(payload.get("hook_event_name", ""))
    tool = str(payload.get("tool_name", ""))
    cwd = payload.get("cwd")
    root = cfg.project_root or cwd
    if not event and (tool or "tool_input" in payload):
        event = "PreToolUse"                           # an unlabelled tool call is still a tool call
    if event in PROMPT_EVENTS:
        if not cfg.scan_prompts:
            return Report(), event, tool
        return engine.scan_text(str(payload.get("prompt", "")), sql=False), event, tool
    if event not in TOOL_EVENTS:
        return Report(), event, tool
    tool_input = payload.get("tool_input", {})
    if not isinstance(tool_input, dict):
        tool_input = {"value": tool_input}
    findings: List[Finding] = []

    # 1. Shell commands: full rule set including exfiltration and tamper rules. A tool is a shell
    #    when it is a known one, or when its input carries a command (MCP shells, argv lists).
    command = _command_text(tool_input)
    if tool in SHELL_TOOLS or (command is not None and tool not in LOCAL_WRITE_TOOLS):
        findings += engine.findings(command or "", command=True)
        rest: List[str] = []
        _strings({k: v for k, v in tool_input.items() if k not in COMMAND_KEYS}, rest)
        for text in rest:                             # Monitor's ws.url, env blocks, descriptions
            findings += engine.findings(text)
        return engine.report(findings), event, tool

    paths = [str(tool_input[k]) for k in PATH_KEYS if isinstance(tool_input.get(k), str)]
    extra = tool_input.get("file_paths")
    if isinstance(extra, list):
        paths += [str(p) for p in extra if isinstance(p, str)]

    # 2. Reads and file sends: the file's content is what leaves, so look at the file.
    if tool in READ_TOOLS or tool in FILE_SEND_TOOLS:
        paths = [p for p in paths if not engine.path_allowed(p, root)]
        if tool in READ_TOOLS:
            if cfg.level("read") != "off":
                findings += _file_findings(engine, "read", paths, cwd, "file")
        else:
            findings += _file_findings(engine, "exfil", paths, cwd, "file sent out")
        return engine.report(findings), event, tool
    if tool in BROWSE_TOOLS:
        return Report(), event, tool

    # 3. File writes: what the agent writes, not what already exists. Honour allow_paths for local files.
    if tool == "apply_patch":
        patch = str(tool_input.get("command", tool_input.get("input", "")))
        paths = _PATCH_FILE.findall(patch)
        texts = [_added_lines(patch)]
    elif tool in ("Edit", "replace"):
        texts = [str(tool_input.get("new_string", ""))]
    elif tool == "MultiEdit":
        texts = [str(e.get("new_string", "")) for e in tool_input.get("edits", []) if isinstance(e, dict)]
    elif tool in ("Write", "write_file"):
        texts = [str(tool_input.get("content", ""))]
    elif tool == "NotebookEdit":
        texts = [str(tool_input.get("new_source", ""))]
    else:
        texts = []
        _strings(tool_input, texts)
    for p in paths:
        if tamper_path(p, root):
            verb = "write to" if tool in LOCAL_WRITE_TOOLS else "touches"
            findings.append(Finding("tamper", 0, 0, mask(posixpath.basename(p.replace("\\", "/"))),
                                    f"{verb} the gate's own configuration"))
    if tool in LOCAL_WRITE_TOOLS and paths and all(engine.path_allowed(p, root) for p in paths):
        return engine.report(findings), event, tool
    for text in texts:
        findings += engine.findings(text)
    return engine.report(findings), event, tool


def _stdout_for(payload: dict, event: str) -> str:
    """Claude Code echoes a blocked prompt back to the user and into the transcript unless told not to."""
    if event == "UserPromptSubmit" and _agent(payload) != "codex":
        return json.dumps({"hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "suppressOriginalPrompt": True}})
    return ""


def run(stdin_text: str, cfg: Optional[Config] = None, home: Optional[str] = None,
        fail_open: Optional[bool] = None) -> Outcome:
    try:
        if len(stdin_text) > MAX_PAYLOAD_BYTES:
            raise ValueError(f"payload of {len(stdin_text) // 1024} KB is too large to scan within the hook timeout")
        payload = json.loads(stdin_text)
        if not isinstance(payload, dict):
            raise ValueError("hook payload must be a JSON object")
        if cfg is None:
            cfg = load(cwd=payload.get("cwd"), home=home)
        rep, event, tool = evaluate(payload, cfg)
        if cfg.log and (rep.blocking or rep.warnings):
            decision = "DENY" if rep.blocked else "ALLOW-WARN"
            decision_log.write(_agent(payload), event, tool, decision,
                               {**rep.counts(rep.warnings), **rep.counts()}, home=home)
        if rep.blocked:
            return Outcome(2, _reason(event, tool, rep), _stdout_for(payload, event), rep.counts())
        return Outcome(0)
    except Exception as exc:  # noqa: BLE001 - fail closed on anything
        open_ = fail_open if fail_open is not None else (cfg.fail_open if cfg else False)
        kind = "config error" if isinstance(exc, ConfigError) else "internal error"
        msg = f"pii-gate {kind}: {exc}. " + ("Allowing (fail_open)." if open_ else "Blocking to stay safe.")
        return Outcome(0 if open_ else 2, msg)


def _write(stream: Any, text: str) -> None:
    """Write UTF-8 whatever the console code page is. An encoding error here would turn a block
    (exit 2) into a crash (exit 1), and the agents do not treat exit 1 as a block."""
    try:
        stream.buffer.write(text.encode("utf-8", errors="replace"))
        stream.buffer.flush()
    except (AttributeError, OSError, ValueError):
        stream.write(text.encode("ascii", errors="replace").decode("ascii"))
        stream.flush()


def main(fail_open: Optional[bool] = None) -> int:
    try:
        data = sys.stdin.buffer.read().decode("utf-8", errors="replace")
    except (AttributeError, OSError, ValueError):
        data = sys.stdin.read()
    out = run(data, fail_open=fail_open)
    if out.stdout:
        _write(sys.stdout, out.stdout + "\n")
    if out.stderr:
        _write(sys.stderr, out.stderr + "\n")
    return out.exit_code
