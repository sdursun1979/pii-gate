"""Runs the detectors under a configuration and turns findings into a decision."""
from __future__ import annotations

import fnmatch
import posixpath
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import detectors, exfil, sqlgate
from .config import Config
from .detectors import Finding

_DRIVE = re.compile(r"^[A-Za-z]:")


@dataclass
class Report:
    blocking: List[Finding] = field(default_factory=list)
    warnings: List[Finding] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return bool(self.blocking)

    def counts(self, findings: Optional[List[Finding]] = None) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for f in self.blocking if findings is None else findings:
            out[f.rule] = out.get(f.rule, 0) + 1
        return out


class Engine:
    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()

    # ------------------------------------------------------------------ scanning
    def findings(self, text: str, *, pii: bool = True, secrets: bool = True, sql: bool = True,
                 command: bool = False) -> List[Finding]:
        cfg = self.config
        allow = cfg.allow_values
        found: List[Finding] = []
        if pii:
            found.extend(detectors.find_pii(text, allow, cfg.email_allow_domains))
        if secrets:
            found.extend(detectors.find_secrets(text, allow))
        if sql:
            found.extend(sqlgate.find_sql(text, cfg.sql_extra_columns, cfg.sql_extra_person_tables,
                                          cfg.sql_ignore_columns))
        if command:
            sensitive = any(cfg.level(f.rule) == "block" for f in found)
            found.extend(exfil.find_git_push(text))
            found.extend(exfil.find_exfil(text, sensitive))
            found.extend(exfil.find_tamper(text))
        return [f for f in found if cfg.level(f.rule) != "off"]

    def report(self, findings: List[Finding]) -> Report:
        rep = Report()
        for f in findings:
            (rep.blocking if self.config.level(f.rule) == "block" else rep.warnings).append(f)
        return rep

    def scan_text(self, text: str, **kw) -> Report:
        return self.report(self.findings(text, **kw))

    def scan_command(self, command: str) -> Report:
        return self.report(self.findings(command, command=True))

    # ------------------------------------------------------------------ paths
    def path_allowed(self, path: str, root: Optional[str] = None) -> bool:
        """True when the path matches an allow_paths glob (synthetic fixtures, docs with examples).

        Relative patterns (`tests/*`) are matched against the path relative to the project root, so
        they can never exempt a file outside the project. Absolute patterns match absolute paths.
        `..` segments are resolved first (`tests/../src/x` is `src/x`); a path that still escapes
        upwards is never allowed. fnmatch semantics: `*` also matches `/`.
        """
        if not path or not self.config.allow_paths:
            return False
        norm = posixpath.normpath(path.replace("\\", "/"))
        if norm.startswith("../") or norm == "..":
            return False
        absolute = norm.startswith("/") or _DRIVE.match(norm) is not None
        rel: Optional[str] = None if absolute else norm
        if root:
            prefix = posixpath.normpath(root.replace("\\", "/")).rstrip("/") + "/"
            if norm.lower().startswith(prefix.lower()):
                rel = norm[len(prefix):]
        for pattern in self.config.allow_paths:
            pat = pattern.replace("\\", "/")
            if pat.startswith("./"):
                pat = pat[2:]
            pat_absolute = pat.startswith("/") or _DRIVE.match(pat) is not None
            if pat_absolute:
                if fnmatch.fnmatch(norm, pat):
                    return True
            elif rel is not None and fnmatch.fnmatch(rel, pat):
                return True
        return False


def describe(findings: List[Finding], limit: int = 6) -> List[str]:
    """Human lines, one per rule, never containing a value."""
    by_rule: Dict[str, List[Finding]] = {}
    for f in findings:
        by_rule.setdefault(f.rule, []).append(f)
    lines = []
    for rule, items in list(by_rule.items())[:limit]:
        first = items[0]
        plural = "es" if len(items) > 1 else ""
        lines.append(f'{rule}: {len(items)} match{plural} ({first.note}, e.g. "{first.sample}")')
    return lines
