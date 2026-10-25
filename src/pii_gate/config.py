"""Configuration: defaults, then the home file, then the project file on top.

Trust model. The home file (`~/.pii-gate.json`) and the file named by `$PII_GATE_CONFIG` belong to
the user and may do anything. The project file (`<project root>/.pii-gate.json`) travels with the
repository the agent is working in, which the agent may have cloned a minute ago. It may therefore
only *tighten* the gate: raise a rule's level, add allow-listed values and paths inside the project,
add sensitive columns and person tables. Lowering a level, `fail_open`, `scan_prompts` and `log`
are accepted from a project file only when the home file says `"trust_project_config": true`.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

RULES = (
    "tckn", "es-dni", "it-cf", "nl-bsn", "pl-pesel", "se-personnummer", "be-rrn", "iban", "card", "email", "phone", "secret", "secret-assign",
    "exfil", "git-push", "tamper", "sql-pii", "sql-star", "sql-pii-context", "read",
)
DEFAULT_LEVELS: Dict[str, str] = {
    "tckn": "block", "es-dni": "block", "it-cf": "block", "nl-bsn": "block", "pl-pesel": "block",
    "se-personnummer": "block", "be-rrn": "block",
    "iban": "block", "card": "block", "secret": "block", "exfil": "block",
    "git-push": "block", "tamper": "block", "sql-pii": "block", "sql-star": "block", "read": "block",
    "email": "warn", "phone": "warn", "secret-assign": "warn", "sql-pii-context": "warn",
}
LEVELS = ("block", "warn", "off")
_STRICTNESS = {"off": 0, "warn": 1, "block": 2}
FILE_NAME = ".pii-gate.json"
ENV_VAR = "PII_GATE_CONFIG"
PROJECT_ROOT_VARS = ("CLAUDE_PROJECT_DIR", "GEMINI_PROJECT_DIR")
KNOWN_KEYS = {"rules", "allow_values", "allow_paths", "email_allow_domains", "sql", "scan_prompts", "fail_open",
              "log", "trust_project_config"}
KNOWN_SQL_KEYS = {"extra_pii_columns", "extra_person_tables", "ignore_columns"}
USER_ONLY_KEYS = ("scan_prompts", "fail_open", "log", "trust_project_config")
_DRIVE = re.compile(r"^[A-Za-z]:")


class ConfigError(ValueError):
    pass


@dataclass
class Config:
    levels: Dict[str, str] = field(default_factory=lambda: dict(DEFAULT_LEVELS))
    allow_values: Set[str] = field(default_factory=set)
    allow_paths: List[str] = field(default_factory=list)
    email_allow_domains: List[str] = field(default_factory=list)
    sql_extra_columns: Set[str] = field(default_factory=set)
    sql_extra_person_tables: Set[str] = field(default_factory=set)
    sql_ignore_columns: Set[str] = field(default_factory=set)
    scan_prompts: bool = True
    fail_open: bool = False
    log: bool = True
    trust_project_config: bool = False
    source: str = "defaults"
    project_root: Optional[str] = None

    def level(self, rule: str) -> str:
        return self.levels.get(rule, "block")


def _as_list(data: dict, key: str, path: str) -> List[str]:
    value = data.get(key, [])
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"{path}: '{key}' must be a list of strings")
    return value


def apply(cfg: Config, data: dict, path: str = "<config>", trusted: bool = True) -> Config:
    """Merge one file's settings into cfg. Untrusted (project) files may only tighten."""
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: top level must be an object")
    unknown = sorted(k for k in data if k not in KNOWN_KEYS and not k.startswith("_"))   # "_comment" is fine
    if unknown:
        raise ConfigError(f"{path}: unknown key(s) {', '.join(unknown)} (known: {', '.join(sorted(KNOWN_KEYS))})")
    rules = data.get("rules", {})
    if not isinstance(rules, dict):
        raise ConfigError(f"{path}: 'rules' must be an object")
    for rule, level in rules.items():
        if rule not in RULES:
            raise ConfigError(f"{path}: unknown rule '{rule}' (known: {', '.join(RULES)})")
        if level not in LEVELS:
            raise ConfigError(f"{path}: rule '{rule}' must be one of {', '.join(LEVELS)}")
        if not trusted and _STRICTNESS[level] < _STRICTNESS[cfg.level(rule)]:
            raise ConfigError(
                f"{path}: a project config may not lower '{rule}' from {cfg.level(rule)} to {level}; "
                f"put it in ~/{FILE_NAME} or set \"trust_project_config\": true there")
        cfg.levels[rule] = level
    for key in ("allow_values", "email_allow_domains"):
        values = _as_list(data, key, path)
        if values and not trusted:
            raise ConfigError(f"{path}: '{key}' loosens the gate and is only read from ~/{FILE_NAME} or ${ENV_VAR}")
    cfg.allow_values |= set(_as_list(data, "allow_values", path))
    for pattern in _as_list(data, "allow_paths", path):
        if not trusted:
            first = pattern.replace("\\", "/").lstrip("./").split("/", 1)[0]
            if (pattern.startswith(("/", "\\", "~")) or ".." in pattern or _DRIVE.match(pattern)
                    or not first or any(ch in first for ch in "*?[")):
                raise ConfigError(f"{path}: a project config may only allow paths inside a named folder of the project "
                                  f"(like 'tests/*'), not '{pattern}'")
        cfg.allow_paths.append(pattern)
    cfg.email_allow_domains += _as_list(data, "email_allow_domains", path)
    sql = data.get("sql", {})
    if not isinstance(sql, dict):
        raise ConfigError(f"{path}: 'sql' must be an object")
    unknown = sorted(set(sql) - KNOWN_SQL_KEYS)
    if unknown:
        raise ConfigError(f"{path}: unknown sql key(s) {', '.join(unknown)} (known: {', '.join(sorted(KNOWN_SQL_KEYS))})")
    cfg.sql_extra_columns |= set(_as_list(sql, "extra_pii_columns", path))
    cfg.sql_extra_person_tables |= set(_as_list(sql, "extra_person_tables", path))
    ignored = _as_list(sql, "ignore_columns", path)
    if ignored and not trusted:
        raise ConfigError(f"{path}: 'sql.ignore_columns' loosens the gate and is only read from ~/{FILE_NAME} or ${ENV_VAR}")
    cfg.sql_ignore_columns |= set(ignored)
    for key in USER_ONLY_KEYS:
        if key in data:
            if not isinstance(data[key], bool):
                raise ConfigError(f"{path}: '{key}' must be true or false")
            if not trusted:
                raise ConfigError(f"{path}: '{key}' is only read from ~/{FILE_NAME} or ${ENV_VAR}")
            setattr(cfg, key, data[key])
    cfg.source = path if cfg.source == "defaults" else f"{cfg.source} + {path}"
    return cfg


def parse(data: dict, path: str = "<config>") -> Config:
    """A single, fully trusted config (tests, the env file)."""
    return apply(Config(), data, path, trusted=True)


def _read(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as exc:
        raise ConfigError(f"{path}: cannot read config ({exc})") from exc
    return data


def project_root(cwd: Optional[str] = None, env: Optional[Dict[str, str]] = None) -> Optional[str]:
    """The directory the agent session was started in: the agents tell us through an environment
    variable; otherwise walk up from cwd to the nearest .pii-gate.json or .git. The project config
    lives there, not in whatever subdirectory the agent has cd'ed into."""
    env = os.environ if env is None else env
    for var in PROJECT_ROOT_VARS:
        if env.get(var):
            return env[var]
    if not cwd:
        return None
    here = Path(cwd)
    for candidate in (here, *here.parents):
        if (candidate / FILE_NAME).is_file() or (candidate / ".git").exists():
            return str(candidate)
    return cwd


def candidates(cwd: Optional[str] = None, home: Optional[str] = None) -> List[Path]:
    """Files that would be consulted, for `pii-gate status`."""
    paths: List[Path] = []
    env = os.environ.get(ENV_VAR)
    if env:
        paths.append(Path(env))
    paths.append(Path(home or Path.home()) / FILE_NAME)
    root = project_root(cwd)
    if root:
        paths.append(Path(root) / FILE_NAME)
    return paths


def load(cwd: Optional[str] = None, home: Optional[str] = None) -> Config:
    env = os.environ.get(ENV_VAR)
    if env:
        path = Path(env)
        if not path.is_file():
            raise ConfigError(f"{ENV_VAR} points to {path}, which is not a file")
        return apply(Config(), _read(path), str(path), trusted=True)
    cfg = Config()
    home_file = Path(home or Path.home()) / FILE_NAME
    if home_file.is_file():
        apply(cfg, _read(home_file), str(home_file), trusted=True)
    root = project_root(cwd)
    cfg.project_root = root
    if root:
        project_file = Path(root) / FILE_NAME
        if project_file.is_file() and project_file.resolve() != home_file.resolve():
            apply(cfg, _read(project_file), str(project_file), trusted=cfg.trust_project_config)
    return cfg
