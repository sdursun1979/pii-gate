"""Configuration: defaults, then one JSON file (env, project, home)."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

RULES = (
    "tckn", "es-dni", "it-cf", "nl-bsn", "pl-pesel", "se-personnummer", "iban", "card", "email", "phone", "secret", "secret-assign",
    "exfil", "git-push", "tamper", "sql-pii", "sql-star", "sql-pii-context",
)
DEFAULT_LEVELS: Dict[str, str] = {
    "tckn": "block", "es-dni": "block", "it-cf": "block", "nl-bsn": "block", "pl-pesel": "block",
    "se-personnummer": "block",
    "iban": "block", "card": "block", "secret": "block", "exfil": "block",
    "git-push": "block", "tamper": "block", "sql-pii": "block", "sql-star": "block",
    "email": "warn", "phone": "warn", "secret-assign": "warn", "sql-pii-context": "warn",
}
LEVELS = ("block", "warn", "off")
FILE_NAME = ".pii-gate.json"
ENV_VAR = "PII_GATE_CONFIG"


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
    source: str = "defaults"

    def level(self, rule: str) -> str:
        return self.levels.get(rule, "block")


def _as_list(data: dict, key: str, path: str) -> List[str]:
    value = data.get(key, [])
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"{path}: '{key}' must be a list of strings")
    return value


def parse(data: dict, path: str = "<config>") -> Config:
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: top level must be an object")
    cfg = Config(source=path)
    rules = data.get("rules", {})
    if not isinstance(rules, dict):
        raise ConfigError(f"{path}: 'rules' must be an object")
    for rule, level in rules.items():
        if rule not in RULES:
            raise ConfigError(f"{path}: unknown rule '{rule}' (known: {', '.join(RULES)})")
        if level not in LEVELS:
            raise ConfigError(f"{path}: rule '{rule}' must be one of {', '.join(LEVELS)}")
        cfg.levels[rule] = level
    cfg.allow_values = set(_as_list(data, "allow_values", path))
    cfg.allow_paths = _as_list(data, "allow_paths", path)
    cfg.email_allow_domains = _as_list(data, "email_allow_domains", path)
    sql = data.get("sql", {})
    if not isinstance(sql, dict):
        raise ConfigError(f"{path}: 'sql' must be an object")
    cfg.sql_extra_columns = set(_as_list(sql, "extra_pii_columns", path))
    cfg.sql_extra_person_tables = set(_as_list(sql, "extra_person_tables", path))
    cfg.sql_ignore_columns = set(_as_list(sql, "ignore_columns", path))
    for key in ("scan_prompts", "fail_open", "log"):
        if key in data:
            if not isinstance(data[key], bool):
                raise ConfigError(f"{path}: '{key}' must be true or false")
            setattr(cfg, key, data[key])
    return cfg


def candidates(cwd: Optional[str] = None, home: Optional[str] = None) -> List[Path]:
    paths: List[Path] = []
    env = os.environ.get(ENV_VAR)
    if env:
        paths.append(Path(env))
    if cwd:
        paths.append(Path(cwd) / FILE_NAME)
    paths.append(Path(home or Path.home()) / FILE_NAME)
    return paths


def load(cwd: Optional[str] = None, home: Optional[str] = None) -> Config:
    for path in candidates(cwd, home):
        if path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8-sig"))
            except (OSError, ValueError) as exc:
                raise ConfigError(f"{path}: cannot read config ({exc})") from exc
            return parse(data, str(path))
    return Config()
