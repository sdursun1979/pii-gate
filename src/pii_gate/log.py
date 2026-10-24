"""Decision log. One line per decision, rule names and counts only. Never a value."""
from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import Dict, Optional

LOG_DIR_NAME = ".pii-gate"
LOG_FILE = "decisions.log"


def log_path(home: Optional[str] = None) -> Path:
    return Path(home or Path.home()) / LOG_DIR_NAME / LOG_FILE


def write(agent: str, event: str, tool: str, decision: str, counts: Dict[str, int],
          home: Optional[str] = None) -> None:
    try:
        path = log_path(home)
        path.parent.mkdir(parents=True, exist_ok=True)
        stamp = dt.datetime.now().replace(microsecond=0).isoformat()
        rules = ",".join(f"{k}={v}" for k, v in sorted(counts.items())) or "-"
        with path.open("a", encoding="utf-8") as fh:   # text mode translates "\n" per platform
            fh.write(f"{stamp} {agent} {event} {tool or '-'} {decision} {rules}\n")
    except OSError:
        pass  # logging must never break the gate
