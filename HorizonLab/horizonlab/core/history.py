"""Historique des analyses (SQLite, bibliothèque standard) et journalisation."""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from horizonlab.core.models import utcnow

_LOCK = threading.Lock()


def setup_logging(log_file: Optional[Path] = None, level: int = logging.INFO) -> logging.Logger:
    log = logging.getLogger("horizonlab")
    log.setLevel(level)
    if not any(isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler) for h in log.handlers):
        sh = logging.StreamHandler()
        sh.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
        log.addHandler(sh)
    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        if not any(isinstance(h, logging.FileHandler) and Path(h.baseFilename) == Path(log_file).resolve()
                   for h in log.handlers):
            fh = logging.FileHandler(log_file, encoding="utf-8")
            fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
            log.addHandler(fh)
    return log


class History:
    """Table ``runs`` : un enregistrement par analyse / diagnostic / campagne de tests."""

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as c:
            c.execute(
                """CREATE TABLE IF NOT EXISTS runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    subject TEXT,
                    status TEXT,
                    report_path TEXT,
                    summary TEXT
                )"""
            )

    def _conn(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path, timeout=10)

    def record(self, kind: str, subject: str, status: str, report_path: str = "",
               summary: Optional[Dict[str, Any]] = None) -> int:
        with _LOCK, self._conn() as c:
            cur = c.execute(
                "INSERT INTO runs(created, kind, subject, status, report_path, summary) VALUES (?,?,?,?,?,?)",
                (utcnow(), kind, subject, status, report_path, json.dumps(summary or {}, ensure_ascii=False)),
            )
            return int(cur.lastrowid)

    def list(self, kind: Optional[str] = None, limit: int = 200) -> List[Dict[str, Any]]:
        q = "SELECT id, created, kind, subject, status, report_path, summary FROM runs"
        args: tuple = ()
        if kind:
            q += " WHERE kind = ?"
            args = (kind,)
        q += " ORDER BY id DESC LIMIT ?"
        args += (limit,)
        with self._conn() as c:
            rows = c.execute(q, args).fetchall()
        out = []
        for r in rows:
            out.append({"id": r[0], "created": r[1], "kind": r[2], "subject": r[3], "status": r[4],
                        "report_path": r[5], "summary": json.loads(r[6] or "{}")})
        return out
