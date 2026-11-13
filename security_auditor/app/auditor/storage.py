"""Persistência em /data: histórico em SQLite e relatórios em JSON.

Os métodos são síncronos; o código assíncrono os chama via ``asyncio.to_thread``.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .config import AllowlistEntry
from .models import ScanResult

_LOGGER = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id     TEXT PRIMARY KEY,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    status      TEXT NOT NULL,
    counts_json TEXT NOT NULL DEFAULT '{}',
    new_count   INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS addon_stats (
    slug        TEXT NOT NULL,
    ts          TEXT NOT NULL,
    cpu_percent REAL,
    memory_usage INTEGER,
    memory_limit INTEGER,
    network_rx  INTEGER,
    network_tx  INTEGER,
    PRIMARY KEY (slug, ts)
);
CREATE INDEX IF NOT EXISTS idx_addon_stats_slug_ts ON addon_stats (slug, ts);
CREATE TABLE IF NOT EXISTS dns_domains (
    domain     TEXT PRIMARY KEY,
    first_seen TEXT,
    last_seen  TEXT,
    queries    INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS ignored (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    component   TEXT NOT NULL,
    rule        TEXT NOT NULL,
    path        TEXT,
    fingerprint TEXT,
    severities  TEXT,
    title       TEXT,
    reason      TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS traffic_events (
    slug          TEXT NOT NULL,
    ts            TEXT NOT NULL,
    rate          REAL NOT NULL,
    baseline_mean REAL NOT NULL,
    baseline_std  REAL NOT NULL,
    reported_scan TEXT,
    PRIMARY KEY (slug, ts)
);
"""


class Storage:
    def __init__(self, db_path: Path, reports_dir: Path) -> None:
        self.db_path = db_path
        self.reports_dir = reports_dir
        self._lock = threading.Lock()
        reports_dir.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.executescript(_SCHEMA)
            # Migração: a tabela "ignored" da 0.6.0 não tinha a coluna de níveis.
            cols = {r["name"] for r in conn.execute("PRAGMA table_info(ignored)")}
            if "severities" not in cols:
                conn.execute("ALTER TABLE ignored ADD COLUMN severities TEXT")

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                conn.row_factory = sqlite3.Row
                yield conn
                conn.commit()
            finally:
                conn.close()

    # --- Lista de ignorados (gerenciada pela interface) -------------------

    def list_ignored(self) -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM ignored ORDER BY id").fetchall()
        return [{**dict(r), "severities": [s for s in (r["severities"] or "").split(",") if s]} for r in rows]

    def add_ignored(self, *, component: str, rule: str, reason: str, created_at: str,
                    path: str | None = None, fingerprint: str | None = None, title: str | None = None,
                    severities: tuple[str, ...] = ()) -> int:
        with self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO ignored (component, rule, path, fingerprint, severities, title, reason, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (component, rule, path, fingerprint, ",".join(severities) or None, title, reason, created_at),
            )
            return int(cur.lastrowid or 0)

    def update_ignored_reason(self, entry_id: int, reason: str) -> bool:
        with self._conn() as conn:
            return conn.execute("UPDATE ignored SET reason = ? WHERE id = ?", (reason, entry_id)).rowcount > 0

    def remove_ignored(self, entry_id: int) -> bool:
        with self._conn() as conn:
            return conn.execute("DELETE FROM ignored WHERE id = ?", (entry_id,)).rowcount > 0

    def ignore_entries(self) -> list[AllowlistEntry]:
        return [
            AllowlistEntry(component=r["component"], rule=r["rule"], reason=r["reason"], path=r["path"],
                           fingerprint=r["fingerprint"], entry_id=r["id"], severities=tuple(r["severities"]))
            for r in self.list_ignored()
        ]

    # --- Varreduras -------------------------------------------------------

    def _report_path(self, scan_id: str) -> Path:
        # scan_id é gerado por nós (timestamp), mas validamos mesmo assim.
        if not scan_id.replace("-", "").replace("T", "").replace("Z", "").isalnum():
            raise ValueError("scan_id inválido")
        return self.reports_dir / f"{scan_id}.json"

    def save_scan(self, result: ScanResult) -> Path:
        data = result.to_dict()
        path = self._report_path(result.scan_id)
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, path)  # escrita atômica
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO scans (scan_id, started_at, finished_at, status, counts_json, new_count)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (
                    result.scan_id,
                    result.started_at,
                    result.finished_at,
                    result.status,
                    json.dumps(data["counts"]),
                    data["new_count"],
                ),
            )
        return path

    def list_scans(self, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM scans ORDER BY scan_id DESC LIMIT ? OFFSET ?", (limit, max(0, offset))
            ).fetchall()
        return [
            {**dict(r), "counts": json.loads(r["counts_json"] or "{}")}
            for r in rows
        ]

    def count_scans(self) -> int:
        with self._conn() as conn:
            return int(conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0])

    def latest_completed_id(self) -> str | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT scan_id FROM scans WHERE status = 'concluida' ORDER BY scan_id DESC LIMIT 1"
            ).fetchone()
        return row["scan_id"] if row else None

    def load_scan(self, scan_id: str) -> ScanResult | None:
        try:
            path = self._report_path(scan_id)
            return ScanResult.from_dict(json.loads(path.read_text(encoding="utf-8")))
        except (FileNotFoundError, ValueError, KeyError, json.JSONDecodeError):
            return None

    def load_latest(self) -> ScanResult | None:
        scan_id = self.latest_completed_id()
        return self.load_scan(scan_id) if scan_id else None

    def report_file(self, scan_id: str) -> Path | None:
        try:
            path = self._report_path(scan_id)
        except ValueError:
            return None
        return path if path.is_file() else None

    def prune(self, keep: int) -> int:
        """Mantém só os ``keep`` relatórios mais recentes."""
        with self._conn() as conn:
            old = [
                r["scan_id"]
                for r in conn.execute(
                    "SELECT scan_id FROM scans ORDER BY scan_id DESC LIMIT -1 OFFSET ?", (keep,)
                ).fetchall()
            ]
            for scan_id in old:
                conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
        for scan_id in old:
            try:
                self._report_path(scan_id).unlink(missing_ok=True)
            except ValueError:
                pass
        if old:
            _LOGGER.debug("Removidos %d relatórios antigos", len(old))
        return len(old)

    # --- Estatísticas de add-ons (Fase 2) --------------------------------

    def add_addon_stats(self, slug: str, ts: str, stats: dict[str, Any]) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO addon_stats VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    slug,
                    ts,
                    stats.get("cpu_percent"),
                    stats.get("memory_usage"),
                    stats.get("memory_limit"),
                    stats.get("network_rx"),
                    stats.get("network_tx"),
                ),
            )

    def addon_stats_since(self, slug: str, since: str) -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM addon_stats WHERE slug = ? AND ts >= ? ORDER BY ts", (slug, since)
            ).fetchall()
        return [dict(r) for r in rows]

    def prune_stats(self, older_than: str) -> None:
        with self._conn() as conn:
            conn.execute("DELETE FROM addon_stats WHERE ts < ?", (older_than,))
            conn.execute("DELETE FROM traffic_events WHERE ts < ?", (older_than,))

    def add_traffic_event(self, slug: str, ts: str, rate: float, mean: float, std: float) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO traffic_events (slug, ts, rate, baseline_mean, baseline_std)"
                " VALUES (?, ?, ?, ?, ?)",
                (slug, ts, rate, mean, std),
            )

    def take_unreported_events(self, scan_id: str) -> list[dict[str, Any]]:
        """Devolve os picos ainda não reportados e os marca como reportados nesta varredura."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM traffic_events WHERE reported_scan IS NULL ORDER BY slug, ts"
            ).fetchall()
            conn.execute("UPDATE traffic_events SET reported_scan = ? WHERE reported_scan IS NULL", (scan_id,))
        return [dict(r) for r in rows]

    # --- Domínios DNS (Fase 3) ------------------------------------------------

    def known_dns_domains(self) -> set[str]:
        with self._conn() as conn:
            return {r["domain"] for r in conn.execute("SELECT domain FROM dns_domains").fetchall()}

    def upsert_dns_domains(self, rows: list[tuple[str, str | None, str | None, int]]) -> None:
        with self._conn() as conn:
            conn.executemany(
                "INSERT INTO dns_domains (domain, first_seen, last_seen, queries) VALUES (?, ?, ?, ?)"
                " ON CONFLICT(domain) DO UPDATE SET last_seen = excluded.last_seen,"
                " queries = dns_domains.queries + excluded.queries",
                rows,
            )

    def addon_stats_history(self, slug: str, limit: int = 500) -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM addon_stats WHERE slug = ? ORDER BY ts DESC LIMIT ?", (slug, limit)
            ).fetchall()
        return [dict(r) for r in reversed(rows)]
