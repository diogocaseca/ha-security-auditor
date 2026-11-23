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


def component_key(component_type: str, name: str) -> str:
    return f"c\x1f{component_type}\x1f{name}"


def finding_key(fingerprint: str) -> str:
    return f"f\x1f{fingerprint}"

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
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS blocklist_items (
    id          TEXT PRIMARY KEY,
    item_json   TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
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
    created_at  TEXT NOT NULL,
    skip        INTEGER NOT NULL DEFAULT 0,
    fingerprints TEXT
);
-- Domínios que o usuário marcou como conhecidos: saem dos achados de DNS.
CREATE TABLE IF NOT EXISTS dns_ignored (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern    TEXT NOT NULL UNIQUE,
    reason     TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
-- Componentes excluídos da tabela ("Excluir…"): saem da análise até mudarem (reinstalação ou
-- atualização) ou sumirem do disco. "fingerprint" é a foto dos arquivos (ou a versão do add-on).
CREATE TABLE IF NOT EXISTS excluded (
    type        TEXT NOT NULL,
    name        TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    PRIMARY KEY (type, name)
);
-- Perfil de capacidades por componente e versão (capacidade nova trazida por atualização).
CREATE TABLE IF NOT EXISTS capabilities (
    type        TEXT NOT NULL,
    name        TEXT NOT NULL,
    version     TEXT NOT NULL,
    caps        TEXT NOT NULL,
    added       TEXT NOT NULL,
    previous    TEXT,
    updated_at  TEXT NOT NULL,
    PRIMARY KEY (type, name)
);
-- Respostas da API do GitHub guardadas por um dia (sinais de cadeia de suprimentos).
CREATE TABLE IF NOT EXISTS github_cache (
    key        TEXT PRIMARY KEY,
    data       TEXT NOT NULL,
    checked_at REAL NOT NULL
);
-- Commit para onde cada tag apontava na primeira vez (detecta tag reescrita).
CREATE TABLE IF NOT EXISTS tag_refs (
    repo       TEXT NOT NULL,
    tag        TEXT NOT NULL,
    sha        TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    PRIMARY KEY (repo, tag)
);
-- Última resposta da IA (opção ia_provedor) para cada domínio consultado na aba DNS.
CREATE TABLE IF NOT EXISTS dns_ai (
    domain      TEXT PRIMARY KEY,
    provider    TEXT NOT NULL,
    model       TEXT NOT NULL,
    verdict     TEXT NOT NULL,
    explanation TEXT NOT NULL,
    lang        TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
-- Primeira vez que cada componente ("c") ou achado ("f") apareceu numa varredura.
CREATE TABLE IF NOT EXISTS discovered (
    key        TEXT PRIMARY KEY,
    first_seen TEXT NOT NULL
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



def _json_list(raw: str | None) -> list[str]:
    try:
        data = json.loads(raw or "[]")
    except json.JSONDecodeError:
        return []
    return [str(x) for x in data] if isinstance(data, list) else []

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
            # Migração (0.20.0): "Não analisar" virou uma marcação explícita. Itens antigos que
            # ignoravam o componente em todos os níveis passam a só esconder os achados.
            if "skip" not in cols:
                conn.execute("ALTER TABLE ignored ADD COLUMN skip INTEGER NOT NULL DEFAULT 0")
            # Migração (0.21.0): ignorar níveis guarda a foto dos achados atuais (lista de impressões).
            if "fingerprints" not in cols:
                conn.execute("ALTER TABLE ignored ADD COLUMN fingerprints TEXT")
            # Migração (0.21.0): "Ignorar…" do componente voltou a tirar o componente da varredura.
            # Itens de componente inteiro (regra "*", todos os níveis, sem arquivo nem achado) ganham a
            # marcação "não analisar", como eram até a 0.19.x. Roda uma vez só.
            done = conn.execute("SELECT 1 FROM settings WHERE key = 'migracao_ignorar_componente'").fetchone()
            if not done:
                rows = conn.execute(
                    "SELECT id, component, severities FROM ignored WHERE skip = 0 AND rule IN ('*', '')"
                    " AND path IS NULL AND fingerprint IS NULL AND fingerprints IS NULL").fetchall()
                every = {"critical", "high", "medium", "low", "info"}
                for r in rows:
                    levels = {x for x in (r["severities"] or "").split(",") if x}
                    pattern = (r["component"] or "").strip()
                    if pattern and not set(pattern) <= {"*", "?"} and (not levels or every <= levels):
                        conn.execute("UPDATE ignored SET skip = 1 WHERE id = ?", (r["id"],))
                conn.execute("INSERT INTO settings (key, value) VALUES ('migracao_ignorar_componente', '1')")
            # Migração (0.17.0): varreduras parciais, feitas ao instalar ou atualizar um componente.
            # Migração (0.31.0): dados públicos (DNS e RDAP) mostrados junto da resposta da IA.
            if "facts_json" not in {r["name"] for r in conn.execute("PRAGMA table_info(dns_ai)")}:
                conn.execute("ALTER TABLE dns_ai ADD COLUMN facts_json TEXT NOT NULL DEFAULT '[]'")
            cols = {r["name"] for r in conn.execute("PRAGMA table_info(scans)")}
            if "kind" not in cols:
                conn.execute("ALTER TABLE scans ADD COLUMN kind TEXT NOT NULL DEFAULT 'completa'")
                conn.execute("ALTER TABLE scans ADD COLUMN targets_json TEXT NOT NULL DEFAULT '[]'")

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

    # --- Preferências da interface (ex.: idioma) ------------------------------

    def get_setting(self, key: str, default: str | None = None) -> str | None:
        with self._conn() as conn:
            row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default

    def set_setting(self, key: str, value: str) -> None:
        with self._conn() as conn:
            conn.execute("INSERT INTO settings (key, value) VALUES (?, ?) "
                         "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, value))

    # --- Lista negra pessoal (gerenciada pela interface) --------------------

    def list_blocklist_items(self) -> list[dict[str, Any]]:
        """Itens da lista negra pessoal criados pela interface, com as datas."""
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM blocklist_items ORDER BY created_at DESC, id DESC").fetchall()
        out = []
        for r in rows:
            try:
                item = json.loads(r["item_json"])
            except ValueError:
                continue
            out.append({"item": item, "criado_em": r["created_at"], "alterado_em": r["updated_at"]})
        return out

    def save_blocklist_item(self, item: dict[str, Any], now: str, *, create: bool) -> bool:
        """Cria (create=True) ou substitui um item. False se o id já existe (criar) ou não existe (editar)."""
        data = json.dumps(item, ensure_ascii=False, sort_keys=True)
        with self._conn() as conn:
            if create:
                cur = conn.execute(
                    "INSERT OR IGNORE INTO blocklist_items (id, item_json, created_at, updated_at) VALUES (?, ?, ?, ?)",
                    (item["id"], data, now, now))
            else:
                cur = conn.execute("UPDATE blocklist_items SET item_json = ?, updated_at = ? WHERE id = ?",
                                   (data, now, item["id"]))
            return cur.rowcount > 0

    def remove_blocklist_item(self, item_id: str) -> bool:
        with self._conn() as conn:
            return conn.execute("DELETE FROM blocklist_items WHERE id = ?", (item_id,)).rowcount > 0

    # --- Lista de ignorados (gerenciada pela interface) -------------------

    def list_ignored(self) -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM ignored ORDER BY id DESC").fetchall()
        return [{**dict(r), "severities": [s for s in (r["severities"] or "").split(",") if s], "skip": bool(r["skip"]),
                 "fingerprints": [f for f in (r["fingerprints"] or "").split(",") if f]}
                for r in rows]

    def add_ignored(self, *, component: str, rule: str, reason: str, created_at: str,
                    path: str | None = None, fingerprint: str | None = None, title: str | None = None,
                    severities: tuple[str, ...] = (), skip: bool = False,
                    fingerprints: tuple[str, ...] = ()) -> int:
        with self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO ignored (component, rule, path, fingerprint, severities, title, reason, created_at, skip,"
                " fingerprints) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (component, rule, path, fingerprint, ",".join(severities) or None, title, reason, created_at,
                 int(skip), ",".join(fingerprints) or None),
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
                           fingerprint=r["fingerprint"], entry_id=r["id"], severities=tuple(r["severities"]),
                           skip=r["skip"], fingerprints=frozenset(r["fingerprints"]))
            for r in self.list_ignored()
        ]

    # --- Data de descoberta ------------------------------------------------

    def discovered(self, keys: list[str], seen_at: str) -> dict[str, str]:
        """Registra as chaves ainda desconhecidas com ``seen_at`` e devolve a data de cada uma.

        Na primeira vez (tabela vazia), aproveita os relatórios guardados para não
        dar a mesma data a tudo o que já existia antes desta versão.
        """
        with self._conn() as conn:
            empty = conn.execute("SELECT 1 FROM discovered LIMIT 1").fetchone() is None
        if empty:
            self._backfill_discovered()
        with self._conn() as conn:
            conn.executemany("INSERT OR IGNORE INTO discovered (key, first_seen) VALUES (?, ?)",
                             [(k, seen_at) for k in keys])
            out: dict[str, str] = {}
            for i in range(0, len(keys), 500):
                chunk = keys[i:i + 500]
                marks = ",".join("?" * len(chunk))
                for r in conn.execute(f"SELECT key, first_seen FROM discovered WHERE key IN ({marks})", chunk):
                    out[r["key"]] = r["first_seen"]
        return out

    def _backfill_discovered(self) -> None:
        with self._conn() as conn:
            ids = [r["scan_id"] for r in conn.execute(
                "SELECT scan_id FROM scans WHERE status = 'concluida' ORDER BY scan_id")]
        rows: list[tuple[str, str]] = []
        for scan_id in ids:
            old = self.load_scan(scan_id)
            if old is None:
                continue
            rows += [(component_key(c.component_type, c.name), old.started_at) for c in old.components]
            rows += [(finding_key(f.fingerprint), old.started_at) for f in old.findings]
        if rows:
            with self._conn() as conn:
                conn.executemany("INSERT OR IGNORE INTO discovered (key, first_seen) VALUES (?, ?)", rows)
            _LOGGER.info("Datas de descoberta recuperadas de %d relatório(s) anteriores", len(ids))

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
                "INSERT OR REPLACE INTO scans (scan_id, started_at, finished_at, status, counts_json, new_count,"
                " kind, targets_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    result.scan_id,
                    result.started_at,
                    result.finished_at,
                    result.status,
                    json.dumps(data["counts"]),
                    data["new_count"],
                    result.kind,
                    json.dumps(result.targets, ensure_ascii=False),
                ),
            )
        return path

    def recent_changes(self, since: str) -> list[tuple[str, str, str]]:
        """Instalações/atualizações recentes: (início da varredura parcial, nome, mudança)."""
        with self._conn() as conn:
            rows = conn.execute("SELECT started_at, targets_json FROM scans WHERE kind = 'parcial' AND started_at >= ?",
                                (since,)).fetchall()
        out = []
        for r in rows:
            try:
                targets = json.loads(r["targets_json"] or "[]")
            except json.JSONDecodeError:
                continue
            out += [(r["started_at"], str(t.get("nome")), str(t.get("mudanca"))) for t in targets
                    if isinstance(t, dict) and t.get("nome") and t.get("mudanca") != "removido"]
        return out

    def list_scans(self, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM scans ORDER BY scan_id DESC LIMIT ? OFFSET ?", (limit, max(0, offset))
            ).fetchall()
        return [
            {**dict(r), "counts": json.loads(r["counts_json"] or "{}"),
             "targets": json.loads(r["targets_json"] or "[]")}
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

    def delete_scan(self, scan_id: str) -> None:
        """Remove um relatório (usado quando uma verificação de DNS substitui a anterior)."""
        path = self._report_path(scan_id)
        with self._conn() as conn:
            conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
        path.unlink(missing_ok=True)

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

    def github_cache(self, key: str) -> tuple[dict[str, Any], float] | None:
        with self._conn() as conn:
            r = conn.execute("SELECT data, checked_at FROM github_cache WHERE key = ?", (key,)).fetchone()
        return (json.loads(r["data"]), float(r["checked_at"])) if r else None

    def set_github_cache(self, key: str, data: dict[str, Any], checked_at: float) -> None:
        with self._conn() as conn:
            conn.execute("INSERT OR REPLACE INTO github_cache VALUES (?, ?, ?)", (key, json.dumps(data), checked_at))

    def first_tag_sha(self, repo: str, tag: str, sha: str, seen: str) -> str:
        """Commit da primeira vez que a tag foi vista (guarda ``sha`` se for a primeira)."""
        with self._conn() as conn:
            conn.execute("INSERT OR IGNORE INTO tag_refs VALUES (?, ?, ?, ?)", (repo, tag, sha, seen))
            return str(conn.execute("SELECT sha FROM tag_refs WHERE repo = ? AND tag = ?", (repo, tag)).fetchone()[0])

    def capability_row(self, component_type: str, name: str) -> dict[str, Any] | None:
        with self._conn() as conn:
            r = conn.execute("SELECT * FROM capabilities WHERE type = ? AND name = ?", (component_type, name)).fetchone()
        if r is None:
            return None
        return {"version": r["version"], "caps": json.loads(r["caps"]), "added": json.loads(r["added"]),
                "previous": r["previous"]}

    def save_capabilities(self, component_type: str, name: str, version: str, caps: set[str], added: set[str],
                          previous: str | None, updated_at: str) -> None:
        with self._conn() as conn:
            conn.execute("INSERT OR REPLACE INTO capabilities VALUES (?, ?, ?, ?, ?, ?, ?)",
                         (component_type, name, version, json.dumps(sorted(caps)), json.dumps(sorted(added)),
                          previous, updated_at))

    def list_excluded(self) -> list[dict[str, str]]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM excluded ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]

    def excluded_map(self) -> dict[tuple[str, str], str]:
        return {(e["type"], e["name"]): e["fingerprint"] for e in self.list_excluded()}

    def add_excluded(self, component_type: str, name: str, fingerprint: str, created_at: str) -> None:
        with self._conn() as conn:
            conn.execute("INSERT OR REPLACE INTO excluded VALUES (?, ?, ?, ?)",
                         (component_type, name, fingerprint, created_at))

    def remove_excluded(self, component_type: str, name: str) -> bool:
        with self._conn() as conn:
            return conn.execute("DELETE FROM excluded WHERE type = ? AND name = ?",
                                (component_type, name)).rowcount > 0

    def dns_ai(self, domain: str | None = None) -> dict[str, dict[str, str]]:
        """Respostas guardadas da IA: domínio -> {veredito, explicacao, provedor, modelo, idioma, data}."""
        with self._conn() as conn:
            rows = (conn.execute("SELECT * FROM dns_ai WHERE domain = ?", (domain,)) if domain
                    else conn.execute("SELECT * FROM dns_ai")).fetchall()
        return {r["domain"]: {"veredito": r["verdict"], "explicacao": r["explanation"], "provedor": r["provider"],
                              "modelo": r["model"], "idioma": r["lang"], "data": r["created_at"],
                              "fatos": _json_list(r["facts_json"])} for r in rows}

    def save_dns_ai(self, domain: str, answer: dict[str, str], lang: str, created_at: str) -> None:
        with self._conn() as conn:
            conn.execute("INSERT OR REPLACE INTO dns_ai (domain, provider, model, verdict, explanation, lang, "
                         "created_at, facts_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                         (domain, answer["provedor"], answer["modelo"], answer["veredito"], answer["explicacao"],
                          lang, created_at, json.dumps([str(x) for x in answer.get("fatos") or []])))

    def dns_first_seen(self) -> dict[str, str | None]:
        """Domínios já vistos e a data da primeira consulta de cada um."""
        with self._conn() as conn:
            return {r["domain"]: r["first_seen"] for r in conn.execute("SELECT domain, first_seen FROM dns_domains")}

    # --- Domínios ignorados (aba DNS) ---------------------------------------

    def list_dns_ignored(self) -> list[dict[str, Any]]:
        with self._conn() as conn:
            return [dict(r) for r in conn.execute("SELECT * FROM dns_ignored ORDER BY id DESC")]

    def dns_ignored_patterns(self) -> list[str]:
        return [r["pattern"] for r in self.list_dns_ignored()]

    def add_dns_ignored(self, pattern: str, reason: str, created_at: str) -> int | None:
        """Inclui o padrão; None se ele já estiver na lista."""
        with self._conn() as conn:
            cur = conn.execute("INSERT OR IGNORE INTO dns_ignored (pattern, reason, created_at) VALUES (?, ?, ?)",
                               (pattern, reason, created_at))
            return int(cur.lastrowid) if cur.rowcount else None

    def update_dns_ignored_reason(self, entry_id: int, reason: str) -> bool:
        with self._conn() as conn:
            return conn.execute("UPDATE dns_ignored SET reason = ? WHERE id = ?", (reason, entry_id)).rowcount > 0

    def remove_dns_ignored(self, entry_id: int) -> bool:
        with self._conn() as conn:
            return conn.execute("DELETE FROM dns_ignored WHERE id = ?", (entry_id,)).rowcount > 0

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
