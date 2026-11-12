"""Código-fonte dos add-ons: Dockerfile, scripts e config.yaml baixados do GitHub.

Para cada add-on de repositório externo:
 1. candidatos: repositório do campo ``url`` do add-on e o repositório da loja;
 2. refs: ``v{versão}``, ``{versão}`` e, por último, ``HEAD`` (repositórios de
    loja raramente têm tag por add-on);
 3. acha o ``config.yaml`` com o slug do add-on e analisa a pasta dele com as
    regras Semgrep (shell/Dockerfile + Python/JS) e o ``map`` declarado.

Limitação: se o add-on usa imagem pronta (campo ``image``), a imagem pode ter
sido construída de um código diferente do publicado; o Trivy cobre a imagem.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import aiohttp
import yaml

from ..addons import AddonInfo
from ..inventory import walk_files
from ..models import ComponentType, Finding, Severity
from ..net import DownloadTooLargeError, EgressDeniedError, HttpError
from ..safe_archive import UnsafeArchiveError, extract
from .base import ScanContext
from .static import SEVERITY_BY_LABEL, read_snippet, run_semgrep

_LOGGER = logging.getLogger(__name__)

_SAFE = re.compile(r"[^A-Za-z0-9_.-]+")
TAG_TTL = 30 * 24 * 3600
HEAD_TTL = 24 * 3600
MISSING_TTL = 24 * 3600
MAX_SOURCE_FILE = 2 * 1024 * 1024
_BINARY_SUFFIXES = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".woff", ".woff2", ".ttf", ".eot",
    ".zip", ".gz", ".tgz", ".tar", ".xz", ".bz2", ".mp3", ".wav", ".mp4", ".pdf", ".so", ".bin", ".pyc",
)
_SKIP_DIRS = ("translations",)
_CONFIG_NAMES = ("config.yaml", "config.yml", "config.json")
_RULE_DIRS = ("addon", "python", "javascript")

# (tipo de pasta) -> (severidade se rw, severidade se ro, explicação)
_MAP_RISK: dict[str, tuple[Severity, Severity | None, str]] = {
    "homeassistant_config": (
        Severity.HIGH, Severity.MEDIUM,
        "a configuração do Home Assistant, incluindo o secrets.yaml e .storage (tokens). Com escrita, o "
        "add-on pode instalar uma integração customizada e executar código dentro do Home Assistant Core",
    ),
    "config": (
        Severity.HIGH, Severity.MEDIUM,
        "a configuração do Home Assistant, incluindo o secrets.yaml e .storage (tokens). Com escrita, o "
        "add-on pode instalar uma integração customizada e executar código dentro do Home Assistant Core",
    ),
    "backup": (Severity.MEDIUM, Severity.MEDIUM, "os backups, que contêm todas as senhas e tokens da instalação"),
    "all_addon_configs": (Severity.MEDIUM, Severity.LOW, "as configurações de todos os outros add-ons"),
    "addons": (Severity.MEDIUM, Severity.LOW, "a pasta de add-ons locais (pode alterar o código deles)"),
    "ssl": (Severity.LOW, Severity.INFO, "os certificados e chaves privadas TLS"),
}


@dataclass
class AddonSource:
    owner: str
    repo: str
    ref: str
    root: Path  # pasta do add-on dentro do repositório
    rel: str  # caminho da pasta dentro do repositório
    config: dict[str, Any]

    @property
    def label(self) -> str:
        return f"{self.owner}/{self.repo}@{self.ref}"


class SourceNotFoundError(Exception):
    pass


class AddonSourceScanner:
    name = "codigo_addons"

    def __init__(self) -> None:
        self._trees: dict[tuple[str, str, str], Path | None] = {}

    async def scan(self, ctx: ScanContext) -> list[Finding]:
        self._trees = {}
        findings: list[Finding] = []
        targets: list[Path] = []
        roots: list[tuple[Path, AddonInfo, AddonSource]] = []
        for addon in await ctx.addons():
            if addon.repository == "local" or not addon.github_candidates():
                continue
            ctx.set_progress(self.name, addon.slug)
            try:
                src = await self._locate(ctx, addon)
            except SourceNotFoundError as err:
                findings.append(_info(addon, "auditor.addon.codigo-nao-encontrado", "Código-fonte não encontrado",
                                      f"Não foi possível localizar o código do add-on no GitHub: {err}.",
                                      str(err)[:60]))
                continue
            except (HttpError, EgressDeniedError, DownloadTooLargeError, UnsafeArchiveError,
                    aiohttp.ClientError, TimeoutError, OSError) as err:
                findings.append(_info(addon, "auditor.addon.codigo-nao-encontrado", "Código-fonte não analisado",
                                      f"Falha ao baixar o código do add-on: {type(err).__name__}: {err}.",
                                      type(err).__name__))
                continue
            ctx.register_component(ComponentType.ADDON, addon.slug, codigo_fonte=src.label)
            findings.extend(_version_note(addon, src))
            findings.extend(evaluate_map(addon, src))
            files = select_files(src.root)
            targets.extend(files)
            roots.append((src.root, addon, src))

        if targets:
            ctx.set_progress(self.name, f"Semgrep em {len(targets)} arquivos de add-ons")
            raw, _incomplete = await run_semgrep(ctx, targets, _RULE_DIRS)
            for r in raw:
                f = _from_semgrep(r, roots)
                if f:
                    findings.append(f)
        return findings

    # --- Localização do código ----------------------------------------------

    async def _locate(self, ctx: ScanContext, addon: AddonInfo) -> AddonSource:
        refs: list[str] = []
        if addon.version:
            v = addon.version
            refs += [f"v{v}", v] if not v.startswith("v") else [v, v[1:]]
        refs.append("HEAD")
        tried = []
        for owner, repo in addon.github_candidates():
            for ref in refs:
                tried.append(f"{owner}/{repo}@{ref}")
                cached = _load_cache(ctx, owner, repo, ref, addon.inner_slug)
                if cached is not None:
                    return cached
                tree = await self._tree(ctx, owner, repo, ref)
                if tree is None:
                    continue
                found = find_addon_dir(tree, addon.inner_slug)
                if found is None:
                    continue
                path, config = found
                src = AddonSource(owner, repo, ref, path, path.relative_to(tree).as_posix() or ".", config)
                return await asyncio.to_thread(_store_cache, ctx, src, addon.inner_slug)
        raise SourceNotFoundError(f"slug '{addon.inner_slug}' não encontrado em {', '.join(tried)}")

    async def _tree(self, ctx: ScanContext, owner: str, repo: str, ref: str) -> Path | None:
        key = (owner, repo, ref)
        if key in self._trees:
            return self._trees[key]
        missing = _cache_root(ctx) / (_SAFE.sub("_", f"{owner}__{repo}__{ref}") + ".missing")
        try:
            if time.time() - missing.stat().st_mtime < MISSING_TTL:
                self._trees[key] = None
                return None
        except OSError:
            pass
        work = ctx.workdir / "addon-src" / _SAFE.sub("_", f"{owner}_{repo}_{ref}")
        shutil.rmtree(work, ignore_errors=True)
        work.mkdir(parents=True)
        archive = work / "src.tar.gz"
        try:
            await ctx.http.download(f"https://codeload.github.com/{owner}/{repo}/tar.gz/{ref}", archive)
        except HttpError as err:
            if err.status != 404:
                raise
            missing.parent.mkdir(parents=True, exist_ok=True)
            missing.touch()
            self._trees[key] = None
            return None
        out = work / "src"
        await asyncio.to_thread(extract, archive, out)
        archive.unlink(missing_ok=True)
        tops = [p for p in out.iterdir() if p.is_dir()]
        tree = tops[0] if len(tops) == 1 else out
        self._trees[key] = tree
        return tree


# --- Funções auxiliares (testáveis isoladamente) --------------------------------


def find_addon_dir(tree: Path, inner_slug: str, max_depth: int = 4) -> tuple[Path, dict[str, Any]] | None:
    """Procura a pasta cujo config.(yaml|yml|json) declara ``slug: inner_slug``."""
    for depth in range(max_depth + 1):
        pattern = "/".join(["*"] * depth)
        for name in _CONFIG_NAMES:
            for cfg in sorted(tree.glob(f"{pattern}/{name}" if pattern else name)):
                if cfg.is_symlink() or not cfg.is_file():
                    continue
                data = _parse_config(cfg)
                if data and str(data.get("slug", "")) == inner_slug:
                    return cfg.parent, data
    return None


def _parse_config(path: Path) -> dict[str, Any] | None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        data = json.loads(text) if path.suffix == ".json" else yaml.safe_load(text)
    except (OSError, ValueError, yaml.YAMLError):
        return None
    return data if isinstance(data, dict) else None


def select_files(root: Path) -> list[Path]:
    files, _links = walk_files(root)
    out = []
    for f in files:
        rel = f.relative_to(root)
        if any(part in _SKIP_DIRS for part in rel.parts):
            continue
        if f.name.lower().endswith(_BINARY_SUFFIXES) or f.suffix.lower() in (".md", ".txt"):
            continue
        try:
            if f.stat().st_size > MAX_SOURCE_FILE:
                continue
            with f.open("rb") as fh:
                if b"\x00" in fh.read(4096):
                    continue
        except OSError:
            continue
        out.append(f)
    return out


def parse_map(entries: Any) -> list[tuple[str, bool]]:
    """Normaliza o ``map`` do config.yaml para [(tipo, somente_leitura)]."""
    out: list[tuple[str, bool]] = []
    for item in entries or []:
        if isinstance(item, str):
            kind, _, mode = item.partition(":")
            out.append((kind.strip(), mode.strip() != "rw"))
        elif isinstance(item, dict) and item.get("type"):
            out.append((str(item["type"]), item.get("read_only", True) is not False))
    return out


def evaluate_map(addon: AddonInfo, src: AddonSource) -> list[Finding]:
    out = []
    for kind, read_only in parse_map(src.config.get("map")):
        risk = _MAP_RISK.get(kind)
        if not risk:
            continue
        sev = risk[1] if read_only else risk[0]
        if sev is None:
            continue
        mode = "somente leitura" if read_only else "leitura e escrita"
        out.append(Finding(
            component=addon.slug,
            component_type=ComponentType.ADDON,
            category="permissao",
            rule_id=f"auditor.addon.map-{kind.replace('_', '-')}-{'ro' if read_only else 'rw'}",
            severity=sev,
            title=f"Acesso a '{kind}' ({mode})",
            explanation=f"O add-on monta {risk[2]}, em modo {mode}.",
            recommendation=(
                "Confirme que a função do add-on justifica esse acesso (ex.: editor de arquivos, backup)."
            ),
            file=f"{src.label}:{src.rel}/config.yaml",
            snippet=f"map: {kind}:{'ro' if read_only else 'rw'}",
            source="codigo-fonte",
        ))
    return out


def _version_note(addon: AddonInfo, src: AddonSource) -> list[Finding]:
    declared = str(src.config.get("version", "")) or None
    if not addon.version or declared == addon.version:
        return []
    return [Finding(
        component=addon.slug,
        component_type=ComponentType.ADDON,
        category="analise_incompleta",
        rule_id="auditor.addon.fonte-versao-diferente",
        severity=Severity.INFO,
        title="Código analisado é de outra versão",
        explanation=(
            f"O repositório não tem uma tag da versão instalada ({addon.version}); foi analisado {src.label}, "
            f"que declara a versão {declared or 'desconhecida'}. Os achados de código podem não "
            "corresponder exatamente ao que está instalado."
        ),
        recommendation="Nenhuma ação obrigatória; atualize o add-on para alinhar as versões.",
        file=f"{src.label}:{src.rel}/config.yaml",
        source="codigo-fonte",
        extra={"fingerprint_key": f"{addon.version}|{declared}"},
    )]


def _from_semgrep(r: dict[str, Any], roots: list[tuple[Path, AddonInfo, AddonSource]]) -> Finding | None:
    path = Path(r["path"])
    owner = next(((a, s) for root, a, s in roots if path.is_relative_to(root)), None)
    if owner is None:
        return None
    addon, src = owner
    meta = (r.get("extra") or {}).get("metadata") or {}
    check_id = str(r.get("check_id", ""))
    rule_id = check_id[check_id.find("auditor."):] if "auditor." in check_id else check_id
    start, end = r.get("start") or {}, r.get("end") or {}
    rel = path.relative_to(src.root).as_posix()
    return Finding(
        component=addon.slug,
        component_type=ComponentType.ADDON,
        category=str(meta.get("categoria", "semgrep")),
        rule_id=rule_id,
        severity=SEVERITY_BY_LABEL.get(str(meta.get("severidade", "media")), Severity.MEDIUM),
        title=str(meta.get("titulo") or rule_id),
        explanation=" ".join(str(meta.get("explicacao", "")).split()),
        recommendation=" ".join(str(meta.get("recomendacao", "Revise o trecho.")).split()),
        file=f"{src.label}:{src.rel}/{rel}",
        line=start.get("line"),
        snippet=read_snippet(path, start.get("line"), end.get("line"), start.get("col"), end.get("col")),
        source="semgrep",
        # O ref (HEAD/tag) muda com o tempo; a identidade do achado usa só o caminho.
        extra={"fingerprint_key": f"{src.owner}/{src.repo}:{src.rel}/{rel}"},
    )


def _info(addon: AddonInfo, rule: str, title: str, why: str, key: str) -> Finding:
    return Finding(
        component=addon.slug, component_type=ComponentType.ADDON, category="analise_incompleta",
        rule_id=rule, severity=Severity.INFO, title=title, explanation=why,
        recommendation="Nenhuma ação obrigatória; a imagem continua coberta pelo Trivy.",
        source="codigo-fonte", extra={"fingerprint_key": key},
    )


# --- Cache em /data --------------------------------------------------------------


def _cache_root(ctx: ScanContext) -> Path:
    return ctx.paths.cache_dir / "addon-src"


def _cache_dir(ctx: ScanContext, owner: str, repo: str, ref: str, inner: str) -> Path:
    return _cache_root(ctx) / _SAFE.sub("_", f"{owner}__{repo}__{ref}__{inner}")


def _load_cache(ctx: ScanContext, owner: str, repo: str, ref: str, inner: str) -> AddonSource | None:
    d = _cache_dir(ctx, owner, repo, ref, inner)
    try:
        meta = json.loads((d / "meta.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    ttl = HEAD_TTL if ref == "HEAD" else TAG_TTL
    if time.time() - float(meta.get("created", 0)) > ttl:
        shutil.rmtree(d, ignore_errors=True)
        return None
    return AddonSource(owner, repo, ref, d / "files", meta.get("rel", "."), meta.get("config") or {})


def _store_cache(ctx: ScanContext, src: AddonSource, inner: str) -> AddonSource:
    d = _cache_dir(ctx, src.owner, src.repo, src.ref, inner)
    tmp = d.with_name(d.name + ".tmp")
    shutil.rmtree(tmp, ignore_errors=True)
    shutil.copytree(src.root, tmp / "files", symlinks=True)
    (tmp / "meta.json").write_text(
        json.dumps({"created": time.time(), "rel": src.rel, "config": src.config}, default=str), encoding="utf-8"
    )
    shutil.rmtree(d, ignore_errors=True)
    tmp.rename(d)
    return AddonSource(src.owner, src.repo, src.ref, d / "files", src.rel, src.config)
