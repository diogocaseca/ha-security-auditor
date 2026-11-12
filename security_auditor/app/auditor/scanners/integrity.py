"""Integridade: compara a integração instalada com a release oficial no GitHub.

Para cada integração com repositório identificável:
 1. descobre a versão instalada (HACS > manifest.json);
 2. baixa o tarball dessa tag (codeload, não conta no limite da API);
    se o hacs.json usa ``zip_release``, baixa o asset da release;
 3. monta a pasta que o HACS instalaria e compara arquivo a arquivo (SHA-256).

Arquivo alterado ou extra = achado ALTO. A pasta de referência fica em
cache em /data/cache/integrity para as próximas varreduras.
"""

from __future__ import annotations

import asyncio
import difflib
import hashlib
import json
import logging
import re
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import aiohttp

from ..inventory import Component, Inventory, walk_files
from ..models import ComponentType, Finding, Severity
from ..net import DownloadTooLargeError, EgressDeniedError, HttpError
from ..safe_archive import UnsafeArchiveError, extract
from .base import ScanContext

_LOGGER = logging.getLogger(__name__)

CACHE_TTL = 30 * 24 * 3600
MISSING_TTL = 24 * 3600  # tag inexistente: não tenta de novo por um dia
_SAFE_NAME = re.compile(r"[^A-Za-z0-9_.-]+")
_COMMITISH = re.compile(r"^[0-9a-f]{7,40}$")
_MAX_DIFF_LINES = 30


class NotVerifiableError(Exception):
    """A integridade não pôde ser verificada (motivo em português na mensagem)."""


@dataclass
class Upstream:
    ref: str
    root: Path  # pasta equivalente ao que o HACS instala
    persistent_directory: str | None = None
    source: str = "tarball"  # tarball | zip_release


def candidate_refs(comp: Component) -> list[str]:
    """Refs do GitHub a tentar, na ordem: versão do HACS, commit, versão do manifest."""
    refs: list[str] = []

    def add_version(v: str | None) -> None:
        if not v:
            return
        v = v.strip()
        if _COMMITISH.match(v):
            refs.append(v)
            return
        refs.append(v)
        refs.append(v[1:] if v.startswith("v") else f"v{v}")

    if comp.hacs:
        add_version(comp.hacs.version_installed)
        if comp.hacs.installed_commit:
            refs.append(comp.hacs.installed_commit)
    add_version(str(comp.manifest.get("version")) if comp.manifest.get("version") else None)
    return list(dict.fromkeys(r for r in refs if r and "/" not in r and ".." not in r))


def hash_tree(root: Path, exclude_prefix: str | None = None) -> dict[str, str]:
    """SHA-256 de cada arquivo regular, sem seguir links simbólicos."""
    out: dict[str, str] = {}
    files, _links = walk_files(root)
    for path in files:
        rel_s = path.relative_to(root).as_posix()
        if exclude_prefix and (rel_s == exclude_prefix or rel_s.startswith(exclude_prefix.rstrip("/") + "/")):
            continue
        out[rel_s] = sha256_file(path)
    return out


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


class IntegrityScanner:
    name = "integridade"

    async def scan(self, ctx: ScanContext) -> list[Finding]:
        inv: Inventory = ctx.inventory()
        findings: list[Finding] = []
        for n, comp in enumerate(inv.integrations):
            if n:
                await ctx.pause()
            ctx.set_progress(self.name, comp.name)
            try:
                found, status = await self._check(ctx, inv, comp)
                findings.extend(found)
            except NotVerifiableError as err:
                status = f"não verificada: {err}"
                findings.append(_not_verified(comp, str(err)))
            except (HttpError, EgressDeniedError, DownloadTooLargeError, UnsafeArchiveError,
                    aiohttp.ClientError, TimeoutError, OSError, json.JSONDecodeError) as err:
                reason = _describe_error(err)
                status = f"não verificada: {reason}"
                findings.append(_not_verified(comp, reason))
            ctx.register_component(comp.component_type, comp.name, integridade=status)
        return findings

    async def _check(self, ctx: ScanContext, inv: Inventory, comp: Component) -> tuple[list[Finding], str]:
        repo = comp.github_repo()
        if repo is None:
            return [_unknown_origin(comp)], "sem repositório identificável"
        refs = candidate_refs(comp)
        if not refs:
            raise NotVerifiableError("versão instalada desconhecida (sem HACS e sem 'version' no manifest)")
        upstream = await self._fetch_upstream(ctx, repo, refs, comp.name)

        local = hash_tree(comp.path, upstream.persistent_directory)
        remote = hash_tree(upstream.root)
        findings: list[Finding] = []
        for rel in sorted(set(local) | set(remote)):
            if rel in local and rel not in remote:
                findings.append(self._extra(comp, inv, rel, upstream, repo))
            elif rel in remote and rel not in local:
                findings.append(self._missing(comp, rel, upstream, repo))
            elif local[rel] != remote[rel]:
                findings.append(self._modified(comp, inv, rel, upstream, repo))
        status = f"verificada contra {repo[0]}/{repo[1]}@{upstream.ref}"
        if findings:
            status += f" ({len(findings)} diferença(s))"
        return findings, status

    # --- Download / cache ---------------------------------------------------

    async def _fetch_upstream(self, ctx: ScanContext, repo: tuple[str, str], refs: list[str], domain: str) -> Upstream:
        owner, name = repo
        cache_root = ctx.paths.cache_dir / "integrity"
        last_error: str | None = None
        for ref in refs:
            key = _SAFE_NAME.sub("_", f"{owner}__{name}__{ref}__{domain}")
            cached = cache_root / key
            meta_file = cached / "meta.json"
            missing = cache_root / f"{key}.missing"
            try:
                if time.time() - missing.stat().st_mtime < MISSING_TTL:
                    last_error = f"tag/commit '{ref}' não encontrado"
                    continue
            except OSError:
                pass
            if meta_file.is_file():
                try:
                    meta = json.loads(meta_file.read_text(encoding="utf-8"))
                    if time.time() - float(meta.get("created", 0)) < CACHE_TTL:
                        return Upstream(ref=ref, root=cached / "files",
                                        persistent_directory=meta.get("persistent_directory"),
                                        source=meta.get("source", "tarball"))
                except (OSError, ValueError, json.JSONDecodeError):
                    pass
                shutil.rmtree(cached, ignore_errors=True)
            try:
                up = await self._download(ctx, owner, name, ref, domain)
            except HttpError as err:
                if err.status == 404:
                    last_error = f"tag/commit '{ref}' não encontrado"
                    cache_root.mkdir(parents=True, exist_ok=True)
                    missing.touch()
                    continue
                raise
            # Guarda no cache só a pasta da integração (pequena).
            tmp = cache_root / f".{key}.tmp"
            shutil.rmtree(tmp, ignore_errors=True)
            await asyncio.to_thread(shutil.copytree, up.root, tmp / "files", symlinks=True)
            (tmp / "meta.json").write_text(
                json.dumps({"created": time.time(), "ref": ref, "persistent_directory": up.persistent_directory,
                            "source": up.source}),
                encoding="utf-8",
            )
            shutil.rmtree(cached, ignore_errors=True)
            tmp.rename(cached)
            return Upstream(ref=ref, root=cached / "files", persistent_directory=up.persistent_directory,
                            source=up.source)
        raise NotVerifiableError(
            f"nenhuma versão correspondente em {owner}/{name} ({last_error or 'sem refs'}; tentado: {', '.join(refs)})"
        )

    async def _download(self, ctx: ScanContext, owner: str, name: str, ref: str, domain: str) -> Upstream:
        work = ctx.workdir / "integrity" / _SAFE_NAME.sub("_", f"{owner}_{name}_{ref}")
        shutil.rmtree(work, ignore_errors=True)
        work.mkdir(parents=True)
        tarball = work / "src.tar.gz"
        await ctx.http.download(f"https://codeload.github.com/{owner}/{name}/tar.gz/{ref}", tarball)
        src = work / "src"
        await asyncio.to_thread(extract, tarball, src)
        tops = [p for p in src.iterdir() if p.is_dir()]
        if len(tops) != 1:
            raise NotVerifiableError("estrutura inesperada no tarball do GitHub")
        repo_root = tops[0]
        hacs = _read_json(repo_root / "hacs.json")
        persistent = str(hacs.get("persistent_directory")) if hacs.get("persistent_directory") else None

        if hacs.get("zip_release") and hacs.get("filename"):
            root = await self._zip_release(ctx, owner, name, ref, str(hacs["filename"]), work, domain)
            return Upstream(ref=ref, root=root, persistent_directory=persistent, source="zip_release")

        if hacs.get("content_in_root"):
            return Upstream(ref=ref, root=repo_root, persistent_directory=persistent)
        root = repo_root / "custom_components" / domain
        if not root.is_dir():
            root = _find_by_domain(repo_root / "custom_components", domain)
        if root is None:
            raise NotVerifiableError(f"o repositório não contém custom_components/{domain} nesta versão")
        return Upstream(ref=ref, root=root, persistent_directory=persistent)

    async def _zip_release(self, ctx: ScanContext, owner: str, name: str, ref: str, filename: str,
                           work: Path, domain: str) -> Path:
        release = await ctx.http.get_json(f"https://api.github.com/repos/{owner}/{name}/releases/tags/{ref}")
        asset = next((a for a in release.get("assets", []) if a.get("name") == filename), None)
        if not asset:
            raise NotVerifiableError(f"release {ref} não tem o arquivo {filename} indicado no hacs.json")
        archive = work / "release.zip"
        await ctx.http.download(str(asset["browser_download_url"]), archive)
        out = work / "release"
        await asyncio.to_thread(extract, archive, out)
        nested = out / "custom_components" / domain
        return nested if nested.is_dir() else out

    # --- Achados -------------------------------------------------------------

    def _modified(self, comp: Component, inv: Inventory, rel: str, up: Upstream, repo: tuple[str, str]) -> Finding:
        diff = _diff(up.root / rel, comp.path / rel)
        return Finding(
            component=comp.name,
            component_type=ComponentType.INTEGRATION,
            category="integridade",
            rule_id="auditor.integridade.arquivo-alterado",
            severity=Severity.HIGH,
            title="Arquivo diferente da release oficial",
            explanation=(
                f"O arquivo instalado não é igual ao da versão {up.ref} publicada em {repo[0]}/{repo[1]}. "
                "Pode ser uma edição sua, mas também pode indicar adulteração depois da instalação "
                "ou um pacote de origem diferente da anunciada."
            ),
            recommendation=(
                "Compare as diferenças abaixo. Se você não editou o arquivo, reinstale a integração pelo HACS "
                "e investigue como ele foi alterado."
            ),
            file=f"{comp.rel_path}/{rel}",
            snippet=diff,
            source="integridade",
            extra={"ref": up.ref, "repositorio": f"{repo[0]}/{repo[1]}"},
        )

    def _extra(self, comp: Component, inv: Inventory, rel: str, up: Upstream, repo: tuple[str, str]) -> Finding:
        return Finding(
            component=comp.name,
            component_type=ComponentType.INTEGRATION,
            category="integridade",
            rule_id="auditor.integridade.arquivo-extra",
            severity=Severity.HIGH,
            title="Arquivo que não existe na release oficial",
            explanation=(
                f"Este arquivo não faz parte da versão {up.ref} de {repo[0]}/{repo[1]}. Arquivos extras "
                "podem ser código injetado depois da instalação. Algumas integrações gravam dados na "
                "própria pasta; nesse caso, adicione uma exceção."
            ),
            recommendation="Abra o arquivo e veja o que ele contém e se algo o importa.",
            file=f"{comp.rel_path}/{rel}",
            snippet=_head(comp.path / rel),
            source="integridade",
            extra={"ref": up.ref, "repositorio": f"{repo[0]}/{repo[1]}"},
        )

    def _missing(self, comp: Component, rel: str, up: Upstream, repo: tuple[str, str]) -> Finding:
        return Finding(
            component=comp.name,
            component_type=ComponentType.INTEGRATION,
            category="integridade",
            rule_id="auditor.integridade.arquivo-ausente",
            severity=Severity.LOW,
            title="Arquivo da release oficial ausente",
            explanation=f"O arquivo existe na versão {up.ref} de {repo[0]}/{repo[1]}, mas não está instalado.",
            recommendation="Normalmente inofensivo; se a integração falhar, reinstale pelo HACS.",
            file=f"{comp.rel_path}/{rel}",
            source="integridade",
        )


def _not_verified(comp: Component, reason: str) -> Finding:
    return Finding(
        component=comp.name,
        component_type=ComponentType.INTEGRATION,
        category="integridade",
        rule_id="auditor.integridade.nao-verificada",
        severity=Severity.INFO,
        title="Integridade não verificada",
        explanation=f"Não foi possível comparar com a release oficial: {reason}.",
        recommendation=(
            "Se a integração foi instalada de um branch (sem release), isso é esperado. Caso contrário, "
            "confira se a versão instalada existe no repositório."
        ),
        file=comp.rel_path,
        source="integridade",
        extra={"fingerprint_key": reason[:80]},
    )


def _unknown_origin(comp: Component) -> Finding:
    return Finding(
        component=comp.name,
        component_type=ComponentType.INTEGRATION,
        category="integridade",
        rule_id="auditor.integridade.origem-desconhecida",
        severity=Severity.LOW,
        title="Integração sem origem identificável",
        explanation=(
            "A integração não foi instalada pelo HACS e o manifest.json não aponta um repositório no "
            "GitHub, então não há uma versão oficial para comparar."
        ),
        recommendation="Confirme de onde a integração veio. Se possível, instale pelo HACS.",
        file=comp.rel_path,
        source="integridade",
    )


def _describe_error(err: Exception) -> str:
    if isinstance(err, HttpError) and err.status in (403, 429):
        return "limite de requisições do GitHub atingido (configure github_token nas opções)"
    if isinstance(err, HttpError):
        return f"GitHub respondeu HTTP {err.status}"
    if isinstance(err, EgressDeniedError):
        return f"destino bloqueado pela allowlist de rede ({err})"
    if isinstance(err, UnsafeArchiveError):
        return f"arquivo baixado rejeitado por segurança ({err})"
    if isinstance(err, DownloadTooLargeError):
        return "download grande demais"
    if isinstance(err, TimeoutError):
        return "tempo esgotado no download"
    return f"{type(err).__name__}"


def _read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _find_by_domain(cc: Path, domain: str) -> Path | None:
    if not cc.is_dir():
        return None
    for d in cc.iterdir():
        if d.is_dir() and _read_json(d / "manifest.json").get("domain") == domain:
            return d
    return None


def _read_text(path: Path) -> list[str] | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:8192]:
        return None
    try:
        return data.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        return None


def _diff(upstream: Path, local: Path) -> str:
    a, b = _read_text(upstream), _read_text(local)
    if a is None or b is None:
        return "(arquivo binário: conteúdo diferente)"
    lines = list(difflib.unified_diff(a, b, "release oficial", "instalado", n=1, lineterm=""))
    if len(lines) > _MAX_DIFF_LINES:
        lines = lines[:_MAX_DIFF_LINES] + [f"… (+{len(lines) - _MAX_DIFF_LINES} linhas)"]
    return "\n".join(line[:240] for line in lines) or "(diferença só em espaços ou fim de linha)"


def _head(path: Path, n: int = 12) -> str:
    lines = _read_text(path)
    if lines is None:
        return "(arquivo binário)"
    out = [line[:240] for line in lines[:n]]
    if len(lines) > n:
        out.append(f"… (+{len(lines) - n} linhas)")
    return "\n".join(out)
