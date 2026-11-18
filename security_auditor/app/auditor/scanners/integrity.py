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

from ..i18n import Bi, english
from ..inventory import Component, Inventory, walk_files
from ..models import ComponentType, Finding, Severity, en_text
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
    """A integridade não pôde ser verificada (motivo em português na mensagem; ``en`` em inglês)."""

    def __init__(self, message: str, en: str | None = None) -> None:
        super().__init__(message)
        self.en = en or message


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
                status = Bi(f"não verificada: {err}", f"not verified: {err.en}")
                findings.append(_not_verified(comp, str(err), err.en))
            except (HttpError, EgressDeniedError, DownloadTooLargeError, UnsafeArchiveError,
                    aiohttp.ClientError, TimeoutError, OSError, json.JSONDecodeError) as err:
                reason, reason_en = _describe_error(err)
                status = Bi(f"não verificada: {reason}", f"not verified: {reason_en}")
                findings.append(_not_verified(comp, reason, reason_en))
            ctx.register_component(comp.component_type, comp.name, integridade=str(status),
                                   integridade_en=english(status))
        for comp in inv.frontend:
            if comp.name == "www":
                continue  # resto da pasta www/ (fotos, arquivos do usuário): não vem do HACS
            await ctx.pause()
            ctx.set_progress(self.name, comp.name)
            found, status = await self._check_card(ctx, comp)
            findings.extend(found)
            ctx.register_component(comp.component_type, comp.name, integridade=str(status),
                                   integridade_en=english(status))
        return findings

    async def _check_card(self, ctx: ScanContext, comp: Component) -> tuple[list[Finding], Bi]:
        """Card do HACS: compara com a versão registrada pelo HACS (anexos da release, dist/ ou raiz)."""
        from .card_integrity import CardNotVerifiable, card_refs, compare_card, fetch_card_sources

        if comp.hacs is None or "/" not in comp.hacs.full_name:
            return [], Bi("não verificada: card sem registro no HACS", "not verified: card not registered in HACS")
        refs = card_refs(comp)
        if not refs:
            return [], Bi("não verificada: o HACS não registrou a versão", "not verified: HACS did not record the version")
        owner, name = comp.hacs.owner_repo
        try:
            ref, sources = await fetch_card_sources(ctx, owner, name, refs)
            found = await asyncio.to_thread(compare_card, comp, sources, ref, f"{owner}/{name}", _diff)
        except CardNotVerifiable as err:
            return [], Bi(f"não verificada: {err}", f"not verified: {err.en}")
        except (HttpError, EgressDeniedError, DownloadTooLargeError, UnsafeArchiveError,
                aiohttp.ClientError, TimeoutError, OSError, json.JSONDecodeError) as err:
            reason, reason_en = _describe_error(err)
            return [], Bi(f"não verificada: {reason}", f"not verified: {reason_en}")
        status = f"verificada contra {owner}/{name}@{ref}"
        status_en = f"verified against {owner}/{name}@{ref}"
        if found:
            status += f" ({len(found)} diferença(s))"
            status_en += f" ({len(found)} difference(s))"
        return found, Bi(status, status_en)

    async def _check(self, ctx: ScanContext, inv: Inventory, comp: Component) -> tuple[list[Finding], str]:
        repo = comp.github_repo()
        if repo is None:
            return [_unknown_origin(comp)], Bi("sem repositório identificável", "no identifiable repository")
        refs = candidate_refs(comp)
        if not refs:
            raise NotVerifiableError("versão instalada desconhecida (sem HACS e sem 'version' no manifest)",
                                     "installed version unknown (no HACS and no 'version' in the manifest)")
        upstream = await self._fetch_upstream(ctx, repo, refs, comp.name)

        local = hash_tree(comp.path, upstream.persistent_directory)
        remote = hash_tree(upstream.root)
        if local != remote:
            # Os arquivos não batem com a versão de referência. Antes de alertar, vê se são de outra versão
            # publicada pelo autor: uma release mais nova (manifest esquecido ou HACS desatualizado) ou o
            # branch principal (instalação beta). Se forem idênticos, não houve adulteração.
            from_hacs = _version_from_hacs(comp)
            newer = await self._match_newer_release(ctx, repo, comp, upstream.ref)
            kind = "release"
            if newer is None:
                newer, kind = await self._match_default_branch(ctx, repo, comp), "branch"
            if newer is not None:
                said = "o HACS registrou" if from_hacs else "o manifest diz"
                said_en = "HACS recorded" if from_hacs else "the manifest says"
                status = f"verificada contra {repo[0]}/{repo[1]}@{newer} ({said} {upstream.ref})"
                status_en = f"verified against {repo[0]}/{repo[1]}@{newer} ({said_en} {upstream.ref})"
                if not from_hacs and kind == "release":
                    return [_stale_manifest(comp, repo, newer, upstream.ref)], Bi(status, status_en)
                return [_other_version(comp, repo, newer, upstream.ref, kind, from_hacs)], Bi(status, status_en)
        findings: list[Finding] = []
        for rel in sorted(set(local) | set(remote)):
            if rel in local and rel not in remote:
                findings.append(self._extra(comp, inv, rel, upstream, repo))
            elif rel in remote and rel not in local:
                findings.append(self._missing(comp, rel, upstream, repo))
            elif local[rel] != remote[rel]:
                findings.append(self._modified(comp, inv, rel, upstream, repo))
        status = f"verificada contra {repo[0]}/{repo[1]}@{upstream.ref}"
        status_en = f"verified against {repo[0]}/{repo[1]}@{upstream.ref}"
        if findings:
            status += f" ({len(findings)} diferença(s))"
            status_en += f" ({len(findings)} difference(s))"
        return findings, Bi(status, status_en)

    async def _match_default_branch(self, ctx: ScanContext, repo: tuple[str, str], comp: Component) -> str | None:
        """Nome do branch principal, se os arquivos instalados forem idênticos aos dele."""
        owner, name = repo
        try:
            info = await _cached_json(ctx, f"https://api.github.com/repos/{owner}/{name}")
            branch = str((info or {}).get("default_branch") or "")
            if not branch or "/" in branch or ".." in branch:
                return None
            up = await self._fetch_upstream(ctx, repo, [branch], comp.name, ttl=BRANCH_TTL)
        except (NotVerifiableError, HttpError, EgressDeniedError, DownloadTooLargeError, UnsafeArchiveError,
                aiohttp.ClientError, TimeoutError, OSError, json.JSONDecodeError, ValueError):
            return None
        if hash_tree(comp.path, up.persistent_directory) == hash_tree(up.root):
            ctx.logger.info("Integridade de %s: arquivos idênticos aos do branch %s de %s/%s", comp.name, branch,
                            owner, name)
            return branch
        return None

    async def _match_newer_release(self, ctx: ScanContext, repo: tuple[str, str], comp: Component,
                                   tried: str) -> str | None:
        """Tag de uma das releases mais recentes cujos arquivos batem exatamente com os instalados."""
        owner, name = repo
        try:
            releases = await _cached_json(ctx, f"https://api.github.com/repos/{owner}/{name}/releases?per_page=10") or []
        except (HttpError, EgressDeniedError, aiohttp.ClientError, TimeoutError, ValueError) as err:
            ctx.logger.debug("Releases de %s/%s indisponíveis: %s", owner, name, type(err).__name__)
            return None
        skip = {tried, tried[1:] if tried.startswith("v") else f"v{tried}"}
        tags = [str(r.get("tag_name") or "") for r in releases if isinstance(r, dict) and not r.get("draft")]
        tags = [t for t in tags if t and t not in skip and "/" not in t and ".." not in t][:NEWER_RELEASES]
        for tag in tags:
            try:
                up = await self._fetch_upstream(ctx, repo, [tag], comp.name)
            except (NotVerifiableError, HttpError, EgressDeniedError, DownloadTooLargeError, UnsafeArchiveError,
                    aiohttp.ClientError, TimeoutError, OSError, json.JSONDecodeError):
                continue
            if hash_tree(comp.path, up.persistent_directory) == hash_tree(up.root):
                ctx.logger.info("Integridade de %s: arquivos idênticos aos de %s/%s@%s (o manifest diz %s)",
                                comp.name, owner, name, tag, tried)
                return tag
        return None

    # --- Download / cache ---------------------------------------------------

    async def _fetch_upstream(self, ctx: ScanContext, repo: tuple[str, str], refs: list[str], domain: str,
                              ttl: float = 0) -> Upstream:
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
                    if time.time() - float(meta.get("created", 0)) < (ttl or CACHE_TTL):
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
            f"nenhuma versão correspondente em {owner}/{name} ({last_error or 'sem refs'}; tentado: {', '.join(refs)})",
            f"no matching version in {owner}/{name} (tried: {', '.join(refs)})",
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
            raise NotVerifiableError("estrutura inesperada no tarball do GitHub", "unexpected GitHub tarball layout")
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
            raise NotVerifiableError(f"o repositório não contém custom_components/{domain} nesta versão",
                                     f"the repository does not contain custom_components/{domain} in this version")
        return Upstream(ref=ref, root=root, persistent_directory=persistent)

    async def _zip_release(self, ctx: ScanContext, owner: str, name: str, ref: str, filename: str,
                           work: Path, domain: str) -> Path:
        release = await ctx.http.get_json(f"https://api.github.com/repos/{owner}/{name}/releases/tags/{ref}")
        asset = next((a for a in release.get("assets", []) if a.get("name") == filename), None)
        if not asset:
            raise NotVerifiableError(f"release {ref} não tem o arquivo {filename} indicado no hacs.json",
                                     f"release {ref} does not have the file {filename} named in hacs.json")
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
            en=en_text(
                "File differs from the official release",
                f"The installed file is not the same as in version {up.ref} published at {repo[0]}/{repo[1]}. "
                "It may be your own edit, but it can also point to tampering after installation or to a package "
                "from a different source than advertised.",
                "Compare the differences below. If you did not edit the file, reinstall the integration from HACS "
                "and investigate how it was changed.",
            ),
            file=f"{comp.rel_path}/{rel}",
            snippet=diff,
            source="integridade",
            extra={"ref": up.ref, "repositorio": f"{repo[0]}/{repo[1]}"},
        )

    def _extra(self, comp: Component, inv: Inventory, rel: str, up: Upstream, repo: tuple[str, str]) -> Finding:
        code = rel.lower().endswith(_CODE_SUFFIXES) or "." not in rel.rsplit("/", 1)[-1]
        return Finding(
            component=comp.name,
            component_type=ComponentType.INTEGRATION,
            category="integridade",
            rule_id="auditor.integridade.arquivo-extra",
            # Código (ou arquivo sem extensão, que pode ser executável) = Alta; dados e textos = Baixa.
            severity=Severity.HIGH if code else Severity.LOW,
            title="Arquivo que não existe na release oficial",
            explanation=(
                f"Este arquivo não faz parte da versão {up.ref} de {repo[0]}/{repo[1]}. Arquivos extras "
                "podem ser código injetado depois da instalação. Algumas integrações gravam dados na "
                "própria pasta; nesse caso, adicione uma exceção."
            ),
            recommendation="Abra o arquivo e veja o que ele contém e se algo o importa.",
            en=en_text(
                "File not present in the official release",
                f"This file is not part of version {up.ref} of {repo[0]}/{repo[1]}. Extra files may be code "
                "injected after installation. Some integrations write data into their own folder; in that case, "
                "add an exception.",
                "Open the file to see what it contains and whether anything imports it.",
            ),
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
            en=en_text("File from the official release is missing",
                       f"The file exists in version {up.ref} of {repo[0]}/{repo[1]} but is not installed.",
                       "Usually harmless; if the integration fails, reinstall it from HACS."),
            file=f"{comp.rel_path}/{rel}",
            source="integridade",
        )


def _not_verified(comp: Component, reason: str, reason_en: str | None = None) -> Finding:
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
        en=en_text(
            "Integrity not verified",
            f"It was not possible to compare with the official release: {reason_en or reason}.",
            "If the integration was installed from a branch (no release), this is expected. Otherwise, check "
            "that the installed version exists in the repository.",
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
        en=en_text(
            "Integration with no identifiable source",
            "The integration was not installed through HACS and its manifest.json does not point to a GitHub "
            "repository, so there is no official version to compare with.",
            "Confirm where the integration came from. If possible, install it through HACS.",
        ),
        file=comp.rel_path,
        source="integridade",
    )


def _describe_error(err: Exception) -> tuple[str, str]:
    """Motivo da falha em (português, inglês)."""
    if isinstance(err, HttpError) and err.status in (403, 429):
        return ("limite de requisições do GitHub atingido (configure github_token nas opções)",
                "GitHub rate limit reached (set github_token in the options)")
    if isinstance(err, HttpError):
        return f"GitHub respondeu HTTP {err.status}", f"GitHub answered HTTP {err.status}"
    if isinstance(err, EgressDeniedError):
        return f"destino bloqueado pela allowlist de rede ({err})", f"destination blocked by the network allowlist ({err})"
    if isinstance(err, UnsafeArchiveError):
        return f"arquivo baixado rejeitado por segurança ({err})", f"downloaded archive rejected for safety ({err})"
    if isinstance(err, DownloadTooLargeError):
        return "download grande demais", "download too large"
    if isinstance(err, TimeoutError):
        return "tempo esgotado no download", "download timed out"
    return type(err).__name__, type(err).__name__


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


NEWER_RELEASES = 5  # releases mais recentes testadas quando o manifest parece desatualizado


def _version_from_hacs(comp: Component) -> bool:
    """True se o HACS sabe a versão (ou o commit) instalada: a referência não veio do manifest."""
    return bool(comp.hacs and (comp.hacs.version_installed or comp.hacs.installed_commit))


def _stale_manifest(comp: Component, repo: tuple[str, str], tag: str, manifest_ref: str) -> Finding:
    return Finding(
        component=comp.name,
        component_type=ComponentType.INTEGRATION,
        category="integridade",
        rule_id="auditor.integridade.manifest-desatualizado",
        severity=Severity.INFO,
        title="Versão do manifest desatualizada",
        explanation=(
            f"Os arquivos instalados são idênticos aos da versão {tag} publicada em {repo[0]}/{repo[1]}, mas o "
            f"manifest.json declara {manifest_ref}. É um descuido comum do autor (esquecer de atualizar o "
            f"\"version\"); a integridade foi confirmada contra {tag}."
        ),
        recommendation="Nada a fazer. Se quiser, avise o autor para atualizar o \"version\" do manifest.json.",
        en=en_text(
            "Manifest version is out of date",
            f"The installed files are identical to version {tag} published at {repo[0]}/{repo[1]}, but "
            f"manifest.json says {manifest_ref}. This is a common oversight by the author (forgetting to update "
            f"\"version\"); integrity was confirmed against {tag}.",
            "Nothing to do. If you like, let the author know so they update \"version\" in manifest.json.",
        ),
        source="integridade",
        extra={"ref": tag, "repositorio": f"{repo[0]}/{repo[1]}", "fingerprint_key": tag},
    )


BRANCH_TTL = 24 * 3600  # o branch muda: a cópia de referência dele vale só um dia
_CODE_SUFFIXES = (".py", ".pyc", ".pyo", ".so", ".pyd", ".js", ".mjs", ".cjs", ".sh", ".bin", ".exe", ".dll")


def _other_version(comp: Component, repo: tuple[str, str], ref: str, recorded: str, kind: str,
                   from_hacs: bool) -> Finding:
    who = "o HACS registrou" if from_hacs else "o manifest.json declara"
    who_en = "HACS recorded" if from_hacs else "manifest.json says"
    where = f"do branch {ref}" if kind == "branch" else f"da versão {ref}"
    where_en = f"of the {ref} branch" if kind == "branch" else f"of version {ref}"
    return Finding(
        component=comp.name,
        component_type=ComponentType.INTEGRATION,
        category="integridade",
        rule_id="auditor.integridade.outra-versao",
        severity=Severity.INFO,
        title="Arquivos de outra versão do repositório oficial",
        explanation=(f"{who[0].upper()}{who[1:]} {recorded}, mas os arquivos instalados são idênticos aos {where} publicada "
                     f"em {repo[0]}/{repo[1]}. É normal ao instalar uma versão beta ou do branch principal; o código é "
                     "o mesmo que o autor publicou."),
        recommendation="Nada a fazer. Se não instalou uma versão beta, reinstale pelo HACS para alinhar a versão.",
        en=en_text("Files from another version of the official repository",
                   f"{who_en[0].upper()}{who_en[1:]} {recorded}, but the installed files are identical to those {where_en} "
                   f"published at {repo[0]}/{repo[1]}. This is normal when installing a beta version or the main "
                   "branch; the code is the same the author published.",
                   "Nothing to do. If you did not install a beta version, reinstall from HACS to align the version."),
        source="integridade",
        extra={"ref": ref, "repositorio": f"{repo[0]}/{repo[1]}", "fingerprint_key": f"{kind}:{ref}"},
    )


LOOKUP_TTL = 24 * 3600


async def _cached_json(ctx: ScanContext, url: str):
    """GET na API do GitHub com cópia guardada por um dia (lista de releases, dados do repositório).

    Evita repetir as mesmas consultas a cada varredura quando um componente não bate com a versão.
    """
    key = hashlib.sha256(url.encode()).hexdigest()[:32]
    path = ctx.paths.cache_dir / "integrity" / "lookups" / f"{key}.json"
    try:
        if time.time() - path.stat().st_mtime < LOOKUP_TTL:
            return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        pass
    try:
        data = await ctx.http.get_json(url)
    except HttpError as err:
        if err.status != 404:
            raise
        data = None  # não existe (repositório sem releases, por exemplo): também fica guardado
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data), encoding="utf-8")
    except OSError:
        pass
    return data
