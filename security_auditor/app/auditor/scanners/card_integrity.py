"""Integridade dos cards do HACS (``www/community/<repo>``) contra a versão publicada no GitHub.

O HACS instala um card de dois jeitos: baixando os arquivos anexados à release (ex.: ``meu-card.js``)
ou copiando ``dist/`` (ou a raiz) do repositório. Depois grava uma cópia ``<arquivo>.js.gz`` de cada
``.js``, e o HA serve o ``.gz`` no lugar do original quando ele existe. Por isso:

- cada arquivo instalado é comparado (SHA-256) com o arquivo de mesmo nome nos anexos da release,
  em ``dist/`` ou na raiz do repositório, na versão que o HACS registrou;
- cada ``.js.gz`` é descompactado e comparado com o ``.js`` correspondente (um ``.gz`` diferente
  trocaria, sem ninguém ver, o código que roda no navegador).

Arquivos da release que não foram instalados não contam: o HACS baixa só parte deles.
"""

from __future__ import annotations

import asyncio
import gzip
import hashlib
import json
import shutil
import time
from pathlib import Path

from ..i18n import Bi
from ..inventory import Component, walk_files
from ..models import ComponentType, Finding, Severity, en_text
from ..net import HttpError
from ..safe_archive import extract
from .base import ScanContext

CACHE_TTL = 30 * 24 * 3600
MISSING_TTL = 24 * 3600
MAX_GZ_BYTES = 64 * 1024 * 1024  # descompactação de .gz limitada (contra "bombas" de compressão)
MAX_SOURCE_FILE = 32 * 1024 * 1024
_CODE_SUFFIXES = (".js", ".mjs", ".cjs")


class CardNotVerifiable(Exception):
    def __init__(self, message: str, en: str) -> None:
        super().__init__(message)
        self.en = en


def card_refs(comp: Component) -> list[str]:
    """Versões a tentar, na ordem: a do HACS (com e sem "v") e o commit gravado por ele."""
    refs: list[str] = []
    if comp.hacs and comp.hacs.version_installed:
        v = comp.hacs.version_installed.strip()
        refs += [v, v[1:] if v.startswith("v") else f"v{v}"]
    if comp.hacs and comp.hacs.installed_commit:
        refs.append(comp.hacs.installed_commit)
    return list(dict.fromkeys(r for r in refs if r and "/" not in r and ".." not in r))


def _sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def _gunzip_sha(path: Path) -> str | None:
    """SHA-256 do conteúdo descompactado; None se não for gzip válido ou passar do limite."""
    h = hashlib.sha256()
    total = 0
    try:
        with gzip.open(path, "rb") as fh:
            while chunk := fh.read(1024 * 1024):
                total += len(chunk)
                if total > MAX_GZ_BYTES:
                    return None
                h.update(chunk)
    except (OSError, EOFError, gzip.BadGzipFile):
        return None
    return h.hexdigest()


async def fetch_card_sources(ctx: ScanContext, owner: str, name: str, refs: list[str]) -> tuple[str, Path]:
    """Baixa (ou pega do cache) os anexos da release e o ``dist/``/raiz do repositório.

    Devolve (ref usada, pasta com ``assets/`` e ``tree/``).
    """
    cache_root = ctx.paths.cache_dir / "integrity" / "cards"
    for ref in refs:
        key = "".join(c if c.isalnum() or c in "._-" else "_" for c in f"{owner}__{name}__{ref}")
        cached = cache_root / key
        meta = cached / "meta.json"
        missing = cache_root / f"{key}.missing"
        try:
            if time.time() - missing.stat().st_mtime < MISSING_TTL:
                continue  # versão inexistente: não tenta de novo por um dia
        except OSError:
            pass
        try:
            if time.time() - float(json.loads(meta.read_text(encoding="utf-8")).get("created", 0)) < CACHE_TTL:
                return ref, cached
        except (OSError, ValueError, json.JSONDecodeError):
            pass
        work = ctx.workdir / "cards" / key
        shutil.rmtree(work, ignore_errors=True)
        work.mkdir(parents=True)
        tarball = work / "src.tar.gz"
        try:
            await ctx.http.download(f"https://codeload.github.com/{owner}/{name}/tar.gz/{ref}", tarball)
        except HttpError as err:
            if err.status == 404:
                cache_root.mkdir(parents=True, exist_ok=True)
                missing.touch()
                continue
            raise
        src = work / "src"
        out = work / "out"
        await asyncio.to_thread(_unpack_tree, tarball, src, out / "tree")
        assets = out / "assets"
        assets.mkdir(parents=True)
        try:
            release = await ctx.http.get_json(f"https://api.github.com/repos/{owner}/{name}/releases/tags/{ref}")
        except HttpError as err:
            if err.status != 404:  # sem release (instalado por commit): só a árvore
                raise
            release = {}
        for asset in (release.get("assets") or [])[:20] if isinstance(release, dict) else []:
            asset_name = str(asset.get("name") or "")
            url = str(asset.get("browser_download_url") or "")
            if asset_name and "/" not in asset_name and asset_name not in (".", "..") and url.startswith("https://"):
                await ctx.http.download(url, assets / asset_name, max_bytes=MAX_SOURCE_FILE)
        (out / "meta.json").write_text(json.dumps({"created": time.time(), "ref": ref}), encoding="utf-8")
        shutil.rmtree(cached, ignore_errors=True)
        cached.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(out), cached)
        return ref, cached
    raise CardNotVerifiable(f"nenhuma versão correspondente em {owner}/{name} (tentado: {', '.join(refs)})",
                            f"no matching version in {owner}/{name} (tried: {', '.join(refs)})")


def _unpack_tree(tarball: Path, src: Path, tree: Path) -> None:
    """Extrai o tarball e guarda só o que o HACS pode instalar: arquivos da raiz e de dist/."""
    extract(tarball, src)
    tops = [p for p in src.iterdir() if p.is_dir()]
    if len(tops) != 1:
        raise CardNotVerifiable("estrutura inesperada no tarball do GitHub", "unexpected GitHub tarball layout")
    tree.mkdir(parents=True)
    for path in tops[0].rglob("*"):
        rel = path.relative_to(tops[0])
        if path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_SOURCE_FILE \
                and (len(rel.parts) == 1 or rel.parts[0] == "dist"):
            dest = tree / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, dest)


def _candidates(sources: Path, rel: str) -> list[Path]:
    paths = [sources / "tree" / "dist" / rel, sources / "tree" / rel]
    if "/" not in rel:
        paths.insert(0, sources / "assets" / rel)
    return [p for p in paths if p.is_file()]


def compare_card(comp: Component, sources: Path, ref: str, repo: str, diff) -> list[Finding]:
    """Achados do card: arquivos alterados, sem correspondente e .gz diferentes do .js."""
    files, _links = walk_files(comp.path)
    local = {f.relative_to(comp.path).as_posix(): f for f in files}
    findings: list[Finding] = []
    for rel, path in sorted(local.items()):
        if rel.endswith(".gz"):
            continue
        cands = _candidates(sources, rel)
        mine = _sha(path)
        if any(_sha(c) == mine for c in cands):
            continue
        if cands:
            findings.append(_modified(comp, rel, ref, repo, diff(cands[0], path)))
        else:
            findings.append(_extra(comp, rel, ref, repo, path))
    for rel, path in sorted(local.items()):
        if not rel.endswith(".gz"):
            continue
        base = rel[:-3]
        unpacked = _gunzip_sha(path)
        if base in local:
            expected = {_sha(local[base])}
        else:
            expected = {_sha(c) for c in _candidates(sources, base)}
        if unpacked is None or (expected and unpacked not in expected):
            findings.append(_gz_mismatch(comp, rel, base, ref, repo))
    return findings


def _modified(comp: Component, rel: str, ref: str, repo: str, snippet: str) -> Finding:
    return Finding(
        component=comp.name, component_type=ComponentType.FRONTEND, category="integridade",
        rule_id="auditor.integridade.card-alterado", severity=Severity.HIGH,
        title="Arquivo do card diferente da release oficial",
        explanation=(f"O arquivo instalado não é igual ao da versão {ref} publicada em {repo}. Cards rodam no "
                     "navegador de quem abre o Home Assistant; pode ser uma edição sua, mas também adulteração."),
        recommendation="Se você não editou o arquivo, reinstale o card pelo HACS e investigue como ele mudou.",
        en=en_text("Card file differs from the official release",
                   f"The installed file is not the same as in version {ref} published at {repo}. Cards run in the "
                   "browser of everyone who opens Home Assistant; it may be your own edit, but also tampering.",
                   "If you did not edit the file, reinstall the card from HACS and investigate how it changed."),
        file=f"{comp.rel_path}/{rel}", snippet=snippet, source="integridade",
        extra={"ref": ref, "repositorio": repo},
    )


def _extra(comp: Component, rel: str, ref: str, repo: str, path: Path) -> Finding:
    code = rel.lower().endswith(_CODE_SUFFIXES)
    return Finding(
        component=comp.name, component_type=ComponentType.FRONTEND, category="integridade",
        rule_id="auditor.integridade.card-arquivo-extra", severity=Severity.HIGH if code else Severity.LOW,
        title="Arquivo do card que não existe na release oficial",
        explanation=(f"Este arquivo não está nos anexos da versão {ref} de {repo}, nem em dist/ ou na raiz do "
                     "repositório." + (" É código JavaScript, que roda no navegador." if code else "")),
        recommendation="Veja o que o arquivo contém e se algum recurso do painel o carrega.",
        en=en_text("Card file not present in the official release",
                   f"This file is not in the assets of version {ref} of {repo}, nor in dist/ or the repository "
                   "root." + (" It is JavaScript code, which runs in the browser." if code else ""),
                   "Check what the file contains and whether any dashboard resource loads it."),
        file=f"{comp.rel_path}/{rel}", snippet=None, source="integridade",
        extra={"ref": ref, "repositorio": repo},
    )


def _gz_mismatch(comp: Component, rel: str, base: str, ref: str, repo: str) -> Finding:
    return Finding(
        component=comp.name, component_type=ComponentType.FRONTEND, category="integridade",
        rule_id="auditor.integridade.card-gz-diferente", severity=Severity.HIGH,
        title="Cópia compactada (.gz) diferente do arquivo do card",
        explanation=(f"{rel} não corresponde a {base} (nem à versão {ref} de {repo}). O Home Assistant serve o "
                     ".gz no lugar do arquivo original, então o código que roda no navegador pode ser outro."),
        recommendation="Reinstale o card pelo HACS (ele recria o .gz) e investigue como o arquivo mudou.",
        en=en_text("Compressed copy (.gz) differs from the card file",
                   f"{rel} does not match {base} (nor version {ref} of {repo}). Home Assistant serves the .gz "
                   "instead of the original file, so the code that runs in the browser may be different.",
                   "Reinstall the card from HACS (it recreates the .gz) and investigate how the file changed."),
        file=f"{comp.rel_path}/{rel}", snippet=None, source="integridade",
        extra={"ref": ref, "repositorio": repo},
    )


def not_verified_status(reason_pt: str, reason_en: str) -> Bi:
    return Bi(f"não verificada: {reason_pt}", f"not verified: {reason_en}")
