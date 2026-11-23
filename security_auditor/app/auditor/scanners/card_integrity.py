"""Integridade dos cards do HACS (``www/community/<repo>``) contra a versão publicada no GitHub.

O HACS instala um card de dois jeitos: baixando os arquivos anexados à release (ex.: ``meu-card.js``)
ou copiando ``dist/`` (ou a raiz) do repositório. Depois grava uma cópia ``<arquivo>.js.gz`` de cada
``.js``, e o HA serve o ``.gz`` no lugar do original quando ele existe. Por isso:

- cada arquivo instalado é comparado (SHA-256) com o arquivo de mesmo nome nos anexos da release,
  em ``dist/`` ou na raiz do repositório, na versão que o HACS registrou;
- cada ``.js.gz`` é descompactado e comparado com o ``.js`` correspondente (um ``.gz`` diferente
  trocaria, sem ninguém ver, o código que roda no navegador).

Arquivos da release que não foram instalados não contam: o HACS baixa só parte deles.

O HACS não apaga os arquivos da versão anterior ao atualizar. Por isso, um arquivo que não bate
com a versão registrada é procurado nas outras releases do repositório pelo SHA-256 que o GitHub
informa de cada anexo: se bater, é "sobra de uma versão anterior" (ou "arquivo de outra versão"),
Informativa, em vez de arquivo desconhecido.
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
MAX_ASSETS = 300
MAX_ASSETS_BYTES = 128 * 1024 * 1024
OTHER_RELEASES = 30  # releases do repositório consultadas para reconhecer arquivos de outras versões
CACHE_FORMAT = 2  # 2: todos os anexos e os SHA-256 das outras releases
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
            data = json.loads(meta.read_text(encoding="utf-8"))
            if time.time() - float(data.get("created", 0)) < CACHE_TTL and (cached / "tree").is_dir():
                if data.get("formato") != CACHE_FORMAT:
                    # Cache de uma versão anterior do auditor: aproveita o código já baixado e só completa
                    # os anexos (antes eram no máximo 20) e os SHA-256 das releases.
                    await _fetch_release(ctx, owner, name, ref, cached)
                    meta.write_text(json.dumps({**data, "formato": CACHE_FORMAT}), encoding="utf-8")
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
        await _fetch_release(ctx, owner, name, ref, out)
        (out / "meta.json").write_text(json.dumps({"created": time.time(), "ref": ref, "formato": CACHE_FORMAT}),
                                       encoding="utf-8")
        shutil.rmtree(cached, ignore_errors=True)
        cached.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(out), cached)
        return ref, cached
    raise CardNotVerifiable(f"nenhuma versão correspondente em {owner}/{name} (tentado: {', '.join(refs)})",
                            f"no matching version in {owner}/{name} (tried: {', '.join(refs)})")


async def _fetch_release(ctx: ScanContext, owner: str, name: str, ref: str, out: Path) -> None:
    """Anexos da release em ``out/assets`` (pula os que já estão lá) e ``out/digests.json``."""
    assets = out / "assets"
    assets.mkdir(parents=True, exist_ok=True)
    try:
        release = await ctx.http.get_json(f"https://api.github.com/repos/{owner}/{name}/releases/tags/{ref}")
    except HttpError as err:
        if err.status != 404:  # sem release (instalado por commit): só a árvore
            raise
        release = {}
    total = 0
    current: dict[str, str] = {}
    for asset in (release.get("assets") or [])[:MAX_ASSETS] if isinstance(release, dict) else []:
        asset_name = str(asset.get("name") or "")
        url = str(asset.get("browser_download_url") or "")
        if not asset_name or "/" in asset_name or asset_name in (".", "..") or not url.startswith("https://"):
            continue
        if digest := _digest(asset):
            current[asset_name] = digest
        size = int(asset.get("size") or 0)
        if (assets / asset_name).is_file() or total + size > MAX_ASSETS_BYTES:
            continue
        total += size
        await ctx.http.download(url, assets / asset_name, max_bytes=MAX_SOURCE_FILE)
    others = await _other_releases(ctx, owner, name, ref)
    (out / "digests.json").write_text(json.dumps({"atual": current, "outras": others}), encoding="utf-8")


def _digest(asset: dict) -> str | None:
    """SHA-256 que o GitHub informa do anexo ("sha256:…"), ou None."""
    value = str(asset.get("digest") or "")
    return value.split(":", 1)[1].lower() if value.startswith("sha256:") else None


async def _other_releases(ctx: ScanContext, owner: str, name: str, ref: str) -> dict[str, list[list[str]]]:
    """{nome do anexo: [[tag, sha256], …]} das outras releases (sem baixar nada além da lista)."""
    try:
        releases = await ctx.http.get_json(
            f"https://api.github.com/repos/{owner}/{name}/releases?per_page={OTHER_RELEASES}")
    except (HttpError, ValueError):
        return {}
    out: dict[str, list[list[str]]] = {}
    for release in releases if isinstance(releases, list) else []:
        tag = str(release.get("tag_name") or "")
        if not tag or tag == ref:
            continue
        for asset in release.get("assets") or []:
            if (digest := _digest(asset)) and (asset_name := str(asset.get("name") or "")):
                out.setdefault(asset_name, []).append([tag, digest])
    return out


def _load_digests(sources: Path) -> dict:
    try:
        data = json.loads((sources / "digests.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"atual": {}, "outras": {}}
    return data if isinstance(data, dict) else {"atual": {}, "outras": {}}


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
    digests = _load_digests(sources)
    findings: list[Finding] = []
    for rel, path in sorted(local.items()):
        if rel.endswith(".gz"):
            continue
        cands = _candidates(sources, rel)
        mine = _sha(path)
        if any(_sha(c) == mine for c in cands) or ("/" not in rel and (digests.get("atual") or {}).get(rel) == mine):
            continue
        other = [tag for tag, digest in (digests.get("outras") or {}).get(rel, []) if digest == mine] \
            if "/" not in rel else []
        if other:
            leftover = not cands and rel not in (digests.get("atual") or {})
            findings.append(_other_release(comp, rel, ref, repo, other[0], leftover))
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


def _other_release(comp: Component, rel: str, ref: str, repo: str, tag: str, leftover: bool) -> Finding:
    if leftover:
        title, title_en = "Sobra de uma versão anterior do card", "Leftover from an earlier card version"
        why = (f"O arquivo não faz parte da versão {ref}, mas é idêntico ao da versão {tag} publicada em {repo}. "
               "O HACS não apaga os arquivos antigos ao atualizar; a versão atual normalmente não o carrega.")
        why_en = (f"The file is not part of version {ref}, but it is identical to the one in version {tag} published "
                  f"at {repo}. HACS does not delete old files when updating; the current version normally does not "
                  "load it.")
        todo = "Pode ser apagado com segurança (ou reinstale o card pelo HACS para limpar a pasta)."
        todo_en = "It can be safely deleted (or reinstall the card from HACS to clean the folder)."
    else:
        title, title_en = "Arquivo de outra versão do card", "File from another card version"
        why = (f"O HACS registrou a versão {ref}, mas este arquivo é idêntico ao da versão {tag} publicada em {repo}. "
               "Costuma ser uma atualização interrompida ou o registro do HACS desatualizado.")
        why_en = (f"HACS recorded version {ref}, but this file is identical to the one in version {tag} published at "
                  f"{repo}. It is usually an interrupted update or an outdated HACS record.")
        todo = "Reinstale o card pelo HACS para deixar arquivos e versão iguais."
        todo_en = "Reinstall the card from HACS so files and version match."
    return Finding(
        component=comp.name, component_type=ComponentType.FRONTEND, category="integridade",
        rule_id="auditor.integridade.card-outra-versao", severity=Severity.INFO, title=title, explanation=why,
        recommendation=todo, en=en_text(title_en, why_en, todo_en),
        file=f"{comp.rel_path}/{rel}", snippet=None, source="integridade",
        extra={"ref": ref, "repositorio": repo, "versao_do_arquivo": tag},
    )


def _modified(comp: Component, rel: str, ref: str, repo: str, snippet: str) -> Finding:
    code = rel.lower().endswith(_CODE_SUFFIXES)
    return Finding(
        component=comp.name, component_type=ComponentType.FRONTEND, category="integridade",
        rule_id="auditor.integridade.card-alterado", severity=Severity.HIGH if code else Severity.LOW,
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
