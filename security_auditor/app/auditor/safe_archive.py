"""Extração segura de arquivos tar/zip baixados da internet.

Conteúdo baixado é tratado como hostil: nada é executado, e a extração
rejeita caminhos absolutos, ``..``, links simbólicos/físicos, dispositivos
e arquivos grandes demais (zip bombs).
"""

from __future__ import annotations

import stat
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

DEFAULT_MAX_TOTAL = 500 * 1024 * 1024  # 500 MiB descompactados
DEFAULT_MAX_MEMBERS = 20_000


class UnsafeArchiveError(Exception):
    """Arquivo compactado com conteúdo perigoso ou fora dos limites."""


def _safe_relpath(name: str) -> PurePosixPath | None:
    """Caminho relativo normalizado, ou ``None`` para entradas a ignorar (diretório raiz)."""
    name = name.replace("\\", "/")
    p = PurePosixPath(name)
    if p.is_absolute() or name.startswith("/"):
        raise UnsafeArchiveError(f"Caminho absoluto no arquivo: {name!r}")
    parts = [part for part in p.parts if part not in ("", ".")]
    if any(part == ".." for part in parts):
        raise UnsafeArchiveError(f"Caminho com '..' no arquivo: {name!r}")
    if not parts:
        return None
    return PurePosixPath(*parts)


def _target(dest: Path, rel: PurePosixPath) -> Path:
    target = (dest / rel).resolve()
    if not target.is_relative_to(dest):
        raise UnsafeArchiveError(f"Entrada escapa do diretório de destino: {rel}")
    return target


def extract(
    archive: Path,
    dest: Path,
    *,
    max_total: int = DEFAULT_MAX_TOTAL,
    max_members: int = DEFAULT_MAX_MEMBERS,
) -> list[str]:
    """Extrai ``archive`` em ``dest`` (que deve estar vazio). Retorna os arquivos extraídos.

    Links são ignorados com registro na lista de retorno como ``"<link> nome"``
    para que o chamador possa reportá-los, mas nunca são criados no disco.
    """
    dest.mkdir(parents=True, exist_ok=True)
    dest = dest.resolve()
    if zipfile.is_zipfile(archive):
        return _extract_zip(archive, dest, max_total, max_members)
    if tarfile.is_tarfile(archive):
        return _extract_tar(archive, dest, max_total, max_members)
    raise UnsafeArchiveError(f"Formato de arquivo não reconhecido: {archive.name}")


def _extract_tar(archive: Path, dest: Path, max_total: int, max_members: int) -> list[str]:
    extracted: list[str] = []
    total = 0
    with tarfile.open(archive, "r:*") as tar:
        for count, member in enumerate(tar, start=1):
            if count > max_members:
                raise UnsafeArchiveError("Arquivo com entradas demais")
            rel = _safe_relpath(member.name)
            if rel is None:
                continue
            if member.issym() or member.islnk():
                extracted.append(f"<link> {rel}")
                continue
            if member.isdir():
                _target(dest, rel).mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                # FIFO, dispositivo, etc.
                raise UnsafeArchiveError(f"Tipo de entrada não permitido: {rel}")
            total += member.size
            if total > max_total:
                raise UnsafeArchiveError("Conteúdo descompactado excede o limite")
            target = _target(dest, rel)
            target.parent.mkdir(parents=True, exist_ok=True)
            src = tar.extractfile(member)
            if src is None:
                continue
            with src, target.open("wb") as fh:
                _copy_limited(src, fh, member.size)
            target.chmod(0o644)
            extracted.append(str(rel))
    return extracted


def _extract_zip(archive: Path, dest: Path, max_total: int, max_members: int) -> list[str]:
    extracted: list[str] = []
    total = 0
    with zipfile.ZipFile(archive) as zf:
        infos = zf.infolist()
        if len(infos) > max_members:
            raise UnsafeArchiveError("Arquivo com entradas demais")
        for info in infos:
            rel = _safe_relpath(info.filename)
            if rel is None:
                continue
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                extracted.append(f"<link> {rel}")
                continue
            if info.is_dir():
                _target(dest, rel).mkdir(parents=True, exist_ok=True)
                continue
            total += info.file_size
            if total > max_total:
                raise UnsafeArchiveError("Conteúdo descompactado excede o limite")
            target = _target(dest, rel)
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, target.open("wb") as fh:
                _copy_limited(src, fh, info.file_size)
            target.chmod(0o644)
            extracted.append(str(rel))
    return extracted


def _copy_limited(src, dst, declared: int) -> None:  # noqa: ANN001
    """Copia sem confiar no tamanho declarado no cabeçalho."""
    written = 0
    while chunk := src.read(64 * 1024):
        written += len(chunk)
        if written > declared:
            raise UnsafeArchiveError("Entrada maior que o tamanho declarado")
        dst.write(chunk)
