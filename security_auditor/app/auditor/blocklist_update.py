"""Download da lista negra comunitária (fase 2), com assinatura Ed25519 e cache.

Segurança:
- baixa o arquivo inteiro do GitHub (raw.githubusercontent.com, na allowlist de saída);
  nada sobre a instalação é enviado;
- só aceita a lista se a assinatura (``lista.json.sig``) for válida para uma das chaves
  públicas embutidas abaixo: quem invadir o repositório não consegue publicar itens;
- rejeita uma lista mais antiga que a do cache (proteção contra "voltar no tempo");
- valida o conteúdo inteiro antes de gravar; em qualquer falha, mantém a cópia anterior.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import os
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .blocklist import MAX_FILE_BYTES, BlocklistError, community_cache_path, parse
from .net import DownloadTooLargeError, EgressDeniedError, HttpError, SafeHttpClient

_LOGGER = logging.getLogger(__name__)

BASE_URL = "https://raw.githubusercontent.com/diogocaseca/ha-security-blocklist/main"
LIST_URL = f"{BASE_URL}/lista.json"
SIG_URL = f"{BASE_URL}/lista.json.sig"

# Chaves públicas aceitas (id -> chave Ed25519 em base64). Mais de uma permite trocar a chave
# sem quebrar quem ainda não atualizou o add-on. A chave privada nunca entra em repositório.
PUBLIC_KEYS: dict[str, str] = {
    "539f9e99d82adfd9": "A6gSN0z7ArxoKaQTnlNgaz5EzO4iLEAvZSFWQNnqh2g=",
}

REFRESH_EVERY = timedelta(hours=6)  # não baixa de novo antes disso
STALE_AFTER = timedelta(days=7)  # avisa se a cópia local ficar mais velha que isso
MAX_SIG_BYTES = 4096


class SignatureError(Exception):
    """Assinatura ausente, malformada ou inválida."""


def key_id(public_key: bytes) -> str:
    return hashlib.sha256(public_key).hexdigest()[:16]


def verify(data: bytes, sig_text: str, keys: dict[str, str] | None = None) -> str:
    """Confere a assinatura de ``data``. Devolve o id da chave que assinou."""
    keys = PUBLIC_KEYS if keys is None else keys
    try:
        sig = json.loads(sig_text)
        if not isinstance(sig, dict) or sig.get("versao") != 1 or sig.get("algoritmo") != "ed25519":
            raise SignatureError("formato de assinatura desconhecido")
        kid = str(sig.get("chave", ""))
        raw = base64.b64decode(str(sig.get("assinatura", "")), validate=True)
    except (ValueError, binascii.Error) as err:
        raise SignatureError("assinatura malformada") from err
    if kid not in keys:
        raise SignatureError(f"assinada por uma chave desconhecida ({kid[:16]})")
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(keys[kid])).verify(raw, data)
    except (InvalidSignature, ValueError) as err:
        raise SignatureError("assinatura inválida: o arquivo não é o publicado pelo mantenedor") from err
    return kid


@dataclass
class UpdateResult:
    status: str  # atualizada | sem_mudancas | recente | falhou | desativada
    message: str
    items: int = 0
    list_date: str | None = None
    downloaded_at: str | None = None


def _state_path(cache_dir: Path) -> Path:
    return cache_dir / "lista_comunitaria.estado.json"


def read_state(cache_dir: Path) -> dict[str, Any]:
    try:
        data = json.loads(_state_path(cache_dir).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _write_atomic(path: Path, data: bytes) -> None:
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def _parse_dt(value: Any) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value))
    except ValueError:
        return None


async def update(http: SafeHttpClient, cache_dir: Path, *, now: datetime | None = None,
                 force: bool = False, keys: dict[str, str] | None = None,
                 list_url: str = LIST_URL, sig_url: str = SIG_URL) -> UpdateResult:
    """Baixa e instala a lista comunitária se houver versão nova e assinada. Nunca levanta exceção."""
    now = now or datetime.now(UTC)
    cache_dir.mkdir(parents=True, exist_ok=True)
    state = read_state(cache_dir)
    last_check = _parse_dt(state.get("verificado_em"))
    if not force and last_check and now - last_check < REFRESH_EVERY and community_cache_path(cache_dir).exists():
        return UpdateResult("recente", "cópia local verificada há pouco", int(state.get("itens", 0)),
                            state.get("atualizado_em"), state.get("baixado_em"))

    _LOGGER.info("Lista negra comunitária: verificando atualização")
    with tempfile.TemporaryDirectory(dir=cache_dir, prefix=".lista-") as tmp:
        tmp_dir = Path(tmp)
        try:
            await http.download(sig_url, tmp_dir / "lista.json.sig", max_bytes=MAX_SIG_BYTES)
            await http.download(list_url, tmp_dir / "lista.json", max_bytes=MAX_FILE_BYTES)
            data = (tmp_dir / "lista.json").read_bytes()
            kid = verify(data, (tmp_dir / "lista.json.sig").read_text(encoding="utf-8"), keys)
            doc = json.loads(data.decode("utf-8"))
            entries, errors = parse(doc, "comunitária")
        except SignatureError as err:
            return _failed(state, f"lista recusada: {err}")
        except (HttpError, EgressDeniedError, DownloadTooLargeError, OSError, TimeoutError) as err:
            return _failed(state, f"não foi possível baixar ({type(err).__name__}: {err})")
        except (BlocklistError, ValueError) as err:
            return _failed(state, f"lista com formato inválido ({err})")
        except Exception as err:  # noqa: BLE001 - qualquer erro mantém a cópia anterior
            return _failed(state, f"erro inesperado ({type(err).__name__})")

        list_date = str(doc.get("atualizado_em") or "")
        old_date = str(state.get("atualizado_em") or "")
        digest = hashlib.sha256(data).hexdigest()
        if old_date and list_date and list_date < old_date:
            return _failed(state, f"lista recusada: é mais antiga ({list_date}) que a cópia local ({old_date})")

        stamp = now.isoformat(timespec="seconds")
        changed = digest != state.get("sha256") or not community_cache_path(cache_dir).exists()
        if changed:
            _write_atomic(community_cache_path(cache_dir), data)
        new_state = {
            "verificado_em": stamp, "baixado_em": stamp, "atualizado_em": list_date or None,
            "sha256": digest, "itens": len(entries), "chave": kid, "erros": errors[:5], "ultimo_erro": None,
        }
        _write_atomic(_state_path(cache_dir), json.dumps(new_state, ensure_ascii=False).encode())

    for err in errors[:5]:
        _LOGGER.warning("Lista negra comunitária: %s", err)
    if changed:
        _LOGGER.info("Lista negra comunitária atualizada: %d item(ns), lista de %s, assinatura OK (chave %s)",
                     len(entries), list_date or "data desconhecida", kid)
        return UpdateResult("atualizada", "lista nova instalada", len(entries), list_date or None, stamp)
    _LOGGER.info("Lista negra comunitária sem mudanças (%d item(ns), lista de %s)", len(entries), list_date or "?")
    return UpdateResult("sem_mudancas", "nenhuma mudança", len(entries), list_date or None, stamp)


def _failed(state: dict[str, Any], message: str) -> UpdateResult:
    _LOGGER.warning("Lista negra comunitária: %s; mantendo a cópia anterior", message)
    return UpdateResult("falhou", message, int(state.get("itens", 0)), state.get("atualizado_em"),
                        state.get("baixado_em"))


def is_stale(result: UpdateResult, now: datetime | None = None) -> bool:
    """True se a cópia local é velha demais (as atualizações estão falhando)."""
    downloaded = _parse_dt(result.downloaded_at)
    return downloaded is None or (now or datetime.now(UTC)) - downloaded > STALE_AFTER
