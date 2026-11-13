"""Lista negra: componentes reportados (comunidade ou o próprio usuário).

A lista só ACRESCENTA avisos. Ela nunca libera, suprime ou muda o que o auditor
verifica. Tudo é comparado localmente: nada sobre a instalação sai daqui.

Fontes, na ordem:
- ``/data/cache/lista_comunitaria.json``: lista comunitária baixada (fase 2);
- ``/config/security_auditor/lista_negra.json``: lista pessoal, editável no HA.

Formato (versão 1):

    {"versao": 1, "itens": [{"id": "2026-001", "tipo": "integracao",
      "github": "dono/repo", "nome": "dominio", "imagem": null, "versoes": "<1.4.2",
      "nivel": "critica", "categoria": "malicioso", "motivo": "...",
      "evidencias": ["https://..."], "adicionado_em": "2026-11-12"}]}
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from .models import ComponentType, Severity

_LOGGER = logging.getLogger(__name__)

FORMAT_VERSION = 1
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_ITEMS = 5000

TYPES = {"integracao": ComponentType.INTEGRATION, "frontend": ComponentType.FRONTEND, "addon": ComponentType.ADDON}
LEVELS = {"critica": Severity.CRITICAL, "alta": Severity.HIGH, "media": Severity.MEDIUM, "aviso": Severity.LOW}
CATEGORIES = {
    "malicioso": "reportado como malicioso",
    "comprometido": "reportado como comprometido (conta ou versão adulterada)",
    "vulneravel": "com vulnerabilidade grave conhecida",
    "abandonado": "abandonado, sem correções de segurança",
    "telemetria": "envia dados para terceiros sem aviso claro",
    "removido": "removido ou bloqueado numa loja oficial (ex.: HACS)",
    "incompativel": "versão bloqueada pelo próprio Home Assistant",
}
# Fontes conhecidas (campo opcional "fonte"), com o nome exibido no relatório.
SOURCES = {"hacs": "lista de removidos do HACS", "home-assistant": "lista de bloqueados do Home Assistant",
           "comunidade": "relato da comunidade"}

_GITHUB = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
_NAME = re.compile(r"^[A-Za-z0-9_.*?-]{1,200}$")
_IMAGE = re.compile(r"^[a-z0-9._/{}:-]{1,300}$")
_ID = re.compile(r"^[A-Za-z0-9_.-]{1,40}$")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class BlocklistError(ValueError):
    """Arquivo da lista inválido (mensagem em português, sem dados sensíveis)."""


class _NewerFormat(Exception):  # noqa: N818 - sinal interno, não é erro
    """Item usa um valor (categoria, tipo, fonte) de uma versão mais nova do formato."""


@dataclass(frozen=True)
class BlocklistEntry:
    id: str
    nivel: str
    categoria: str
    motivo: str
    origem: str  # "comunitária" | "pessoal"
    tipo: str | None = None
    github: str | None = None
    nome: str | None = None
    imagem: str | None = None
    versoes: str = ""
    evidencias: tuple[str, ...] = ()
    adicionado_em: str | None = None
    fonte: str | None = None  # hacs | home-assistant | comunidade

    @property
    def severity(self) -> Severity:
        return LEVELS[self.nivel]


@dataclass(frozen=True)
class Match:
    entry: BlocklistEntry
    strong: bool  # True = mesmo repositório do GitHub ou imagem; False = só o nome
    how: str  # explicação curta de como casou


@dataclass
class Blocklist:
    entries: list[BlocklistEntry] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)  # descrições das fontes carregadas
    errors: list[str] = field(default_factory=list)

    def matches(self, component_type: str, name: str, *, github: list[str] | None = None,
                image: str | None = None, version: str | None = None, aliases: tuple[str, ...] = ()) -> list[Match]:
        """Entradas que se aplicam ao componente, já filtradas pela versão instalada."""
        repos = {g.lower() for g in (github or []) if g}
        names = {n.lower() for n in (name, *aliases) if n}
        out: list[Match] = []
        for e in self.entries:
            if e.tipo and TYPES[e.tipo] != component_type:
                continue
            how = None
            strong = False
            if e.github and e.github.lower() in repos:
                how, strong = f"repositório {e.github}", True
            elif e.imagem and image and fnmatchcase(image.lower(), e.imagem.lower().replace("{arch}", "*")):
                how, strong = f"imagem {e.imagem}", True
            elif e.nome and any(fnmatchcase(n, e.nome.lower()) for n in names):
                # Sem o GitHub (ou com outro GitHub) o nome sozinho é só um indício.
                if e.github and repos:
                    continue  # o componente tem outro repositório: é outro projeto com o mesmo nome
                how = f"nome {e.nome}"
                # O Home Assistant bloqueia pelo domínio da integração: para essa fonte o nome é a chave.
                strong = e.fonte == "home-assistant"
            if how is None or not version_affected(e.versoes, version):
                continue
            out.append(Match(e, strong, how))
        return out


def version_affected(spec: str, installed: str | None) -> bool:
    """True se a versão instalada está na faixa da entrada (vazia = todas).

    Versão desconhecida ou não comparável conta como afetada: melhor avisar.
    """
    if not spec:
        return True
    if not installed:
        return True
    try:
        return Version(installed.strip().lstrip("vV")) in SpecifierSet(spec, prereleases=True)
    except (InvalidVersion, InvalidSpecifier):
        return True


def _text(item: dict[str, Any], key: str, limit: int, pattern: re.Pattern[str] | None = None,
          required: bool = False) -> str | None:
    value = item.get(key)
    if value is None or value == "":
        if required:
            raise BlocklistError(f"campo '{key}' obrigatório")
        return None
    if not isinstance(value, str) or len(value) > limit or any(ord(c) < 32 for c in value):
        raise BlocklistError(f"campo '{key}' inválido")
    if pattern and not pattern.match(value):
        raise BlocklistError(f"campo '{key}' com formato inválido")
    return value.strip()


def parse(data: Any, origem: str) -> tuple[list[BlocklistEntry], list[str]]:
    """Valida o conteúdo (já decodificado do JSON). Entradas inválidas são descartadas com erro."""
    if not isinstance(data, dict) or data.get("versao") != FORMAT_VERSION:
        raise BlocklistError(f"formato desconhecido (esperado \"versao\": {FORMAT_VERSION})")
    items = data.get("itens")
    if not isinstance(items, list):
        raise BlocklistError("campo 'itens' ausente ou não é uma lista")
    if len(items) > MAX_ITEMS:
        raise BlocklistError(f"lista grande demais (máximo {MAX_ITEMS} itens)")
    entries: list[BlocklistEntry] = []
    errors: list[str] = []
    newer = 0
    seen: set[str] = set()
    for n, item in enumerate(items, start=1):
        try:
            if not isinstance(item, dict):
                raise BlocklistError("item não é um objeto")
            entry_id = _text(item, "id", 40, _ID, required=True) or ""
            if entry_id in seen:
                raise BlocklistError(f"id '{entry_id}' repetido")
            tipo = _text(item, "tipo", 20)
            if tipo is not None and tipo not in TYPES:
                raise _NewerFormat
            nivel = _text(item, "nivel", 20, required=True) or ""
            if nivel not in LEVELS:
                raise BlocklistError("campo 'nivel' deve ser critica, alta, media ou aviso")
            categoria = _text(item, "categoria", 20, required=True) or ""
            if categoria not in CATEGORIES:
                raise _NewerFormat
            versoes = _text(item, "versoes", 100) or ""
            if versoes:
                try:
                    SpecifierSet(versoes)
                except InvalidSpecifier as err:
                    raise BlocklistError("campo 'versoes' inválido (ex.: \"<1.4.2\" ou \">=1.0,<1.2\")") from err
            evid = item.get("evidencias") or []
            if not isinstance(evid, list) or len(evid) > 10:
                raise BlocklistError("campo 'evidencias' deve ser uma lista (até 10 links)")
            links = []
            for url in evid:
                # Só https: os links viram <a href>, então nada de javascript: ou data:.
                if not isinstance(url, str) or not url.startswith("https://") or len(url) > 500 \
                        or any(ord(c) <= 32 for c in url):
                    raise BlocklistError("evidências devem ser links https://")
                links.append(url)
            entry = BlocklistEntry(
                id=entry_id, nivel=nivel, categoria=categoria, origem=origem,
                motivo=_text(item, "motivo", 500, required=True) or "",
                tipo=tipo,
                github=_text(item, "github", 201, _GITHUB),
                nome=_text(item, "nome", 200, _NAME),
                imagem=_text(item, "imagem", 300, _IMAGE),
                versoes=versoes, evidencias=tuple(links),
                adicionado_em=_text(item, "adicionado_em", 10, _DATE),
                fonte=_text(item, "fonte", 30),
            )
            if entry.fonte is not None and entry.fonte not in SOURCES:
                raise _NewerFormat
            if not (entry.github or entry.nome or entry.imagem):
                raise BlocklistError("informe 'github', 'nome' ou 'imagem'")
            if entry.nome and set(entry.nome) <= {"*", "?"}:
                raise BlocklistError("'nome' não pode ser só curinga")
            seen.add(entry_id)
            entries.append(entry)
        except BlocklistError as err:
            errors.append(f"item {n}: {err}")
        except _NewerFormat:
            # Compatibilidade: categorias/tipos/fontes novos não quebram versões antigas do add-on.
            newer += 1
    if newer:
        _LOGGER.info("Lista negra %s: %d item(ns) ignorado(s) por usar(em) valores de uma versão mais nova "
                     "do formato; atualize o add-on para usá-los", origem, newer)
    return entries, errors


def load_file(path: Path, origem: str) -> tuple[list[BlocklistEntry], list[str]]:
    """Lê e valida um arquivo da lista. Arquivo ausente = lista vazia, sem erro."""
    try:
        size = path.stat().st_size
    except FileNotFoundError:
        return [], []
    except OSError as err:
        return [], [f"não foi possível ler {path.name}: {type(err).__name__}"]
    if size > MAX_FILE_BYTES:
        return [], [f"{path.name} é grande demais (máximo {MAX_FILE_BYTES // 1024 // 1024} MB)"]
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError) as err:
        return [], [f"não foi possível ler {path.name}: {type(err).__name__}"]
    except json.JSONDecodeError as err:
        return [], [f"{path.name} não é um JSON válido (linha {err.lineno}, coluna {err.colno})"]
    try:
        entries, errors = parse(data, origem)
    except BlocklistError as err:
        return [], [f"{path.name}: {err}"]
    return entries, [f"{path.name}, {e}" for e in errors]


def personal_path(config_dir: Path) -> Path:
    return config_dir / "security_auditor" / "lista_negra.json"


def community_cache_path(cache_dir: Path) -> Path:
    return cache_dir / "lista_comunitaria.json"


def validate_item(item: Any) -> BlocklistEntry:
    """Valida um item vindo da interface (lista pessoal). Levanta BlocklistError com a explicação."""
    entries, errors = parse({"versao": FORMAT_VERSION, "itens": [item]}, "pessoal")
    if errors:
        raise BlocklistError(errors[0].removeprefix("item 1: "))
    if not entries:
        raise BlocklistError("valor de 'tipo', 'categoria' ou 'fonte' desconhecido")
    return entries[0]


def load(config_dir: Path, cache_dir: Path, community: bool = True,
         ui_items: list[dict[str, Any]] | None = None) -> Blocklist:
    """Junta a lista comunitária (cache), o arquivo pessoal e os itens pessoais criados na interface."""
    bl = Blocklist()
    if ui_items:
        entries, errors = parse({"versao": FORMAT_VERSION, "itens": ui_items}, "pessoal")
        bl.entries.extend(entries)
        bl.errors.extend(f"lista pessoal da interface, {e}" for e in errors)
        if entries:
            bl.sources.append(f"lista pessoal da interface ({len(entries)} itens)")
            _LOGGER.info("Lista negra pessoal (interface) carregada: %d item(ns)", len(entries))
    sources = [(personal_path(config_dir), "pessoal")]
    if community:
        sources.insert(0, (community_cache_path(cache_dir), "comunitária"))
    for path, origem in sources:
        entries, errors = load_file(path, origem)
        bl.errors.extend(errors)
        if entries:
            bl.entries.extend(entries)
            bl.sources.append(f"lista {origem} ({len(entries)} itens)")
            _LOGGER.info("Lista negra %s carregada: %d item(ns)", origem, len(entries))
    for err in errors_unique(bl.errors):
        _LOGGER.warning("Lista negra: %s", err)
    return bl


def errors_unique(errors: list[str]) -> list[str]:
    return list(dict.fromkeys(errors))
