"""Dependências maliciosas: pacotes catalogados como maliciosos na OSV e nomes de typosquatting.

- OSV (api.osv.dev): a consulta em lote devolve os avisos de cada pacote; os que começam com
  ``MAL-`` são pacotes maliciosos catalogados (OpenSSF Malicious Packages). Só o nome do pacote vai.
  Depois cada aviso é baixado pelo id (só o id vai) e as versões afetadas são comparadas aqui dentro com a
  versão pedida: um pacote legítimo que teve uma versão invadida (ex.: num2words 0.5.15 e 0.5.16) não é
  malicioso nas outras versões.
- Typosquatting: o nome fica a uma "letra" (troca, falta, sobra ou inversão) de um pacote popular
  em integrações do HA, sem ser ele.
"""

from __future__ import annotations

import logging
import re

from packaging.requirements import InvalidRequirement, Requirement
from packaging.version import InvalidVersion, Version

from ..models import Severity, en_text

_LOGGER = logging.getLogger(__name__)

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/{}"
_SAFE_ID = re.compile(r"^MAL-\d{4}-\d+$")
MAX_QUERY = 500

# Pacotes muito usados por integrações (nomes normalizados: minúsculas, "-" no lugar de "_" e ".").
POPULAR = frozenset("""
requests aiohttp urllib3 certifi charset-normalizer numpy pandas pyyaml cryptography pycryptodome
pycryptodomex paramiko websockets websocket-client beautifulsoup4 pillow python-dateutil
simplejson setuptools protobuf grpcio boto3 botocore google-auth httpx pydantic attrs jinja2
markupsafe click colorama pyserial paho-mqtt bleak zeroconf async-timeout voluptuous pyjwt
oauthlib requests-oauthlib xmltodict defusedxml netifaces psutil pexpect pymodbus pysnmp pyopenssl
bcrypt pynacl typing-extensions packaging scipy matplotlib opencv-python selenium flask
django fastapi uvicorn tenacity backoff cachetools aiofiles aiodns multidict orjson ujson msgpack
cbor2 pycountry geopy haversine pyusb pyudev dbus-fast bleak-retry-connector hass-nabucasa
python-slugify unidecode awesomeversion aiohttp-cors fnvhash sqlalchemy pyotp qrcode
""".split())
# Pacotes legítimos conhecidos que ficam a uma letra de um popular (não são typosquatting).
KNOWN_NEIGHBOURS = frozenset({"pyaml", "websocket", "pycrypto", "aiosignal", "aiofile"})
_NORM = re.compile(r"[-_.]+")


def normalize(name: str) -> str:
    return _NORM.sub("-", name.strip().lower())


def _one_edit(a: str, b: str) -> bool:
    """True se ``a`` e ``b`` diferem por exatamente uma troca, inserção, remoção ou inversão vizinha."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diff = [i for i in range(len(a)) if a[i] != b[i]]
        if len(diff) == 1:
            return True
        return len(diff) == 2 and diff[1] == diff[0] + 1 and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]]
    short, long_ = (a, b) if len(a) < len(b) else (b, a)
    for i in range(len(long_)):
        if long_[:i] + long_[i + 1:] == short:
            return True
    return False


def typosquat_of(name: str) -> str | None:
    """Pacote popular que ``name`` parece imitar, ou None."""
    n = normalize(name)
    if n in POPULAR or n in KNOWN_NEIGHBOURS or len(n) < 5:
        return None
    for popular in sorted(POPULAR):
        if len(popular) >= 5 and _one_edit(n, popular):
            return popular
    return None


async def malicious_ids(http, names: list[str]) -> dict[str, list[str]]:
    """Nome normalizado -> ids MAL-… na OSV (só o nome do pacote é enviado)."""
    names = sorted({normalize(n) for n in names})[:MAX_QUERY]
    if not names:
        return {}
    data = await http.post_json(OSV_BATCH, {"queries": [{"package": {"name": n, "ecosystem": "PyPI"}} for n in names]})
    out: dict[str, list[str]] = {}
    for name, result in zip(names, (data or {}).get("results") or [], strict=False):
        ids = sorted({str(v.get("id")) for v in (result or {}).get("vulns") or []
                      if str(v.get("id", "")).startswith("MAL-")})
        if ids:
            out[name] = ids
    return out


TEXTS = {
    "malicioso": (
        Severity.CRITICAL, "Dependência catalogada como pacote malicioso",
        ("A base OSV lista este pacote do PyPI como malicioso ({ids}). Pacotes assim costumam roubar credenciais "
        "ou instalar código remoto quando são instalados."),
        "Remova a integração e troque as senhas e tokens que o Home Assistant guarda. Confira os avisos na OSV.",
        "Dependency listed as a malicious package",
        ("The OSV database lists this PyPI package as malicious ({ids}). Packages like this usually steal "
        "credentials or install remote code when they are installed."),
        "Remove the integration and change the passwords and tokens Home Assistant stores. Check the OSV entries."),
    "malicioso_faixa": (
        Severity.MEDIUM, "Dependência aceita versões que foram maliciosas",
        ("O pacote teve versões publicadas com código malicioso ({versoes}; {ids}) e a faixa pedida no "
         "manifest.json ({pedido}) aceita alguma delas. Essas versões costumam ser retiradas do PyPI logo, mas uma "
         "instalação feita naquela época pode ter ficado com elas."),
        "Confira a versão instalada do pacote; se for uma das listadas, troque as senhas e tokens do Home Assistant.",
        "Dependency accepts versions that were malicious",
        ("The package had versions published with malicious code ({versoes}; {ids}) and the range required in "
         "manifest.json ({pedido}) accepts one of them. Such versions are usually pulled from PyPI quickly, but an "
         "install made at that time may have kept them."),
        ("Check the installed version of the package; if it is one of those listed, change the Home Assistant "
         "passwords and tokens.")),
    "malicioso_outra_versao": (
        Severity.INFO, "Pacote que já teve versões maliciosas (não a pedida)",
        ("O pacote teve versões publicadas com código malicioso ({versoes}; {ids}), em geral porque a conta do "
         "autor foi invadida. A versão pedida no manifest.json ({pedido}) não está entre elas."),
        ("Nenhuma ação obrigatória. Ao atualizar a integração, confira que ela não passou a pedir uma das "
         "versões listadas."),
        "Package that had malicious versions (not the required one)",
        ("The package had versions published with malicious code ({versoes}; {ids}), usually because the author's "
         "account was compromised. The version required in manifest.json ({pedido}) is not one of them."),
        ("No action required. When updating the integration, check it did not start requiring one of the "
         "listed versions.")),
    "typosquatting": (
        Severity.MEDIUM, "Nome de dependência parecido com um pacote popular",
        ("O pacote {nome} fica a uma letra de {popular}, um pacote muito usado. Nomes assim são usados para enganar "
        "quem instala (typosquatting). Pode ser só um pacote legítimo de nome parecido."),
        "Confira no PyPI quem publica {nome} e se não deveria ser {popular}.",
        "Dependency name similar to a popular package",
        ("The package {nome} is one letter away from {popular}, a widely used package. Names like this are used to "
        "trick whoever installs them (typosquatting). It may just be a legitimate package with a similar name."),
        "Check on PyPI who publishes {nome} and whether it should be {popular}."),
}


def texts(kind: str, **values: str) -> tuple[Severity, str, str, str, dict[str, str]]:
    sev, title, why, todo, title_en, why_en, todo_en = TEXTS[kind]
    return (sev, title, why.format(**values), todo.format(**values),
            en_text(title_en, why_en.format(**values), todo_en.format(**values)))


async def malicious_details(http, ids: list[str]) -> dict[str, list[dict]]:
    """Id MAL-… -> lista ``affected`` do aviso (só o id é enviado). Ids que falharem ficam de fora."""
    out: dict[str, list[dict]] = {}
    for vid in sorted(set(ids)):
        if not _SAFE_ID.match(vid):
            continue
        try:
            data = await http.get_json(OSV_VULN.format(vid))
        except Exception as err:  # noqa: BLE001 - sem o detalhe, o aviso fica como "todas as versões"
            _LOGGER.debug("Detalhe do aviso %s na OSV indisponível: %s", vid, type(err).__name__)
            continue
        if isinstance(data, dict) and isinstance(data.get("affected"), list):
            out[vid] = data["affected"]
    return out


def _v(text: str):
    try:
        return Version(str(text))
    except InvalidVersion:
        return None


def affected_summary(affected: list[dict], name: str) -> tuple[bool, list[str], list[tuple]]:
    """(todas as versões?, versões listadas, faixas [(introduzida, corrigida, última afetada)]) do pacote."""
    versions: list[str] = []
    ranges: list[tuple] = []
    entries = [a for a in affected if normalize(str((a.get("package") or {}).get("name") or "")) == name]
    for a in entries:
        versions += [str(v) for v in a.get("versions") or []]
        for r in a.get("ranges") or []:
            if r.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            intro = fixed = last = None
            for ev in r.get("events") or []:
                intro = ev.get("introduced", intro)
                fixed = ev.get("fixed", fixed)
                last = ev.get("last_affected", last)
            ranges.append((intro, fixed, last))
    everything = not entries or (not versions and not ranges) or any(
        str(i) in ("0", "") and not f and not la for i, f, la in ranges)
    return everything, sorted(set(versions), key=lambda x: (_v(x) is None, _v(x) or x)), ranges


def version_is_affected(version: str, versions: list[str], ranges: list[tuple]) -> bool:
    if version in versions:
        return True
    v = _v(version)
    if v is None:
        return True  # versão estranha: na dúvida, afetada
    for intro, fixed, last in ranges:
        lo = _v(intro) if intro not in (None, "0") else None
        if lo is not None and v < lo:
            continue
        if fixed and (hi := _v(fixed)) is not None and v >= hi:
            continue
        if last and (hi := _v(last)) is not None and v > hi:
            continue
        return True
    return False


def malicious_verdict(raw: str, name: str, affected: list[dict] | None) -> tuple[str, list[str]]:
    """'afetada' (a versão pedida é maliciosa ou não dá para saber), 'faixa' (a faixa pedida permite versões
    maliciosas) ou 'fora' (só outras versões do pacote foram maliciosas), com as versões maliciosas listadas."""
    if affected is None:
        return "afetada", []
    everything, versions, ranges = affected_summary(affected, name)
    if everything:
        return "afetada", versions
    try:
        spec = Requirement(raw.strip()).specifier
    except InvalidRequirement:
        return "afetada", versions
    exact = [s.version for s in spec if s.operator in ("==", "===") and "*" not in s.version]
    if exact:
        return ("afetada" if any(version_is_affected(v, versions, ranges) for v in exact) else "fora"), versions
    if not versions or any(spec.contains(v, prereleases=True) for v in versions if _v(v)):
        return "faixa", versions
    return "fora", versions
