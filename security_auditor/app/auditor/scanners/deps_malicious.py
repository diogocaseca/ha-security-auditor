"""Dependências maliciosas: pacotes catalogados como maliciosos na OSV e nomes de typosquatting.

- OSV (api.osv.dev): a consulta em lote devolve os avisos de cada pacote; os que começam com
  ``MAL-`` são pacotes maliciosos catalogados (OpenSSF Malicious Packages). Só o nome do pacote vai.
- Typosquatting: o nome fica a uma "letra" (troca, falta, sobra ou inversão) de um pacote popular
  em integrações do HA, sem ser ele.
"""

from __future__ import annotations

import re

from ..models import Severity, en_text

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
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
KNOWN_NEIGHBOURS = frozenset({"pyaml", "websocket", "pycrypto", "aiosignal"})
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
