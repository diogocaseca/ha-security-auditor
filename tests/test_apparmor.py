"""Regressão do perfil AppArmor.

O AppArmor avalia o caminho REAL de cada executável (depois de resolver links
simbólicos). Um link como /usr/bin/bashio -> /usr/lib/bashio/bashio, sem "x" no
destino, impede o add-on de iniciar ("env: can't execute 'bashio': Permission
denied"). Este teste interpreta as regras de arquivo do perfil e confere:
 - todos os executáveis da cadeia de inicialização e das ferramentas podem rodar;
 - nada pode ser executado de onde o add-on escreve nem de /config;
 - /config não pode ser escrito.

Se o Docker e a imagem local estiverem disponíveis, os caminhos reais são
obtidos de dentro da imagem; senão, usa a lista conhecida abaixo.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

PROFILE = Path(__file__).parents[1] / "security_auditor/apparmor.txt"
IMAGE = "local/security_auditor:dev"

# Comandos que o add-on executa (nomes como aparecem no PATH/shebangs).
COMMANDS = ["bashio", "env", "bash", "python3", "python", "semgrep", "bandit", "pip-audit", "trivy",
            "curl", "jq", "mkdir"]
# Caminhos reais conhecidos (imagem base Alpine do HA + pip), usados sem Docker.
KNOWN_REAL = [
    "/sbin/docker-init",
    "/run.sh",
    "/usr/lib/bashio/bashio",
    "/bin/busybox",
    "/bin/bash",
    "/usr/local/bin/python3.12",
    "/usr/local/bin/semgrep",
    "/usr/local/lib/python3.12/site-packages/semgrep/bin/semgrep-core",
    "/usr/local/bin/bandit",
    "/usr/local/bin/pip-audit",
    "/usr/local/bin/trivy",
    "/usr/bin/curl",
    "/usr/bin/jq",
    "/sbin/ldconfig",
]

_VARS = {"@{PROC}": "/proc", "@{pid}": "[0-9]+", "@{tid}": "[0-9]+"}
_RULE = re.compile(r"^\s*(deny\s+)?(owner\s+)?(/\S+|@\{PROC\}\S*)\s+([rwaklmix]+)\s*,\s*$")


def _glob_to_regex(glob: str) -> re.Pattern[str]:
    for var, rep in _VARS.items():
        glob = glob.replace(var, "\x00" + rep + "\x00")
    out, i, parts = "", 0, glob.split("\x00")
    for n, part in enumerate(parts):
        if n % 2 == 1:  # já é regex (variável)
            out += part
            continue
        i = 0
        while i < len(part):
            c = part[i]
            if part.startswith("**", i):
                out += ".*"
                i += 2
                continue
            if c == "*":
                out += "[^/]*"
            elif c == "{":
                j = part.index("}", i)
                out += "(?:" + "|".join(re.escape(x) for x in part[i + 1 : j].split(",")) + ")"
                i = j
            elif c == "?":
                out += "[^/]"
            else:
                out += re.escape(c)
            i += 1
    return re.compile(out + "$")


def _rules() -> list[tuple[bool, re.Pattern[str], str]]:
    rules = []
    for line in PROFILE.read_text().splitlines():
        m = _RULE.match(line)
        if m:
            rules.append((bool(m.group(1)), _glob_to_regex(m.group(3)), m.group(4)))
    return rules


def allowed(path: str, perm: str) -> bool:
    """Permissão concedida se alguma regra allow cobre e nenhuma deny cobre."""
    rules = _rules()
    if any(deny and rx.match(path) and perm in perms for deny, rx, perms in rules):
        return False
    return any(not deny and rx.match(path) and perm in perms for deny, rx, perms in rules)


def _real_paths_from_image() -> list[str] | None:
    if not shutil.which("docker"):
        return None
    script = (
        "for c in " + " ".join(COMMANDS) + "; do p=$(command -v $c) && realpath $p; done; "
        "realpath /usr/local/lib/python3*/site-packages/semgrep/bin/semgrep-core; "
        "for s in /usr/local/bin/semgrep /usr/local/bin/bandit /usr/local/bin/pip-audit /usr/lib/bashio/bashio /run.sh; do "
        "  i=$(head -1 $s | sed 's/^#! *//' | cut -d' ' -f1); realpath $i; done"
    )
    try:
        res = subprocess.run(  # noqa: S603
            ["docker", "run", "--rm", "--entrypoint", "sh", IMAGE, "-c", script],  # noqa: S607
            capture_output=True, text=True, timeout=60, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if res.returncode != 0 or not res.stdout.strip():
        return None
    return sorted(set(res.stdout.split()) | {"/sbin/docker-init", "/run.sh"})


def test_glob_translation():
    assert _glob_to_regex("/usr/lib/**").match("/usr/lib/bashio/bashio")
    assert not _glob_to_regex("/usr/lib/*").match("/usr/lib/bashio/bashio")
    assert _glob_to_regex("@{PROC}/@{pid}/fd/*").match("/proc/123/fd/4")
    assert _glob_to_regex("@{PROC}/{cpuinfo,meminfo}").match("/proc/meminfo")


@pytest.mark.parametrize("path", KNOWN_REAL)
def test_known_executables_allowed(path):
    assert allowed(path, "x"), f"AppArmor bloquearia a execução de {path}"


def test_real_executables_from_image():
    paths = _real_paths_from_image()
    if paths is None:
        pytest.skip("Docker ou imagem local indisponível")
    blocked = [p for p in paths if not allowed(p, "x")]
    assert blocked == [], f"AppArmor bloquearia: {blocked}"


@pytest.mark.parametrize("path", [
    "/data/cache/integrity/x/files/__init__.py",
    "/data/payload",
    "/tmp/auditor-1/src/install.sh",
    "/dev/shm/x",
    "/config/custom_components/x/run.sh",
])
def test_no_exec_from_writable_or_config(path):
    assert not allowed(path, "x")


@pytest.mark.parametrize("path", ["/config/secrets.yaml", "/config/custom_components/x/__init__.py", "/config/"])
def test_config_read_only(path):
    assert allowed(path, "r")
    assert not allowed(path, "w")


def test_state_writable():
    assert allowed("/data/auditor.db", "w") and allowed("/tmp/x", "w")
    assert not allowed("/usr/local/bin/trivy", "w") and not allowed("/app/auditor/net.py", "w")


def test_no_capabilities_granted():
    text = PROFILE.read_text()
    assert not re.search(r"^\s*capability\b", text, re.M), "o perfil não deve conceder capacidades"
    assert not re.search(r"^\s*file\s*,", text, re.M), "regra 'file,' liberaria tudo"
    assert "ux" not in re.findall(r"\b[rwaklmipux]+(?=,)", text) and " Ux" not in text
