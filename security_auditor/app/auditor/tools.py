"""Execução segura das ferramentas externas (semgrep, bandit, pip-audit, trivy).

 - ambiente mínimo: o SUPERVISOR_TOKEN e demais variáveis do add-on NÃO
   são repassados às ferramentas;
 - HOME isolado em diretório temporário;
 - telemetria e checagem de versão desligadas;
 - tempo limite e limite de saída; o processo é morto se estourar.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

_LOGGER = logging.getLogger(__name__)

MAX_OUTPUT = 64 * 1024 * 1024  # 64 MiB de JSON é mais que suficiente


class ToolNotFoundError(Exception):
    pass


class ToolTimeoutError(Exception):
    pass


@dataclass
class ToolResult:
    returncode: int
    stdout: str
    stderr: str


def find_tool(name: str) -> str:
    """Procura no PATH e ao lado do interpretador atual (venv de desenvolvimento)."""
    found = shutil.which(name)
    if found:
        return found
    sibling = Path(sys.executable).parent / name
    if sibling.is_file() and os.access(sibling, os.X_OK):
        return str(sibling)
    raise ToolNotFoundError(f"Ferramenta '{name}' não encontrada")


def tool_env(home: Path, extra: dict[str, str] | None = None) -> dict[str, str]:
    home.mkdir(parents=True, exist_ok=True)
    path = os.pathsep.join(
        dict.fromkeys([str(Path(sys.executable).parent), "/usr/local/bin", "/usr/bin", "/bin"])
    )
    env = {
        "PATH": path,
        "HOME": str(home),
        "XDG_CACHE_HOME": str(home / ".cache"),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "NO_COLOR": "1",
        "TERM": "dumb",
        "PYTHONDONTWRITEBYTECODE": "1",
        # Semgrep: sem métricas, sem checagem de versão, sem registro remoto.
        "SEMGREP_SEND_METRICS": "off",
        "SEMGREP_ENABLE_VERSION_CHECK": "0",
        # Trivy (Fase 2)
        "TRIVY_DISABLE_TELEMETRY": "true",
        "TRIVY_SKIP_VERSION_CHECK": "true",
    }
    if extra:
        env.update(extra)
    return env


async def run_tool(
    args: list[str],
    *,
    home: Path,
    timeout: float,
    cwd: Path | None = None,
    extra_env: dict[str, str] | None = None,
) -> ToolResult:
    exe = find_tool(args[0])
    _LOGGER.debug("Executando %s (%d argumentos)", args[0], len(args) - 1)
    proc = await asyncio.create_subprocess_exec(
        exe,
        *args[1:],
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=str(cwd or home),
        env=tool_env(home, extra_env),
        limit=MAX_OUTPUT,
        start_new_session=True,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except TimeoutError as err:
        _kill(proc)
        await proc.wait()
        raise ToolTimeoutError(f"{args[0]} excedeu {int(timeout)}s") from err
    except asyncio.CancelledError:
        _kill(proc)
        raise
    if len(stdout) > MAX_OUTPUT:
        raise ToolTimeoutError(f"Saída de {args[0]} grande demais")
    return ToolResult(
        returncode=proc.returncode if proc.returncode is not None else -1,
        stdout=stdout.decode("utf-8", "replace"),
        stderr=stderr.decode("utf-8", "replace")[-4000:],
    )


def _kill(proc: asyncio.subprocess.Process) -> None:
    """Mata o grupo de processos inteiro (semgrep cria semgrep-core)."""
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(proc.pid, 9)
    with contextlib.suppress(ProcessLookupError):
        proc.kill()
