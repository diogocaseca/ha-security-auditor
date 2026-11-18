"""Sinais de cadeia de suprimentos no GitHub: tag reescrita, repositório transferido e arquivado."""

from __future__ import annotations

import json

from auditor.config import Paths
from auditor.models import Severity
from auditor.net import HttpError
from auditor.scanners import repo_signals
from auditor.scanners.repo_signals import RepoSignalsScanner
from auditor.storage import Storage

from .test_fase1 import RULES, FakeGitHub, _ctx

API = "https://api.github.com/repos"


def _setup(tmp_path, recorded="dono/meu-card", version="v2.0.0"):
    config = tmp_path / "config"
    (config / "www/community/meu-card").mkdir(parents=True)
    (config / "www/community/meu-card/meu-card.js").write_text("x")
    (config / ".storage").mkdir()
    (config / ".storage/hacs.repositories").write_text(json.dumps({"data": {"9": {
        "full_name": recorded, "category": "plugin", "version_installed": version}}}))
    data = tmp_path / "data"
    data.mkdir()
    paths = Paths(config_dir=config, data_dir=data, rules_dir=RULES)
    return paths, Storage(paths.db_path, paths.reports_dir)


def _routes(full_name="dono/meu-card", archived=False, sha="a" * 40):
    return {f"{API}/dono/meu-card": {"full_name": full_name, "archived": archived},
            f"{API}/dono/meu-card/git/ref/tags/v2.0.0": {"object": {"sha": sha, "type": "commit"}}}


async def _scan(paths, storage, tmp_path, gh, scan_id="s1"):
    ctx = _ctx(paths, tmp_path, http=gh, storage=storage)
    ctx.scan_id = scan_id
    return {f.rule_id: f for f in await RepoSignalsScanner().scan(ctx)}


async def test_clean_repo_and_daily_cache(tmp_path):
    paths, storage = _setup(tmp_path)
    gh = FakeGitHub(_routes())
    assert await _scan(paths, storage, tmp_path, gh) == {}
    gh.calls.clear()
    assert await _scan(paths, storage, tmp_path, gh) == {} and gh.calls == []  # consultado no máximo 1x/dia


async def test_moved_and_archived(tmp_path):
    paths, storage = _setup(tmp_path)
    by = await _scan(paths, storage, tmp_path, FakeGitHub(_routes(full_name="Outro-Dono/meu-card", archived=True)))
    assert set(by) == {"auditor.repositorio.transferido", "auditor.repositorio.arquivado"}
    moved = by["auditor.repositorio.transferido"]
    assert moved.severity is Severity.MEDIUM and "dono/meu-card" in moved.explanation and "Outro-Dono" in moved.explanation
    assert by["auditor.repositorio.arquivado"].severity is Severity.INFO


async def test_case_only_difference_is_not_a_move(tmp_path):
    paths, storage = _setup(tmp_path, recorded="Dono/Meu-Card")
    routes = {f"{API}/Dono/Meu-Card": {"full_name": "dono/meu-card"},
              f"{API}/Dono/Meu-Card/git/ref/tags/v2.0.0": {"object": {"sha": "a" * 40}}}
    assert await _scan(paths, storage, tmp_path, FakeGitHub(routes)) == {}


async def test_retagged_version(tmp_path, monkeypatch):
    paths, storage = _setup(tmp_path)
    assert await _scan(paths, storage, tmp_path, FakeGitHub(_routes(sha="a" * 40))) == {}
    monkeypatch.setattr(repo_signals, "CHECK_TTL", 0)  # passou um dia
    by = await _scan(paths, storage, tmp_path, FakeGitHub(_routes(sha="b" * 40)), scan_id="s2")
    (f,) = by.values()
    assert f.rule_id == "auditor.repositorio.tag-reescrita" and f.severity is Severity.HIGH
    assert "aaaaaaaaaaaa" in f.explanation and "bbbbbbbbbbbb" in f.explanation
    # Continua avisando enquanto a tag apontar para o commit diferente do primeiro visto.
    again = await _scan(paths, storage, tmp_path, FakeGitHub(_routes(sha="b" * 40)), scan_id="s3")
    assert set(again) == {"auditor.repositorio.tag-reescrita"}


async def test_rate_limit_just_skips(tmp_path):
    class Limited(FakeGitHub):
        async def get_json(self, url, headers=None):
            raise HttpError(403, url)

    paths, storage = _setup(tmp_path)
    assert await _scan(paths, storage, tmp_path, Limited({})) == {}


async def test_commit_installs_skip_the_tag_check(tmp_path):
    paths, storage = _setup(tmp_path, version="1234567abcdef")
    gh = FakeGitHub(_routes())
    assert await _scan(paths, storage, tmp_path, gh) == {}
    assert not any("/git/ref/" in c for c in gh.calls)
