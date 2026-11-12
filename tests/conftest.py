from __future__ import annotations

from pathlib import Path

import pytest

from auditor.config import Options, Paths
from auditor.masking import Masker
from auditor.models import ComponentType, Finding, Severity
from auditor.storage import Storage

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def paths(tmp_path: Path) -> Paths:
    config = tmp_path / "config"
    data = tmp_path / "data"
    config.mkdir()
    data.mkdir()
    return Paths(config_dir=config, data_dir=data, rules_dir=Path(__file__).parents[1] / "security_auditor/app/rules")


@pytest.fixture
def storage(paths: Paths) -> Storage:
    return Storage(paths.db_path, paths.reports_dir)


@pytest.fixture
def masker() -> Masker:
    return Masker()


@pytest.fixture
def options() -> Options:
    return Options(scan_on_start=False, scan_interval_hours=0)


def make_finding(**overrides) -> Finding:
    base = dict(
        component="minha_integracao",
        component_type=ComponentType.INTEGRATION,
        category="execucao_dinamica",
        rule_id="auditor.eval-dinamico",
        severity=Severity.HIGH,
        title="eval com dados dinâmicos",
        explanation="eval executa texto como código.",
        recommendation="Revise a origem dos dados.",
        file="custom_components/minha_integracao/__init__.py",
        line=10,
        snippet="eval(payload)",
        source="semgrep",
    )
    base.update(overrides)
    return Finding(**base)
