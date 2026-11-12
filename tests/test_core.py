import io
import tarfile
import zipfile

import pytest

from auditor.allowlist import apply_allowlist
from auditor.config import AllowlistEntry, Options
from auditor.diff import compare
from auditor.models import ScanResult, Severity
from auditor.net import EgressDeniedError, SafeHttpClient
from auditor.publisher import build_states
from auditor.safe_archive import UnsafeArchiveError, extract
from auditor.scoring import summarize
from auditor.supervisor import CoreStatesPublisher, ForbiddenPathError, SupervisorClient

from .conftest import make_finding


# --- Modelos / diff -----------------------------------------------------------


def test_fingerprint_ignores_line_and_whitespace():
    a = make_finding(line=10, snippet="eval( payload )")
    b = make_finding(line=99, snippet="eval(payload)")
    assert a.fingerprint == b.fingerprint
    assert a.fingerprint != make_finding(snippet="exec(payload)").fingerprint


def test_finding_roundtrip():
    f = make_finding()
    again = type(f).from_dict(f.to_dict())
    assert again.severity is Severity.HIGH and again.fingerprint == f.fingerprint


def test_compare_marks_new_and_resolved():
    prev = ScanResult("1", "t", findings=[make_finding(), make_finding(rule_id="auditor.outra", snippet="x")])
    cur = ScanResult("2", "t", findings=[make_finding(), make_finding(rule_id="auditor.nova", snippet="y")])
    compare(cur, prev)
    assert [f.is_new for f in cur.findings] == [False, True]
    assert [r["rule_id"] for r in cur.resolved] == ["auditor.outra"]
    assert cur.previous_scan_id == "1"


def test_first_scan_is_baseline():
    cur = ScanResult("1", "t", findings=[make_finding()])
    compare(cur, None)
    assert not cur.findings[0].is_new


# --- Allowlist e pontuação ---------------------------------------------------


def test_allowlist_by_component_rule_and_path():
    findings = [
        make_finding(),
        make_finding(component="outra"),
        make_finding(rule_id="bandit.B602", file="custom_components/minha_integracao/util.py"),
    ]
    entries = (
        AllowlistEntry(component="minha_integracao", rule="auditor.eval-dinamico", reason="revisado"),
        AllowlistEntry(component="*", rule="bandit.*", path="*/util.py", reason="falso positivo"),
    )
    assert apply_allowlist(findings, entries) == 2
    assert [f.suppressed for f in findings] == [True, False, True]
    assert findings[0].suppression_reason == "revisado"


def test_options_parse_allowlist_and_ignores_invalid():
    opts = Options.from_dict(
        {"allowlist": [{"component": "a", "rule": "r", "reason": "ok"}, {"rule": "sem componente"}], "github_token": ""}
    )
    assert len(opts.allowlist) == 1 and opts.github_token is None


def test_scoring_ignores_suppressed_and_caps():
    findings = [make_finding(severity=Severity.CRITICAL, snippet=str(i)) for i in range(5)]
    findings.append(make_finding(component="limpa_mas_suprimida", suppressed=True))
    summaries = summarize(findings, {("integracao", "sem_achados"): {"versao": "1.0"}})
    by_name = {s.name: s for s in summaries}
    assert by_name["minha_integracao"].score == 100
    assert by_name["limpa_mas_suprimida"].score == 0
    assert by_name["sem_achados"].score == 0 and by_name["sem_achados"].metadata == {"versao": "1.0"}
    assert summaries[0].name == "minha_integracao"


# --- Rede ---------------------------------------------------------------------


def test_egress_allowlist():
    client = SafeHttpClient()
    client.check_url("https://api.github.com/repos/x/y")
    with pytest.raises(EgressDeniedError):
        client.check_url("http://api.github.com/repos/x/y")  # sem TLS
    with pytest.raises(EgressDeniedError):
        client.check_url("https://exfiltra.example.com/")
    with pytest.raises(EgressDeniedError):
        client.check_url("https://api.github.com.evil.com/")


def test_github_token_only_to_github_hosts():
    client = SafeHttpClient(github_token="ghp_tokenzinho")
    assert client._headers_for("https://api.github.com/x", None)["Authorization"] == "Bearer ghp_tokenzinho"
    assert "Authorization" not in client._headers_for("https://objects.githubusercontent.com/x", None)
    assert "Authorization" not in client._headers_for("https://ghcr.io/v2/", None)


# --- Supervisor --------------------------------------------------------------


async def test_supervisor_client_blocks_unlisted_paths():
    client = SupervisorClient(session=None, token="t")  # type: ignore[arg-type]
    for path in ("/addons/core_ssh/stop", "/addons/x/options", "/backups", "/addons/../host/reboot"):
        with pytest.raises(ForbiddenPathError):
            await client.get(path)


async def test_core_publisher_only_own_sensors():
    pub = CoreStatesPublisher(session=None, token="t")  # type: ignore[arg-type]
    with pytest.raises(ForbiddenPathError):
        await pub.set_state("switch.porta_garagem", "on", {})
    with pytest.raises(ForbiddenPathError):
        await pub.set_state("sensor.outro", "1", {})


def test_build_states():
    result = ScanResult("20261112T000000000000Z", "2026-11-12T00:00:00+00:00", finished_at="2026-11-12T00:01:00+00:00")
    result.findings = [make_finding(), make_finding(snippet="b", is_new=True), make_finding(snippet="c", suppressed=True)]
    states = build_states(result, "concluida")
    assert states["sensor.security_auditor_alertas_altos"][0] == 2
    assert states["sensor.security_auditor_novos_achados"][0] == 1
    assert states["sensor.security_auditor_ultima_varredura"][0] == "2026-11-12T00:01:00+00:00"
    assert states["sensor.security_auditor_status"][0] == "concluida"
    assert build_states(None, "ocioso")["sensor.security_auditor_alertas_altos"][0] == "unknown"


# --- Extração segura ---------------------------------------------------------


def _tar(path, entries):
    with tarfile.open(path, "w:gz") as tar:
        for name, kind, data in entries:
            info = tarfile.TarInfo(name)
            if kind == "file":
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
            elif kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = data
                tar.addfile(info)
            elif kind == "fifo":
                info.type = tarfile.FIFOTYPE
                tar.addfile(info)


def test_extract_tar_ok_and_skips_links(tmp_path):
    arc = tmp_path / "a.tar.gz"
    _tar(arc, [("repo-1.0/a.py", "file", b"x=1"), ("repo-1.0/link", "symlink", "/config/secrets.yaml")])
    out = extract(arc, tmp_path / "out")
    assert "repo-1.0/a.py" in out and "<link> repo-1.0/link" in out
    assert not (tmp_path / "out/repo-1.0/link").exists()


@pytest.mark.parametrize(
    "entries",
    [
        [("../fora.py", "file", b"x")],
        [("/etc/passwd", "file", b"x")],
        [("a/../../fora.py", "file", b"x")],
        [("fifo", "fifo", None)],
    ],
)
def test_extract_tar_rejects_dangerous(tmp_path, entries):
    arc = tmp_path / "a.tar.gz"
    _tar(arc, entries)
    with pytest.raises(UnsafeArchiveError):
        extract(arc, tmp_path / "out")


def test_extract_limits(tmp_path):
    arc = tmp_path / "a.zip"
    with zipfile.ZipFile(arc, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("grande.bin", b"0" * 10_000)
    with pytest.raises(UnsafeArchiveError):
        extract(arc, tmp_path / "out", max_total=1_000)
    assert extract(arc, tmp_path / "out2") == ["grande.bin"]
