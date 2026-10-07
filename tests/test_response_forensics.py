import json
import os
import stat
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from app.core.events import SecurityEvent
from app.response.forensics import (
    COMMAND_ARTIFACTS,
    SAFE_ENVIRONMENT,
    EvidenceSettings,
    ForensicEvidenceCollector,
    ForensicEvidenceError,
    is_valid_capture_id,
    sanitize_text,
)

NOW = datetime(2026, 10, 5, 12, 0, tzinfo=UTC)


def detection(
    *,
    severity: str = "high",
    event_type: str = "SSH_USER_ENUMERATION_ATTEMPT",
    source_ip: str = "192.168.1.50",
    evidence: dict | None = None,
) -> SecurityEvent:
    return SecurityEvent(
        event_id=uuid4(),
        timestamp=NOW,
        agent_id="agent-1",
        hostname="srv-test",
        source="detection-engine",
        category="detection",
        event_type=event_type,
        severity=severity,
        description="Detección de prueba",
        evidence=evidence or {"source_ip": source_ip},
    )


class RecordingRunner:
    def __init__(self, outputs: dict[str, object] | None = None) -> None:
        self.outputs = outputs or {}
        self.commands: list[list[str]] = []

    def __call__(self, command: list[str], timeout: int) -> tuple[int, str, str]:
        assert timeout > 0
        self.commands.append(list(command))
        result = self.outputs.get(command[0], (0, f"{command[0]} ok\n", ""))
        if isinstance(result, BaseException):
            raise result
        return result  # type: ignore[return-value]


def collector(
    tmp_path: Path,
    *,
    enabled: bool = True,
    max_bytes: int = 262_144,
    max_total_bytes: int = 52_428_800,
    retention_days: int = 7,
    runner: RecordingRunner | None = None,
    processes: list[dict] | None = None,
) -> tuple[ForensicEvidenceCollector, RecordingRunner]:
    recording = runner or RecordingRunner()
    instance = ForensicEvidenceCollector(
        EvidenceSettings(
            enabled=enabled,
            base_dir=tmp_path / "state" / "evidence",
            retention_days=retention_days,
            max_bytes=max_bytes,
            max_total_bytes=max_total_bytes,
            command_timeout_seconds=3,
        ),
        runner=recording,
        process_provider=lambda _ip: list(processes or []),
        clock=lambda: NOW,
    )
    return instance, recording


def mode(path: Path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


def make_symlink(link: Path, target: Path) -> None:
    """Crea un symlink real; omite la prueba solo si el SO lo deniega.

    En Windows crear symlinks exige el privilegio SeCreateSymbolicLink
    (WinError 1314) o el modo desarrollador. Se intenta siempre la
    creación; únicamente esa negativa por falta de privilegio omite la
    prueba. Cualquier otro error se propaga.
    """
    try:
        link.symlink_to(target)
    except NotImplementedError:
        pytest.skip("El sistema no implementa symlinks.")
    except OSError as error:
        if getattr(error, "winerror", None) == 1314:
            pytest.skip(
                "Windows denegó crear el symlink por falta del privilegio "
                f"requerido (WinError 1314): {error}"
            )
        raise


def test_capture_creates_restrictive_directory_files_and_metadata(
    tmp_path: Path,
) -> None:
    instance, runner = collector(
        tmp_path,
        processes=[
            {
                "pid": 10,
                "ppid": 1,
                "name": "sshd",
                "username": "root",
                "status": "sleeping",
                "connected_to_source": True,
                "cmdline": "sshd: invalid [preauth]",
            }
        ],
    )
    event = detection()

    result = instance.capture(event, incident_id="INC-0123456789ABCDEF")

    assert result is not None
    capture_dir = tmp_path / "state" / "evidence" / str(event.event_id)
    assert result.directory == capture_dir
    if os.name == "posix":
        # Los bits POSIX solo son verificables en POSIX; en Windows el
        # acceso depende de ACL heredadas y st_mode no los refleja.
        assert mode(tmp_path / "state" / "evidence") == 0o700
        assert mode(capture_dir) == 0o700

    files = sorted(path.name for path in capture_dir.iterdir())
    assert "metadata.json" in files
    assert "relevant_processes.txt" in files
    assert "ssh_journal.txt" in files
    for path in capture_dir.iterdir():
        if os.name == "posix":
            assert mode(path) == 0o600
            assert not mode(path) & 0o077

    metadata = json.loads((capture_dir / "metadata.json").read_text())
    assert metadata["capture_id"] == str(event.event_id)
    assert metadata["incident_id"] == "INC-0123456789ABCDEF"
    assert metadata["detection_event_id"] == str(event.event_id)
    assert metadata["detection_type"] == "SSH_USER_ENUMERATION_ATTEMPT"
    assert metadata["severity"] == "high"
    assert metadata["source_ip"] == "192.168.1.50"
    assert metadata["hostname"] == "srv-test"
    assert metadata["agent_id"] == "agent-1"
    assert metadata["captured_at"] == NOW.isoformat()
    assert metadata["status"] == "complete"
    assert metadata["total_bytes"] <= metadata["max_bytes"]
    assert {artifact["name"] for artifact in metadata["artifacts"]} >= {
        "network_connections",
        "listening_sockets",
        "logged_in_users",
        "ssh_journal",
        "ssh_services",
        "nftables_auditoria",
        "relevant_processes",
    }
    assert not list((tmp_path / "state" / "evidence").glob(".tmp-*"))
    assert result.event_evidence()["storage"] == "agent-local"
    assert str(tmp_path) not in json.dumps(result.event_evidence())
    assert len(runner.commands) == len(COMMAND_ARTIFACTS) + 1


def test_capture_is_disabled_by_settings_and_for_non_high_detections(
    tmp_path: Path,
) -> None:
    disabled, runner = collector(tmp_path, enabled=False)
    assert disabled.capture(detection(), incident_id=None) is None
    assert runner.commands == []
    assert not (tmp_path / "state" / "evidence").exists()

    enabled, runner = collector(tmp_path)
    assert enabled.capture(detection(severity="medium"), incident_id=None) is None
    assert runner.commands == []


def test_commands_are_fixed_and_never_built_from_event_data(tmp_path: Path) -> None:
    instance, runner = collector(tmp_path)
    hostile = detection(
        evidence={
            "source_ip": "192.168.1.50; rm -rf /",
            "users": ["$(reboot)", "`id`"],
            "command": "cat /etc/shadow",
        }
    )

    instance.capture(hostile, incident_id=None)

    allowed = {tuple(command) for _, _, command in COMMAND_ARTIFACTS}
    for command in runner.commands:
        assert tuple(command) in allowed or command[0] == "journalctl"
        joined = " ".join(command)
        assert "rm -rf" not in joined
        assert "reboot" not in joined
        assert "shadow" not in joined


def test_default_runner_uses_argument_list_timeout_and_minimal_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured.update(kwargs)
        return subprocess.CompletedProcess(command, 0, "ok", "")

    monkeypatch.setenv("AUDITORIA_RESEND_API_KEY", "valor-que-no-debe-filtrarse")
    monkeypatch.setattr(
        "app.response.forensics.shutil.which",
        lambda name, path=None: f"/usr/bin/{name}",
    )
    monkeypatch.setattr("app.response.forensics.subprocess.run", fake_run)

    ForensicEvidenceCollector._default_runner(["ss", "-tunap"], 4)

    assert captured["command"] == ["/usr/bin/ss", "-tunap"]
    assert captured["timeout"] == 4
    assert captured.get("shell") in (None, False)
    assert captured["env"] == SAFE_ENVIRONMENT
    assert "AUDITORIA_RESEND_API_KEY" not in captured["env"]


def test_capture_enforces_maximum_size(tmp_path: Path) -> None:
    big = "x" * 50_000 + "\n"
    runner = RecordingRunner({name: (0, big, "") for name in ("ss", "who", "nft")})
    instance, _ = collector(tmp_path, max_bytes=16_384, runner=runner)

    result = instance.capture(detection(), incident_id=None)

    assert result is not None
    metadata = result.metadata
    assert metadata["total_bytes"] <= 16_384
    assert metadata["truncated"] is True
    capture_dir = result.directory
    assert capture_dir is not None
    data_bytes = sum(
        path.stat().st_size
        for path in capture_dir.iterdir()
        if path.name != "metadata.json"
    )
    assert data_bytes <= 16_384
    assert any(artifact["status"] == "skipped" for artifact in metadata["artifacts"])


def test_partial_errors_are_recorded_without_aborting_capture(tmp_path: Path) -> None:
    runner = RecordingRunner(
        {
            "nft": FileNotFoundError("nft"),
            "who": subprocess.TimeoutExpired(["who"], 3),
            "systemctl": (1, "", "Unit sshd.service could not be found."),
        }
    )
    instance, _ = collector(tmp_path, runner=runner)

    result = instance.capture(detection(), incident_id=None)

    assert result is not None
    assert result.status == "partial"
    by_name = {artifact["name"]: artifact for artifact in result.metadata["artifacts"]}
    assert by_name["nftables_auditoria"]["status"] == "unavailable"
    assert by_name["logged_in_users"]["status"] == "error"
    assert "tiempo" in by_name["logged_in_users"]["error"]
    assert by_name["ssh_services"]["status"] == "error"
    assert by_name["network_connections"]["status"] == "ok"


def test_failed_capture_cleans_temporary_directory(tmp_path: Path) -> None:
    def failing_processes(_ip):
        raise RuntimeError("psutil no disponible")

    instance = ForensicEvidenceCollector(
        EvidenceSettings(enabled=True, base_dir=tmp_path / "evidence"),
        runner=RecordingRunner({"ss": FileNotFoundError("ss")}),
        process_provider=failing_processes,
        clock=lambda: NOW,
    )

    result = instance.capture(detection(), incident_id=None)

    assert result is not None
    by_name = {artifact["name"]: artifact for artifact in result.metadata["artifacts"]}
    assert by_name["relevant_processes"]["status"] == "error"
    assert not list((tmp_path / "evidence").glob(".tmp-*"))


def test_capture_refuses_symlinked_base_directory_and_duplicate_capture(
    tmp_path: Path,
) -> None:
    target = tmp_path / "otro-lugar"
    target.mkdir()
    (tmp_path / "state").mkdir()
    make_symlink(tmp_path / "state" / "evidence", target)
    instance, _ = collector(tmp_path)

    with pytest.raises(ForensicEvidenceError):
        instance.capture(detection(), incident_id=None)
    assert list(target.iterdir()) == []

    (tmp_path / "state" / "evidence").unlink()
    event = detection()
    instance.capture(event, incident_id=None)
    with pytest.raises(ForensicEvidenceError):
        instance.capture(event, incident_id=None)


def test_evidence_is_sanitized_of_obvious_secrets(tmp_path: Path) -> None:
    secret_output = (
        "ESTAB 0 0 10.0.0.5:22 192.168.1.50:51515 users:((sshd))\n"
        "password=hunter2 token: abcdef123456 api_key=valor-api-ficticio-123\n"
        "Authorization: Bearer tokenficticio.abc.def\n"
        "-----BEGIN OPENSSH PRIVATE KEY-----\nCONTENIDOFICTICIO\n"
        "-----END OPENSSH PRIVATE KEY-----\n"
    )
    runner = RecordingRunner({"ss": (0, secret_output, "")})
    instance, _ = collector(
        tmp_path,
        runner=runner,
        processes=[
            {
                "pid": 7,
                "name": "python3",
                "cmdline": "python3 app.py --password s3cr3t --token=xyz123",
                "connected_to_source": True,
            }
        ],
    )

    result = instance.capture(detection(), incident_id=None)

    assert result is not None
    assert result.directory is not None
    content = "\n".join(path.read_text() for path in result.directory.iterdir())
    for secret in (
        "hunter2",
        "abcdef123456",
        "valor-api-ficticio-123",
        "tokenficticio",
        "CONTENIDOFICTICIO",
        "s3cr3t",
        "xyz123",
    ):
        assert secret not in content
    assert "[REDACTED]" in content
    assert "192.168.1.50:51515" in content
    for forbidden in ("agent-identity", "agent.env", "credential"):
        assert forbidden not in " ".join(
            " ".join(command) for command in runner.commands
        )


def test_sanitize_text_redacts_url_and_basic_auth_credentials() -> None:
    text = sanitize_text(
        "git clone https://deploy:claveurl@git.example/repo.git\n"
        "curl -u admin:clavecurl https://api.example\n"
    )

    assert "claveurl" not in text
    assert "clavecurl" not in text
    assert "https://deploy:[REDACTED]@git.example" in text
    assert "admin:[REDACTED]" in text


def test_sanitize_text_keeps_non_secret_content() -> None:
    assert sanitize_text("Accepted publickey for admin") == (
        "Accepted publickey for admin"
    )
    assert "[REDACTED]" in sanitize_text("secret = valor")


def _make_capture(base: Path, *, age_days: float, size: int = 10) -> Path:
    capture = base / str(uuid4())
    capture.mkdir(parents=True, mode=0o700)
    (capture / "metadata.json").write_bytes(b"x" * size)
    timestamp = (NOW - timedelta(days=age_days)).timestamp()
    os.utime(capture, (timestamp, timestamp))
    return capture


def test_retention_removes_expired_and_temporary_captures_only(tmp_path: Path) -> None:
    instance, _ = collector(tmp_path, retention_days=7)
    base = tmp_path / "state" / "evidence"
    old = _make_capture(base, age_days=8)
    recent = _make_capture(base, age_days=1)
    temporary = base / f".tmp-{uuid4()}"
    temporary.mkdir()
    unrelated = base / "no-tocar"
    unrelated.mkdir()
    outside = tmp_path / "fuera"
    outside.mkdir()
    (outside / "importante.txt").write_text("datos")
    symlink = base / str(uuid4())
    make_symlink(symlink, outside)

    removed = instance.purge(now=NOW)

    assert removed == 3
    assert not old.exists()
    assert not temporary.exists()
    assert not os.path.lexists(symlink)
    assert recent.exists()
    assert unrelated.exists()
    assert (outside / "importante.txt").read_text() == "datos"


def test_retention_enforces_total_size_removing_oldest_first(tmp_path: Path) -> None:
    instance, _ = collector(tmp_path, max_total_bytes=2_500)
    base = tmp_path / "state" / "evidence"
    oldest = _make_capture(base, age_days=3, size=1_000)
    middle = _make_capture(base, age_days=2, size=1_000)
    newest = _make_capture(base, age_days=1, size=1_000)

    removed = instance.purge(now=NOW)

    assert removed == 1
    assert not oldest.exists()
    assert middle.exists()
    assert newest.exists()


def test_capture_ids_must_be_canonical_uuids() -> None:
    assert is_valid_capture_id(str(uuid4()))
    for value in ("../etc", "..", "", "INC-1", str(uuid4()).upper()):
        assert not is_valid_capture_id(value)
