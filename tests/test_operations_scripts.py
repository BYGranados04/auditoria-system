import os
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
OPERATION_SCRIPTS = (
    "preparar-instalacion.sh",
    "backup.sh",
    "restaurar-backup.sh",
    "actualizar.sh",
    "rollback.sh",
)
RELEASE_DIRECTORIES = (
    "app/agent",
    "app/api",
    "deploy/systemd",
    "scripts/lib",
)
RELEASE_FILES = (
    "app/agent/__main__.py",
    "app/api/main.py",
    "deploy/systemd/auditoria-agent.service",
    "deploy/systemd/auditoria-api.service",
    "scripts/lib/operaciones-comunes.sh",
    "scripts/preparar-instalacion.sh",
    "scripts/instalar-servicio.sh",
    "scripts/restaurar-backup.sh",
    "scripts/rollback.sh",
    "requirements.txt",
    "pyproject.toml",
)


def script(name: str) -> str:
    return (SCRIPTS / name).read_text(encoding="utf-8")


def create_complete_release(path: Path) -> Path:
    for relative in RELEASE_DIRECTORIES:
        (path / relative).mkdir(parents=True, exist_ok=True)
    for relative in RELEASE_FILES:
        target = path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("test fixture\n", encoding="utf-8")
    return path


def bash_executable() -> str:
    if os.name == "nt":
        candidate = Path("C:/Program Files/Git/bin/bash.exe")
        if candidate.is_file():
            return str(candidate)
    resolved = shutil.which("bash")
    assert resolved is not None
    return resolved


def validate_release(path: Path) -> subprocess.CompletedProcess[str]:
    common = (SCRIPTS / "lib" / "operaciones-comunes.sh").as_posix()
    return subprocess.run(
        [
            bash_executable(),
            "-lc",
            'source "$1"; validar_estructura_release "$2"',
            "release-validation",
            common,
            path.as_posix(),
        ],
        check=False,
        capture_output=True,
        text=True,
    )


def test_shell_scripts_are_lf_and_have_strict_mode() -> None:
    for path in SCRIPTS.rglob("*.sh"):
        content = path.read_bytes()
        assert b"\r\n" not in content
        assert content.startswith(b"#!/usr/bin/env bash\n")
        if path.name != "operaciones-comunes.sh":
            assert b"set -euo pipefail" in content


def test_operation_scripts_have_help_and_reject_unknown_arguments() -> None:
    for name in OPERATION_SCRIPTS:
        content = script(name)
        assert "-h|--help" in content
        assert "argumento no reconocido" in content


def test_bootstrap_is_explicit_and_reproducible() -> None:
    content = script("preparar-instalacion.sh")
    assert "python3.12 -m venv" in content
    assert "--no-deps --requirement" in content
    assert 'RAIZ_INSTALACION="/opt/auditoria-system"' in script(
        "lib/operaciones-comunes.sh"
    )
    assert "git clone" not in content
    assert "git pull" not in content


def test_backup_and_restore_handle_sqlite_and_sensitive_permissions() -> None:
    backup = script("backup.sh")
    restore = script("restaurar-backup.sh")
    common = script("lib/operaciones-comunes.sh")

    assert "source.backup(destination)" in common
    assert "PRAGMA integrity_check" in common
    assert "chmod 0600" in backup
    assert "agent-identity.json" in backup
    assert 'setfacl -m "u:${USUARIO_API}:r--"' in restore
    assert "puede leer auditoria.db después del restore" in restore
    assert "cat agent-identity.json" not in backup + restore
    assert "--no-start" in restore


def test_backup_destination_must_be_outside_active_installation() -> None:
    backup = script("backup.sh")
    common = script("lib/operaciones-comunes.sh")

    assert 'validar_destino_fuera_instalacion "${DESTINO_BASE}"' in backup
    assert '"${destino_resuelto}" != "${instalacion_resuelta}"/*' in common


def test_upgrade_requires_backup_and_never_pulls_or_resets_git() -> None:
    upgrade = script("actualizar.sh")
    rollback = script("rollback.sh")

    assert upgrade.index('SALIDA_BACKUP="$(bash') < upgrade.index(
        'mv "${RAIZ_INSTALACION}" "${CODIGO_ANTERIOR}"'
    )
    assert "--source" in upgrade
    assert "rollback automático" in upgrade
    assert "\ngit pull" not in upgrade
    assert "\ngit reset" not in upgrade + rollback


def test_rollback_restores_without_starting_and_stops_again_on_failure() -> None:
    rollback = script("rollback.sh")

    assert '--backup "${BACKUP}" --no-start' in rollback
    assert rollback.index("restaurar-backup.sh") < rollback.index(
        "instalar-servicio.sh"
    )
    assert "SERVICIOS_DEBEN_QUEDAR_DETENIDOS=true" in rollback
    assert 'systemctl stop "${servicio}"' in rollback


def test_ci_checks_stabilization_and_shell_syntax() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )

    assert '"estabilizacion/**"' in workflow
    assert "bash -n" in workflow


def test_release_version_is_consistent() -> None:
    metadata = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    api = (ROOT / "app" / "api" / "main.py").read_text(encoding="utf-8")

    assert 'version = "1.0.0"' in metadata
    assert 'version="1.0.0"' in api


def test_health_retries_are_quiet_but_final_failure_is_visible() -> None:
    common = script("lib/operaciones-comunes.sh")
    health = common[common.index("comprobar_health()") :]

    assert "for intento in {1..15}" in health
    assert "http://127.0.0.1:8000/health >/dev/null 2>&1" in health
    assert "--show-error --max-time 3" in health
    assert 'error "la API no respondió correctamente en /health."' in health


def test_sensitive_runtime_artifacts_are_ignored() -> None:
    ignored = (ROOT / ".gitignore").read_text(encoding="utf-8")

    for pattern in (
        "agent-identity.json",
        ".env.*",
        "*.db",
        "*.db-wal",
        "*.db-shm",
        "backup-*/",
        "*.pem",
        "*.key",
    ):
        assert pattern in ignored


def test_installable_config_does_not_fake_a_central_url() -> None:
    config = (ROOT / "deploy" / "agent.env.example").read_text(encoding="utf-8")

    assert "AUDITORIA_CENTRAL_URL=\n" in config
    assert "AUDITORIA_CENTRAL_URL=http" not in config


def test_release_with_empty_app_is_rejected(tmp_path: Path) -> None:
    release = create_complete_release(tmp_path / "release")
    shutil.rmtree(release / "app")
    (release / "app").mkdir()

    result = validate_release(release)

    assert result.returncode != 0
    assert "app/agent/" in result.stderr


def test_release_without_agent_entrypoint_is_rejected(tmp_path: Path) -> None:
    release = create_complete_release(tmp_path / "release")
    (release / "app" / "agent" / "__main__.py").unlink()

    result = validate_release(release)

    assert result.returncode != 0
    assert "app/agent/__main__.py" in result.stderr


def test_release_without_central_api_is_rejected(tmp_path: Path) -> None:
    release = create_complete_release(tmp_path / "release")
    (release / "app" / "api" / "main.py").unlink()

    result = validate_release(release)

    assert result.returncode != 0
    assert "app/api/main.py" in result.stderr


def test_upgrade_preflight_runs_before_backup_stop_or_move() -> None:
    upgrade = script("actualizar.sh")
    validation = upgrade.index('validar_estructura_release "${FUENTE_REAL}"')

    assert validation < upgrade.index('SALIDA_BACKUP="$(bash')
    assert validation < upgrade.index('detener_servicios "${SERVICIOS[@]}"')
    assert validation < upgrade.index('mv "${RAIZ_INSTALACION}"')
    assert "validar_estructura_release" in script("lib/operaciones-comunes.sh")
    assert "validar_estructura_release" in script("lib/operaciones-comunes.sh").split(
        "copiar_codigo_release()", maxsplit=1
    )[1]


def test_bootstrap_rejects_incomplete_app_before_creating_venv() -> None:
    bootstrap = script("preparar-instalacion.sh")

    assert bootstrap.index(
        'validar_estructura_release "${RAIZ_INSTALACION}"'
    ) < bootstrap.index('python3.12 -m venv "${TEMPORAL}"')
    assert "from app.agent.__main__ import cli" in bootstrap
    assert "from app.api.main import app" in bootstrap
    assert '"${VENV}/bin/python" -m app.agent --help' in bootstrap


def test_installer_cannot_report_success_without_role_entrypoint() -> None:
    installer = script("instalar-servicio.sh")
    validation = installer.index(
        'validar_entrypoints_rol "${RAIZ_PROYECTO}" "${ROL}"'
    )

    assert validation < installer.index('install -d -m 0750 "${DIRECTORIO_CONFIG}"')
    assert validation < installer.index("Nexora instalado correctamente")
