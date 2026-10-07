"""`pwd` es exclusivo de Unix: su ausencia no debe romper imports ni la
enumeración de usuarios (por ejemplo, al recolectar tests en Windows)."""

from __future__ import annotations

import os
import subprocess
import sys
from types import SimpleNamespace

import pytest

import app.agent.continuous_agent as continuous_agent_module
import app.audit.system_auditor as system_auditor_module
from app.agent.continuous_agent import ContinuousAgent
from app.audit.system_auditor import SystemAuditor


def entry(name: str, uid: int) -> SimpleNamespace:
    return SimpleNamespace(
        pw_name=name,
        pw_uid=uid,
        pw_gid=uid,
        pw_shell="/bin/bash",
        pw_dir=f"/home/{name}",
    )


FAKE_ENTRIES = [
    entry("root", 0),
    entry("daemon", 1),
    entry("servicio", 999),
    entry("ana", 1000),
    entry("nobody", 65534),
]


def test_agent_users_are_empty_when_pwd_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(continuous_agent_module, "pwd", None)

    assert ContinuousAgent._users() == {}


def test_auditor_users_are_empty_when_pwd_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(system_auditor_module, "pwd", None)

    assert SystemAuditor._users() == []


def test_agent_users_keep_linux_filtering_with_pwd(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        continuous_agent_module,
        "pwd",
        SimpleNamespace(getpwall=lambda: list(FAKE_ENTRIES)),
    )

    assert ContinuousAgent._users() == {
        "root": {"uid": 0, "gid": 0, "shell": "/bin/bash", "home": "/home/root"},
        "ana": {"uid": 1000, "gid": 1000, "shell": "/bin/bash", "home": "/home/ana"},
    }


def test_auditor_users_keep_linux_filtering_with_pwd(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        system_auditor_module,
        "pwd",
        SimpleNamespace(getpwall=lambda: list(FAKE_ENTRIES)),
    )

    assert [user["username"] for user in SystemAuditor._users()] == ["root", "ana"]


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="En Windows `pwd` ya no existe; el import real lo cubre la colección.",
)
def test_real_pwd_module_is_used_on_unix() -> None:
    import pwd

    assert continuous_agent_module.pwd is pwd
    assert system_auditor_module.pwd is pwd


def test_modules_import_without_pwd_in_a_clean_interpreter() -> None:
    code = (
        "import sys\n"
        "sys.modules['pwd'] = None\n"
        "import app.agent.continuous_agent as agent\n"
        "import app.audit.system_auditor as auditor\n"
        "assert agent.pwd is None and auditor.pwd is None\n"
        "assert agent.ContinuousAgent._users() == {}\n"
        "assert auditor.SystemAuditor._users() == []\n"
        "print('ok')\n"
    )
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)}

    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        env=env,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok"
