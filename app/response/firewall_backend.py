from __future__ import annotations

import subprocess
from collections.abc import Callable
from dataclasses import dataclass

from app.response.firewall import (
    NftablesFirewallPlanner,
    TemporaryBlockPlan,
)


@dataclass(frozen=True)
class FirewallCommandResult:
    returncode: int
    stdout: str
    stderr: str


class FirewallBackendError(RuntimeError):
    pass


Runner = Callable[
    [list[str], str | None],
    FirewallCommandResult,
]


class NftablesFirewallBackend:
    def __init__(
        self,
        *,
        nft_path: str = "/usr/sbin/nft",
        runner: Runner | None = None,
    ) -> None:
        self.nft_path = nft_path
        self._runner = runner or self._default_runner

    @staticmethod
    def _default_runner(
        command: list[str],
        input_text: str | None,
    ) -> FirewallCommandResult:
        result = subprocess.run(
            command,
            input=input_text,
            text=True,
            capture_output=True,
            timeout=5,
            check=False,
        )

        return FirewallCommandResult(
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
        )

    def _run(
        self,
        command: list[str],
        *,
        input_text: str | None = None,
    ) -> FirewallCommandResult:
        result = self._runner(
            command,
            input_text,
        )

        return result

    def _run_script(
        self,
        script: str,
        *,
        check_only: bool = False,
    ) -> FirewallCommandResult:
        command = [
            self.nft_path,
        ]

        if check_only:
            command.append("--check")

        command.extend(
            [
                "--file",
                "-",
            ]
        )

        result = self._run(
            command,
            input_text=script,
        )

        if result.returncode != 0:
            raise FirewallBackendError(
                self._format_error(
                    command=command,
                    result=result,
                )
            )

        return result

    @staticmethod
    def _format_error(
        *,
        command: list[str],
        result: FirewallCommandResult,
    ) -> str:
        stderr = result.stderr.strip()

        detail = stderr or "nftables devolvió un error sin mensaje."

        return (
            "Falló la operación nftables "
            f"(exit={result.returncode}, "
            f"command={' '.join(command)}): "
            f"{detail}"
        )

    def table_exists(self) -> bool:
        command = [
            self.nft_path,
            "list",
            "table",
            "inet",
            "auditoria_response",
        ]

        result = self._run(
            command,
            input_text=None,
        )

        if result.returncode == 0:
            return True

        if "No such file or directory" in result.stderr:
            return False

        raise FirewallBackendError(
            self._format_error(
                command=command,
                result=result,
            )
        )

    def prepare(self) -> bool:
        if self.table_exists():
            return False

        script = NftablesFirewallPlanner.render_prepare_ruleset()

        self._run_script(
            script,
            check_only=True,
        )

        self._run_script(script)

        return True

    def add_temporary_block(
        self,
        plan: TemporaryBlockPlan,
    ) -> None:
        self._run_script(
            plan.render_add_element(),
            check_only=True,
        )

        self._run_script(plan.render_add_element())

    def remove_block(
        self,
        plan: TemporaryBlockPlan,
    ) -> None:
        self._run_script(
            plan.render_delete_element(),
            check_only=True,
        )

        self._run_script(plan.render_delete_element())
