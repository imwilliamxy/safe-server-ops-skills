"""Safe subprocess & SSH execution layer (always shell=False, BatchMode=yes)."""

from __future__ import annotations

import shlex
import subprocess
from dataclasses import dataclass
from typing import Callable, Sequence

from ..config import GlobalPolicy, ServerProfile


class ExecutionError(RuntimeError):
    """Raised when a local or remote execution fails validation or policy checks."""


@dataclass(frozen=True)
class CommandResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False


CommandRunner = Callable[[list[str], str | None, int], CommandResult]


def default_subprocess_runner(
    argv: list[str],
    stdin_data: str | None,
    timeout: int,
) -> CommandResult:
    try:
        proc = subprocess.run(
            argv,
            input=stdin_data,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
        return CommandResult(
            exit_code=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            timed_out=False,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return CommandResult(
            exit_code=124,
            stdout=stdout,
            stderr=stderr or f"Command timed out after {timeout}s.",
            timed_out=True,
        )


class SSHExecutor:
    """Executes structured remote operations over OpenSSH with strict security flags."""

    def __init__(
        self,
        global_cfg: GlobalPolicy,
        runner: CommandRunner | None = None,
    ) -> None:
        self._global = global_cfg
        self._runner = runner or default_subprocess_runner

    def build_ssh_base_options(
        self,
        profile: ServerProfile,
        *,
        use_sync_key: bool = False,
    ) -> list[str]:
        key_path = profile.effective_sync_key() if use_sync_key else profile.key_file
        opts = [
            "ssh",
            "-i",
            str(key_path),
            "-p",
            str(profile.port),
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "ForwardAgent=no",
            "-o",
            f"StrictHostKeyChecking={self._global.strict_host_key_checking}",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "ServerAliveInterval=15",
            "-o",
            "ServerAliveCountMax=2",
        ]
        if self._global.known_hosts_file is not None:
            opts.extend(["-o", f"UserKnownHostsFile={self._global.known_hosts_file}"])
        return opts

    def build_rsh_string(self, profile: ServerProfile, *, use_sync_key: bool = True) -> str:
        """Build a safely quoted SSH command string for rsync's -e argument."""
        opts = self.build_ssh_base_options(profile, use_sync_key=use_sync_key)
        return " ".join(shlex.quote(tok) for tok in opts)

    def run_remote(
        self,
        profile: ServerProfile,
        remote_tokens: Sequence[str],
        *,
        stdin_data: str | None = None,
        timeout: int | None = None,
    ) -> CommandResult:
        """Run a structured command token sequence on the remote server."""
        if not remote_tokens:
            raise ExecutionError("Remote command tokens must not be empty.")
        remote_cmd = shlex.join(remote_tokens)
        argv = self.build_ssh_base_options(profile, use_sync_key=False)
        argv.extend(["--", f"{profile.user}@{profile.host}", remote_cmd])
        effective_timeout = timeout or self._global.default_timeout_seconds
        return self._runner(argv, stdin_data, effective_timeout)

    def run_local(
        self,
        argv: list[str],
        *,
        stdin_data: str | None = None,
        timeout: int | None = None,
    ) -> CommandResult:
        """Run a fixed local binary argv (never shell=True)."""
        effective_timeout = timeout or self._global.default_timeout_seconds
        return self._runner(argv, stdin_data, effective_timeout)
