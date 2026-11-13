"""Executors run argv commands somewhere: on this machine, or on an attack box over SSH."""

from __future__ import annotations

import atexit
import os
import re
import shlex
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Protocol

from .targets import system_resolve


@dataclass
class ExecResult:
    argv: list[str]
    rc: int
    stdout: str
    stderr: str
    duration: float
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.rc == 0 and not self.timed_out

    @property
    def output(self) -> str:
        """stdout, plus stderr when there is any."""
        if self.stderr.strip():
            return f"{self.stdout}\n[stderr]\n{self.stderr}" if self.stdout else self.stderr
        return self.stdout


class Executor(Protocol):
    """Runs argv lists somewhere. Implement this to run tools in containers, cloud workers, etc.

    Implementations may also accept an optional ``env: Mapping[str, str]`` keyword (extra environment
    variables) and a ``kill_running()`` method; both are used only when present.
    """

    def run(self, argv: list[str], timeout: int = 120, stdin: str | None = None) -> ExecResult: ...

    def resolve(self, host: str) -> str: ...


class LocalExecutor:
    """Runs commands on this machine. The whole process group is killed on timeout."""

    def __init__(self) -> None:
        self._running: set[subprocess.Popen[bytes]] = set()
        self._lock = threading.Lock()

    def run(
        self,
        argv: list[str],
        timeout: int = 120,
        stdin: str | None = None,
        env: Mapping[str, str] | None = None,
    ) -> ExecResult:
        _check_argv(argv)
        start = time.monotonic()
        try:
            proc = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
                env={**os.environ, **_check_env(env)} if env else None,
            )
        except OSError as exc:
            return ExecResult(argv, 127, "", f"{type(exc).__name__}: {exc}", 0.0)
        with self._lock:
            self._running.add(proc)
        try:
            out, err = proc.communicate(stdin.encode() if stdin is not None else None, timeout)
            timed_out = False
        except subprocess.TimeoutExpired:
            _kill_group(proc)
            out, err = _drain(proc)
            timed_out = True
        finally:
            with self._lock:
                self._running.discard(proc)
        return ExecResult(
            argv,
            proc.returncode if not timed_out else 124,
            out.decode(errors="replace"),
            err.decode(errors="replace"),
            time.monotonic() - start,
            timed_out,
        )

    def resolve(self, host: str) -> str:
        return system_resolve(host)

    def kill_running(self) -> None:
        """Kill every command still running (used when an engagement is closed mid-call)."""
        with self._lock:
            running = list(self._running)
        for proc in running:
            _kill_group(proc)


def _check_argv(argv: list[str]) -> None:
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
        raise TypeError("argv must be a non-empty list of strings")


def _drain(proc: subprocess.Popen[bytes]) -> tuple[bytes, bytes]:
    """Collect output after a kill. A grandchild that escaped the process group may still hold the
    pipes open, so give up after a few seconds instead of hanging."""
    try:
        return proc.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        for pipe in (proc.stdin, proc.stdout, proc.stderr):
            if pipe:
                pipe.close()
        proc.wait(timeout=5)
        return b"", b"output lost: a child process kept the pipes open after the timeout"


def _kill_group(proc: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        proc.kill()


def remote_command(argv: list[str], timeout: int, env: Mapping[str, str] | None = None) -> str:
    """Shell-quote argv for a remote shell, wrapped in coreutils `timeout` so the remote process
    dies even if the SSH connection is dropped."""
    _check_argv(argv)
    assignments = [f"{k}={v}" for k, v in _check_env(env).items()]
    prefix = ["env", *assignments] if assignments else []
    return shlex.join(["timeout", "-k", "5", str(timeout), *prefix, *argv])


_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")


def _check_env(env: Mapping[str, str] | None) -> dict[str, str]:
    env = dict(env or {})
    for name, value in env.items():
        if not _ENV_NAME.fullmatch(name) or not isinstance(value, str) or "\0" in value:
            raise ValueError(f"invalid environment variable: {name!r}")
    return env


class SSHExecutor:
    """Runs commands on a remote box with the system `ssh` client (no extra dependencies).

    - Uses your ~/.ssh/config, keys and agent; never prompts (BatchMode).
    - Reuses one connection (ControlMaster) so many small calls stay fast and cheap for the remote.
    - Wraps every command in remote `timeout`, so nothing keeps running after a timeout.
    """

    def __init__(
        self,
        destination: str,
        *,
        connect_timeout: int = 10,
        options: Iterable[str] = (),
        reuse_connection: bool = True,
    ):
        self.destination = destination
        self.connect_timeout = connect_timeout
        self.options = list(options)
        self._local = LocalExecutor()
        self._control_dir: str | None = None
        if reuse_connection and os.name == "posix":
            # Unix socket paths are limited to ~104 bytes; macOS $TMPDIR is too long, so use /tmp.
            self._control_dir = tempfile.mkdtemp(prefix="opgraph-ssh-", dir="/tmp")
            atexit.register(self.close)

    def _ssh_argv(self) -> list[str]:
        argv = ["ssh", "-o", "BatchMode=yes", "-o", f"ConnectTimeout={self.connect_timeout}"]
        if self._control_dir:
            argv += [
                "-o", "ControlMaster=auto",
                "-o", f"ControlPath={self._control_dir}/%C",
                "-o", "ControlPersist=60",
            ]  # fmt: skip
        return [*argv, *self.options, self.destination, "--"]

    def run(
        self,
        argv: list[str],
        timeout: int = 120,
        stdin: str | None = None,
        env: Mapping[str, str] | None = None,
    ) -> ExecResult:
        """Run argv remotely. Note: `env` values are part of the remote command line (visible to
        other users of the remote box via `ps`); do not pass long-lived secrets this way."""
        command = remote_command(argv, timeout, env)
        # Local safety net: the remote `timeout` should fire first.
        result = self._local.run([*self._ssh_argv(), command], timeout + 15, stdin)
        result.argv = argv
        if result.rc == 124:
            result.timed_out = True
        return result

    def resolve(self, host: str) -> str:
        """Resolve a hostname on the remote box, where the tools will connect from."""
        for database in ("ahostsv4", "ahosts"):
            result = self.run(["getent", database, host], timeout=15)
            if result.ok and result.stdout.split():
                return result.stdout.split()[0]
        raise OSError(f"cannot resolve {host!r} on {self.destination}")

    def kill_running(self) -> None:
        """Kill local ssh clients still running; the remote `timeout` ends the remote side."""
        self._local.kill_running()

    def close(self) -> None:
        """Stop the shared connection and remove the local control socket directory."""
        if not self._control_dir:
            return
        control_dir, self._control_dir = self._control_dir, None
        subprocess.run(
            ["ssh", "-o", f"ControlPath={control_dir}/%C", "-O", "exit", self.destination],
            capture_output=True,
            timeout=10,
            check=False,
        )
        shutil.rmtree(control_dir, ignore_errors=True)
