"""Safe subprocess execution with timeout and error handling."""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console

console = Console(stderr=True)


@dataclass
class RunResult:
    """Result of a subprocess execution."""

    returncode: int
    stdout: str
    stderr: str
    command: list[str]

    @property
    def success(self) -> bool:
        return self.returncode == 0

    def json(self) -> dict:
        """Parse stdout as JSON."""
        return json.loads(self.stdout)


def find_tool(name: str) -> str | None:
    """Find a tool on PATH. Returns full path or None."""
    return shutil.which(name)


def check_tool_version(command: str, version_flag: str = "--version") -> str | None:
    """Run a tool with --version and return the version string, or None if not found."""
    path = find_tool(command)
    if not path:
        return None
    try:
        result = subprocess.run(
            [path, version_flag],
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = result.stdout.strip() or result.stderr.strip()
        return output.split("\n")[0] if output else "unknown"
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None


def run(
    cmd: list[str],
    *,
    cwd: Path | None = None,
    timeout: int = 300,
    verbose: bool = False,
    env: dict[str, str] | None = None,
) -> RunResult:
    """Run a subprocess with timeout and capture output.

    Args:
        cmd: Command and arguments.
        cwd: Working directory.
        timeout: Timeout in seconds (default 5 minutes).
        verbose: Log command before running.
        env: Additional environment variables (merged with os.environ).
    """
    import os

    full_env = {**os.environ, **(env or {})}

    if verbose:
        console.print(f"[dim]$ {' '.join(cmd)}[/dim]")

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            env=full_env,
        )
        return RunResult(
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            command=cmd,
        )
    except subprocess.TimeoutExpired:
        return RunResult(
            returncode=-1,
            stdout="",
            stderr=f"Command timed out after {timeout}s",
            command=cmd,
        )
    except FileNotFoundError:
        return RunResult(
            returncode=-1,
            stdout="",
            stderr=f"Command not found: {cmd[0]}",
            command=cmd,
        )


def run_json(
    cmd: list[str],
    *,
    cwd: Path | None = None,
    timeout: int = 300,
    verbose: bool = False,
    env: dict[str, str] | None = None,
) -> tuple[dict | None, str | None]:
    """Run a command and parse stdout as JSON. Returns (data, error)."""
    result = run(cmd, cwd=cwd, timeout=timeout, verbose=verbose, env=env)
    if not result.success:
        return None, f"Command failed (exit {result.returncode}): {result.stderr}"
    try:
        return result.json(), None
    except json.JSONDecodeError as e:
        return None, f"Failed to parse JSON output: {e}"
