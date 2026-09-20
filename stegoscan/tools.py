"""External tool discovery and timeout-guarded execution.

Two rules make the difference between this and v2's `|| true`:

* a tool that is not installed produces a *reason*, which becomes a SKIPPED
  status in the report rather than silence
* every invocation is bounded by a timeout, and a timeout is an error the
  report states, not a hang
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence

VERSION_TIMEOUT = 10

# Arguments that make each tool print its version. Some of these exit non-zero
# while still printing something useful, which is why output is preferred over
# return code.
_VERSION_FLAGS = {
    "binwalk": ["--help"],
    "foremost": ["-V"],
    "steghide": ["--version"],
    "stegseek": ["--version"],
    "zsteg": ["--version"],
    "stegdetect": ["-V"],
    "exiftool": ["-ver"],
    "ent": [],
    "identify": ["-version"],
}


@dataclass
class ToolInfo:
    name: str
    path: Optional[str]
    version: str = ""

    @property
    def available(self) -> bool:
        return self.path is not None

    def to_dict(self) -> Dict[str, object]:
        return {"name": self.name, "path": self.path, "version": self.version}


@dataclass
class ToolRun:
    """Outcome of one external invocation."""

    argv: List[str]
    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool = False
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.timed_out and not self.error

    def text(self) -> str:
        return self.stdout.decode("utf-8", "replace")


def find_tool(name: str) -> ToolInfo:
    path = shutil.which(name)
    if path is None:
        return ToolInfo(name=name, path=None)
    return ToolInfo(name=name, path=path, version=_version(name, path))


def _version(name: str, path: str) -> str:
    flags = _VERSION_FLAGS.get(name, ["--version"])
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [path] + flags,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=VERSION_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    first = completed.stdout.decode("utf-8", "replace").strip().splitlines()
    return first[0].strip()[:120] if first else ""


def discover(names: Iterable[str]) -> Dict[str, ToolInfo]:
    """Look up every external binary once per scan."""
    return {name: find_tool(name) for name in sorted(set(names))}


def run(
    argv: Sequence[str],
    timeout: int,
    cwd: Optional[str] = None,
    stdin_data: Optional[bytes] = None,
    env: Optional[Dict[str, str]] = None,
) -> ToolRun:
    """Run an external tool without a shell, bounded by a timeout."""
    command = list(argv)
    merged_env = dict(os.environ)
    if env:
        merged_env.update(env)
    try:
        completed = subprocess.run(  # noqa: S603 - argv list, never shell=True
            command,
            input=stdin_data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            cwd=cwd,
            env=merged_env,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return ToolRun(command, -1, b"", b"", timed_out=True)
    except OSError as exc:
        return ToolRun(command, -1, b"", b"", error=str(exc))
    return ToolRun(command, completed.returncode, completed.stdout or b"", completed.stderr or b"")


def command_string(argv: Sequence[str]) -> str:
    """Render an argv for a report, quoting anything with whitespace."""
    parts = []
    for item in argv:
        text = str(item)
        parts.append('"{}"'.format(text) if " " in text else text)
    return " ".join(parts)
