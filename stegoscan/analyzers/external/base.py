"""Shared plumbing for analyzers that shell out to forensics tools.

Every external invocation goes through :meth:`ExternalAnalyzer.execute`, which
guarantees three things the report depends on: the tool is located once per
scan, the call is bounded by a timeout, and a timeout or a crash becomes a
stated error rather than an empty result.
"""

from __future__ import annotations

from typing import List, Optional, Sequence

from ... import tools
from ...model import AnalyzerResult
from ..base import Analyzer, Context


class ExternalAnalyzer(Analyzer):
    binary: str = ""

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if cls.binary and not cls.requires:
            cls.requires = (cls.binary,)

    def tool_path(self, ctx: Context) -> str:
        info = ctx.available_tools.get(self.binary)
        return info.path if info and info.path else self.binary

    def execute(
        self,
        ctx: Context,
        args: Sequence[str],
        cwd: Optional[str] = None,
        stdin_data: Optional[bytes] = None,
    ) -> tools.ToolRun:
        argv: List[str] = [self.tool_path(ctx)] + [str(a) for a in args]
        return tools.run(argv, timeout=ctx.options.timeout, cwd=cwd, stdin_data=stdin_data)

    def failure(self, run: tools.ToolRun, ctx: Context) -> Optional[AnalyzerResult]:
        """Convert a failed invocation into an honest ERROR result."""
        if run.timed_out:
            return AnalyzerResult.errored(
                self.name, "timed out after {} seconds".format(ctx.options.timeout)
            )
        if run.error:
            return AnalyzerResult.errored(self.name, run.error)
        return None

    def save_output(self, ctx: Context, run: tools.ToolRun, name: str) -> Optional[str]:
        payload = run.stdout
        if run.stderr:
            payload = payload + b"\n--- stderr ---\n" + run.stderr
        return ctx.write_artifact(name, payload, subdir="tools")
