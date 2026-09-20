"""Importing this package registers every analyzer.

Builtins are imported before external-tool analyzers so that a report always
leads with evidence that required nothing but the file itself.
"""

from . import builtin  # noqa: F401

try:  # pragma: no cover - present from phase 2 onwards
    from . import external  # noqa: F401
except ImportError:  # pragma: no cover
    pass
