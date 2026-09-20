"""Analyzer registration and selection.

Registration is in-tree and explicit: importing ``stegoscan.analyzers`` pulls in
every module, each of which decorates its class with :func:`register`. Adding a
detection technique is one new file plus one decorator.

This is deliberately not an entry-point plugin system. Third-party plugin
discovery would mean a forensics tool loading code it cannot vouch for, and
nothing in the workflows this tool serves needs it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Dict, List, Optional, Type

from .model import Carrier

if TYPE_CHECKING:  # importing the analyzers package at runtime would be circular:
    from .analyzers.base import Analyzer  # analyzers import register from here

_REGISTRY: List["Analyzer"] = []


def register(cls: Type["Analyzer"]) -> Type["Analyzer"]:
    """Class decorator that adds an analyzer instance to the registry."""
    if not cls.name:
        raise ValueError("{} must define a name".format(cls.__name__))
    if any(existing.name == cls.name for existing in _REGISTRY):
        raise ValueError("duplicate analyzer name: {}".format(cls.name))
    _REGISTRY.append(cls())
    return cls


def all_analyzers() -> List["Analyzer"]:
    """Every registered analyzer, in registration order."""
    _ensure_loaded()
    return list(_REGISTRY)


def analyzers_for(carrier: Carrier) -> List["Analyzer"]:
    """Analyzers applicable to this carrier, in registration order."""
    return [a for a in all_analyzers() if a.applies(carrier)]


def by_name(name: str) -> Optional["Analyzer"]:
    for analyzer in all_analyzers():
        if analyzer.name == name:
            return analyzer
    return None


def external_requirements() -> Dict[str, List[str]]:
    """Map of external binary -> analyzers that need it."""
    requirements: Dict[str, List[str]] = {}
    for analyzer in all_analyzers():
        for binary in analyzer.requires:
            requirements.setdefault(binary, []).append(analyzer.name)
    return requirements


_loaded = False


def _ensure_loaded() -> None:
    global _loaded
    if _loaded:
        return
    _loaded = True
    from . import analyzers  # noqa: F401  (import triggers registration)
