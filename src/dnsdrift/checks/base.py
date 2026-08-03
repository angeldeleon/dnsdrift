"""Check protocol and registry."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from ..config import DomainConfig, Settings
from ..models import CheckResult
from ..resolver import Resolver


@dataclass(slots=True)
class CheckContext:
    """Everything a check is allowed to reach.

    Passing a context rather than letting checks build their own resolvers or
    HTTP clients keeps every outbound request inside the configured timeout and
    concurrency budget.
    """

    domain: DomainConfig
    settings: Settings
    resolver: Resolver

    @property
    def name(self) -> str:
        return self.domain.name


CheckFunc = Callable[[CheckContext], CheckResult]


class Check(Protocol):
    name: str

    def __call__(self, ctx: CheckContext) -> CheckResult: ...


_REGISTRY: dict[str, CheckFunc] = {}


def register(name: str) -> Callable[[CheckFunc], CheckFunc]:
    """Register a check under *name* so config can select it."""

    def decorator(func: CheckFunc) -> CheckFunc:
        if name in _REGISTRY:
            raise RuntimeError(f"check {name!r} is already registered")
        func.name = name  # type: ignore[attr-defined]
        _REGISTRY[name] = func
        return func

    return decorator


def get_check(name: str) -> CheckFunc:
    try:
        return _REGISTRY[name]
    except KeyError as exc:
        raise KeyError(f"no such check: {name}") from exc


def registered_checks() -> tuple[str, ...]:
    return tuple(sorted(_REGISTRY))
