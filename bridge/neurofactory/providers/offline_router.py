"""Fail-closed, offline-only provider routing experiments for Neurofactory.

No SDKs, HTTP, credentials, queue integration, or publishing.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping
import re

SUPPORTED_PROVIDERS = frozenset(("claude", "qwen", "deepseek"))
_TASK_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\\Z")


class ProviderFailure(RuntimeError):
    """A mock provider could not deliver a valid answer."""


class QuotaExhausted(ProviderFailure):
    """Provider explicitly reported its free quota exhausted."""


class AuthenticationFailure(ProviderFailure):
    """Provider rejected credentials (NOT a quota signal)."""


class TemporaryFailure(ProviderFailure):
    """Transient error (NOT a quota signal)."""


@dataclass(frozen=True)
class Request:
    task_id: str
    prompt: str

    def __post_init__(self) -> None:
        if not isinstance(self.task_id, str) or not _TASK_ID_PATTERN.fullmatch(self.task_id):
            raise ValueError("task_id must be a safe non-empty identifier")
        if not isinstance(self.prompt, str) or not self.prompt.strip() or len(self.prompt) > 50000:
            raise ValueError("prompt must be non-empty and at most 50000 chars")


@dataclass(frozen=True)
class Reply:
    task_id: str
    provider: str
    text: str
    offline_mock: bool = True


@dataclass(frozen=True)
class RouteResult:
    reply: Reply
    attempted: tuple[str, ...]
    fallback_used: bool


class OfflineScriptedProvider:
    """A deterministic test double. Never connects to a live model."""

    def __init__(self, name: str, events: Iterable[str | ProviderFailure]):
        if name not in SUPPORTED_PROVIDERS:
            raise ValueError("unsupported provider")
        self.name = name
        self._events = iter(events)
        self.calls = 0

    def generate(self, request: Request) -> Reply:
        self.calls += 1
        try:
            result = next(self._events)
        except StopIteration as exc:
            raise ProviderFailure("mock provider has no remaining scripted events") from exc
        if isinstance(result, ProviderFailure):
            raise result
        if not isinstance(result, str) or not result.strip():
            raise ProviderFailure("mock provider returned invalid text")
        return Reply(task_id=request.task_id, provider=self.name, text=result)


class FreeOnlyOfflineRouter:
    """Routes mock requests, falling back only on explicit QuotaExhausted.

    The strict adapter type check intentionally blocks arbitrary/network adapters.
    It is not evidence of a free live API or successful model authentication.
    """

    def __init__(
        self,
        primary: str,
        fallback: str | None,
        adapters: Mapping[str, OfflineScriptedProvider],
    ) -> None:
        if primary not in SUPPORTED_PROVIDERS or fallback not in SUPPORTED_PROVIDERS | {None}:
            raise ValueError("unsupported route")
        if primary == fallback:
            raise ValueError("fallback must differ from primary")
        names = (primary,) if fallback is None else (primary, fallback)
        if any(name not in adapters for name in names):
            raise ValueError("selected provider missing")
        if any(
            type(adapters[name]) is not OfflineScriptedProvider or adapters[name].name != name
            for name in names
        ):
            raise TypeError("only exact offline scripted adapters are allowed")
        if fallback is not None and adapters[primary] is adapters[fallback]:
            raise ValueError("adapters must be independent")
        self._primary = adapters[primary]
        self._fallback = adapters[fallback] if fallback is not None else None

    def run(self, request: Request) -> RouteResult:
        if not isinstance(request, Request):
            raise TypeError("expected validated Request")
        try:
            reply = self._primary.generate(request)
            return RouteResult(reply=reply, attempted=(self._primary.name,), fallback_used=False)
        except QuotaExhausted:
            if self._fallback is None:
                raise
            reply = self._fallback.generate(request)
            return RouteResult(
                reply=reply,
                attempted=(self._primary.name, self._fallback.name),
                fallback_used=True,
            )
