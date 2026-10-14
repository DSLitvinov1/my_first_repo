"""Disabled-by-default Qwen local adapter. No external AI API transport.

The only production HTTP endpoint is a literal IPv4 loopback Ollama endpoint.
No automatic model downloads or credential handling occur in this module.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from durable_budget import DurableBudget
from threading import Lock
import json
from urllib.error import HTTPError, URLError
from urllib.request import Request as URLRequest, ProxyHandler, HTTPRedirectHandler, build_opener

ENDPOINT = "http://127.0.0.1:11434/api/generate"
ALLOWED_MODELS = frozenset({"qwen3:0.6b", "qwen3:4b", "qwen2.5-coder:7b"})
MAX_PROMPT_CHARS = 12000
MAX_REPLY_BYTES = 131072


class LocalProviderError(RuntimeError):
    pass


class LocalBudgetExceeded(LocalProviderError):
    pass


class LocalProviderDisabled(LocalProviderError):
    pass


class LocalProviderUnknownResult(LocalProviderError):
    """Network failure or malformed/truncated reply: never auto-retry."""


@dataclass(frozen=True)
class LocalQwenConfig:
    enabled: bool = False
    model: str = "qwen3:4b"
    timeout_seconds: int = 30
    max_output_tokens: int = 256

    def __post_init__(self) -> None:
        if type(self.enabled) is not bool or self.model not in ALLOWED_MODELS:
            raise ValueError("local Qwen must be explicitly enabled with an approved model")
        if type(self.timeout_seconds) is not int or not 1 <= self.timeout_seconds <= 60:
            raise ValueError("timeout must be within 1..60 seconds")
        if type(self.max_output_tokens) is not int or not 1 <= self.max_output_tokens <= 512:
            raise ValueError("output token limit must be within 1..512")


@dataclass
class LocalBudget:
    """Per-process strict attempt + conservative character-unit reservation cap.

    Character units are NOT measured model tokens or a provider billing balance.
    Reservations are never refunded, including on timeout/unknown delivery.
    """
    max_attempts: int = 10
    max_reserved_units: int = 250000
    attempts: int = field(default=0, init=False)
    reserved_units: int = field(default=0, init=False)
    _lock: Lock = field(default_factory=Lock, init=False, repr=False)

    def __post_init__(self) -> None:
        if (type(self.max_attempts) is not int or not 1 <= self.max_attempts <= 100 or
                type(self.max_reserved_units) is not int or not 1024 <= self.max_reserved_units <= 1000000):
            raise ValueError("invalid budget")

    def reserve(self, units: int) -> None:
        if type(units) is not int or units <= 0:
            raise ValueError("invalid reserved units")
        with self._lock:
            if self.attempts >= self.max_attempts or self.reserved_units + units > self.max_reserved_units:
                raise LocalBudgetExceeded("local attempt budget exhausted")
            self.attempts += 1
            self.reserved_units += units


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise LocalProviderUnknownResult("redirect blocked")


def _loopback_post(url: str, payload: bytes, timeout: int) -> bytes:
    """Only production network function: pinned loopback; proxies disabled."""
    if url != ENDPOINT:
        raise LocalProviderError("non-loopback endpoint rejected")
    opener = build_opener(ProxyHandler({}), _NoRedirect())
    request = URLRequest(url, data=payload, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with opener.open(request, timeout=timeout) as response:
            if response.status != 200:
                raise LocalProviderUnknownResult("local daemon returned non-200 status")
            data = response.read(MAX_REPLY_BYTES + 1)
    except (HTTPError, URLError, OSError, TimeoutError) as exc:
        raise LocalProviderUnknownResult("local Ollama response unavailable") from exc
    if len(data) > MAX_REPLY_BYTES:
        raise LocalProviderUnknownResult("oversize Ollama response")
    return data


def _no_duplicate_pairs(pairs):
    output = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("duplicate JSON key")
        output[key] = value
    return output


@dataclass(frozen=True)
class LocalReply:
    model: str
    text: str
    local_only: bool = True
    published: bool = False


class LocalQwenAdapter:
    def __init__(self, config: LocalQwenConfig, budget: LocalBudget):
        if type(config) is not LocalQwenConfig or type(budget) not in (LocalBudget, DurableBudget):
            raise TypeError("validated local config and budget required")
        self.config = config
        self.budget = budget

    def generate(self, prompt: str, *, task_id: str | None = None) -> LocalReply:
        if not self.config.enabled:
            raise LocalProviderDisabled("local adapter disabled by default")
        if not isinstance(prompt, str) or not prompt.strip() or len(prompt) > MAX_PROMPT_CHARS:
            raise ValueError("invalid prompt")
        # Reserve BEFORE the side effect. Never refund on ambiguous failure.
        units = len(prompt) + 4 * self.config.max_output_tokens
        if type(self.budget) is DurableBudget:
            self.budget.reserve(units, task_id)
        else:
            self.budget.reserve(units)
        payload = json.dumps({
            "model": self.config.model,
            "prompt": prompt,
            "stream": False,
            "keep_alive": "0",
            "options": {"num_predict": self.config.max_output_tokens, "num_ctx": 4096},
        }).encode("utf-8")
        try:
            reply_bytes = _loopback_post(ENDPOINT, payload, self.config.timeout_seconds)
            reply = json.loads(reply_bytes.decode("utf-8"), object_pairs_hook=_no_duplicate_pairs)
        except (ValueError, UnicodeError, TypeError, OverflowError) as exc:
            raise LocalProviderUnknownResult("invalid local response") from exc
        if (type(reply) is not dict or reply.get("done") is not True or
                reply.get("model") != self.config.model or
                reply.get("done_reason") in ("length", "load") or
                type(reply.get("response")) is not str or
                not reply["response"].strip() or len(reply["response"]) > 16000):
            raise LocalProviderUnknownResult("incomplete or unexpected local model result")
        return LocalReply(model=self.config.model, text=reply["response"])
