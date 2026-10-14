"""One-way mock-Claude quota exhaustion -> local Qwen fallback only.

No actual Claude or DeepSeek adapter is available. Unsafe errors never replay.
"""
from __future__ import annotations

from dataclasses import dataclass
from offline_router import OfflineScriptedProvider, QuotaExhausted, Request
from local_qwen import LocalQwenAdapter, LocalReply


@dataclass(frozen=True)
class SafeFallbackResult:
    text: str
    provider: str
    mock_primary: bool
    local_fallback: bool


class MockClaudeToLocalQwen:
    def __init__(self, mock_claude: OfflineScriptedProvider, local_qwen: LocalQwenAdapter):
        if type(mock_claude) is not OfflineScriptedProvider or mock_claude.name != "claude":
            raise TypeError("real Claude transport is forbidden")
        if type(local_qwen) is not LocalQwenAdapter:
            raise TypeError("expected local Qwen adapter")
        self.mock_claude = mock_claude
        self.local_qwen = local_qwen

    def run(self, request: Request) -> SafeFallbackResult:
        if type(request) is not Request:
            raise TypeError("expected validated offline request")
        try:
            reply = self.mock_claude.generate(request)
            return SafeFallbackResult(reply.text, "claude", True, False)
        except QuotaExhausted:
            backup: LocalReply = self.local_qwen.generate(request.prompt)
            return SafeFallbackResult(backup.text, backup.model, True, True)
