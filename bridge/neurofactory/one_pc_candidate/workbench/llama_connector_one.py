"""NEIROZAVOD ONE Qwen3.5 local llama.cpp adapter.

Connects only to a separately configured, loopback-only llama-server.
User secrets remain in an OS-owner-only file, never in source, logs or SQLite.
All outputs are untrusted, non-executable planning drafts.
"""
from __future__ import annotations

import http.client
import json
import os
from pathlib import Path
import re
import stat

from work_core import WorkDenied

HOST = "127.0.0.1"
PORT = 11435
MODEL = "qwen3.5:9b"
KEY_RE = re.compile(r"^[0-9a-f]{64,128}$")
MAX_PROMPT = 3000
MAX_RESPONSE = 24000


class LlamaCppQwenOne:
    def __init__(self, *, key_file: Path, port=PORT):
        self.key_file = Path(key_file)
        if (type(port) is not int or port != PORT or
                not self.key_file.is_absolute()):
            raise WorkDenied("QWEN_LLAMA_CONFIG_INVALID")
        self.port = port

    def _key(self):
        # Windows chmod does not enforce POSIX owner-only ACLs. This adapter
        # deliberately runs only on the Linux Qwen host; Windows uses a
        # separately pinned SSH provider or a future DPAPI-secured tunnel.
        if os.name == "nt":
            raise WorkDenied("QWEN_LLAMA_POSIX_KEY_FILE_REQUIRED")
        path = self.key_file
        if path.is_symlink() or not path.is_file():
            raise WorkDenied("QWEN_KEY_FILE_MISSING")
        info = path.stat()
        if (not stat.S_ISREG(info.st_mode) or info.st_size > 150 or
                info.st_mode & 0o077 or
                hasattr(os, "getuid") and info.st_uid != os.getuid()):
            raise WorkDenied("QWEN_KEY_FILE_INSECURE")
        secret = path.read_text(encoding="ascii").strip()
        if not KEY_RE.fullmatch(secret):
            raise WorkDenied("QWEN_KEY_INVALID")
        return secret

    def available(self):
        try:
            self._key()
            client = http.client.HTTPConnection(HOST, self.port, timeout=3)
            try:
                client.request("GET", "/health")
                response = client.getresponse()
                if response.status != 200:
                    return False
                payload = response.read(1024)
                return json.loads(payload).get("status") == "ok"
            finally:
                client.close()
        except (OSError, ValueError, UnicodeError, WorkDenied):
            return False

    def __call__(self, project, instruction):
        if (type(project) is not str or not re.fullmatch(r"[0-9a-f]{32}", project)
                or type(instruction) is not str or
                not 30 <= len(instruction) <= MAX_PROMPT):
            raise WorkDenied("QWEN_LLAMA_INPUT_REFUSED")
        secret = self._key()
        body = json.dumps({
            "model": MODEL,
            "messages": [
                {"role": "system", "content": (
                    "Ты составляешь только структурированный JSON-план. "
                    "Никакие действия самостоятельно не выполняй. "
                    "Думай кратко и отвечай строго JSON." )},
                {"role": "user", "content": instruction},
            ],
            "temperature": 0,
            "max_tokens": 180,
            "chat_template_kwargs": {"enable_thinking": False},
            "stream": False,
            "response_format": {"type": "json_object"},
        }, ensure_ascii=False, separators=(",", ":")).encode("utf8")
        if len(body) > 6500:
            raise WorkDenied("QWEN_LLAMA_REQUEST_TOO_LARGE")
        connection = http.client.HTTPConnection(HOST, self.port, timeout=130)
        try:
            connection.request("POST", "/v1/chat/completions", body=body, headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Authorization": "Bearer " + secret,
            })
            response = connection.getresponse()
            if response.status != 200:
                raise WorkDenied("QWEN_LLAMA_RESPONSE_REFUSED")
            raw = response.read(MAX_RESPONSE + 1)
            if len(raw) > MAX_RESPONSE:
                raise WorkDenied("QWEN_LLAMA_RESPONSE_TOO_LARGE")
            parsed = json.loads(raw.decode("utf8"))
            if (type(parsed) is not dict or
                    type(parsed.get("choices")) is not list or
                    len(parsed["choices"]) != 1):
                raise WorkDenied("QWEN_LLAMA_RESULT_SCHEMA_INVALID")
            choice = parsed["choices"][0]
            if (type(choice) is not dict or
                    type(choice.get("message")) is not dict):
                raise WorkDenied("QWEN_LLAMA_CHOICE_SCHEMA_INVALID")
            output = choice["message"].get("content")
            if type(output) is not str or not 10 <= len(output) <= 12000:
                raise WorkDenied("QWEN_LLAMA_EMPTY_RESULT")
            # Do not log or cache this text. The independent strict validator
            # checks every proposed step before the owner can approve it.
            return {"status": "PROPOSED_UNVERIFIED", "text": output}
        except WorkDenied:
            raise
        except (OSError, UnicodeError, ValueError, TypeError):
            raise WorkDenied("QWEN_LLAMA_UNKNOWN_NO_AUTO_RETRY")
        finally:
            connection.close()
