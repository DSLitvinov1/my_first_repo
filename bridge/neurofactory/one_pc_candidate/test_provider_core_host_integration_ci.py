"""Single disposable Windows test: real CORE SQLite -> local provider HTTP
adapter (FAKE Ollama response) -> test operator signed approval -> REAL SCM
restricted-SID receiver -> exact file readback, denied forgery and replay.

This does NOT test genuine Qwen weights, operator keys, an authorized PC,
UI task dispatch, permanent databases, or independent production review.
"""
from __future__ import annotations

import base64
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import sys
from threading import Thread

MODEL = "qwen2.5-coder:1.5b"
CONTENT = "NEUROFACTORY_ONEPC_FAKE_OLLAMA_UNTRUSTED_PROVIDER_FILE\n"
TARGET = "bridge/neurofactory/development/core_owned/windows_pilot.txt"
ROOT = Path(__file__).resolve().parents[3]
REQUIRED = (
    "NF_WINDOWS_SCM_DISPOSABLE_ONLY",
    "NF_WINDOWS_CROSS_BRANCH_ACL_VERIFY",
    "NF_WINDOWS_REQUIRE_RESTRICTED_SERVICE_SID",
    "NF_ONEPC_PROVIDER_CORE_HOST_CI",
)


def _deny(message: str):
    raise RuntimeError("ONEPC_PROVIDER_CORE_HOST_CI_DENIED: " + message)


class FakeLocalModel(BaseHTTPRequestHandler):
    counts = {"tags": 0, "generate": 0}
    reply = json.dumps({"path": TARGET, "content": CONTENT}, sort_keys=True)

    def _send(self, data):
        encoded = json.dumps(data, sort_keys=True).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self):
        if self.path != "/api/tags":
            self.send_error(404)
            return
        type(self).counts["tags"] += 1
        self._send({"models": [{"name": MODEL, "size": 1100000}]})

    def do_POST(self):
        if self.path != "/api/generate":
            self.send_error(404)
            return
        try:
            size = int(self.headers["Content-Length"])
            if size < 1 or size > 16000:
                raise ValueError("bad bounded size")
            obj = json.loads(self.rfile.read(size))
            if (type(obj) is not dict or obj.get("model") != MODEL or
                    obj.get("stream") is not False or
                    type(obj.get("prompt")) is not str or
                    "harmless sandbox file" not in obj["prompt"]):
                raise ValueError("invalid provider prompt")
        except (ValueError, TypeError, KeyError):
            self.send_error(400)
            return
        type(self).counts["generate"] += 1
        self._send({
            "model": MODEL, "done": True,
            "done_reason": "stop", "response": self.reply,
        })

    def log_message(self, fmt, *args):
        pass


def run():
    if os.name != "nt" or os.getenv("GITHUB_ACTIONS") != "true" or \
            os.getenv("RUNNER_ENVIRONMENT") != "github-hosted" or \
            any(os.getenv(key) != "1" for key in REQUIRED):
        _deny("disposable GitHub Windows CI scope required")
    if ROOT.joinpath(".nf_pinned_core").is_dir() is False:
        _deny("exact immutable CORE checkout not available")
    pin_provider = ROOT / ".nf_pinned_providers"
    if not pin_provider.is_dir():
        _deny("exact immutable PROVIDERS checkout not available")
    source = pin_provider / "bridge" / "neurofactory" / "providers"
    sys.path.insert(0, str(source))
    sys.path.insert(0, str(ROOT / "bridge" / "neurofactory" / "trusted_host"))
    import ollama_worker
    import test_windows_scm_two_user_recovery as host_fixture

    # This CI adapter uses real HTTP and real PROVIDERS durable reservation,
    # but deliberately replies from a fake loopback server, NOT Qwen weights.
    # Bind fixed local port expected by existing Ollama adapter.
    server = ThreadingHTTPServer(("127.0.0.1", 11434), FakeLocalModel)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    original = host_fixture.prepare_core_fixture
    provider_state = {"approved": False, "digest": None}

    def prepare_core_from_provider(directory, owner_key):
        # Genuine CORE queue and claim, pinned Git SHA source, private signer
        # generated within isolated temporary fixture only.
        core, spec, claim, packet, _ = original(directory, owner_key)
        from ollama_worker import ProviderTask, execute_one
        ledger = directory / "provider_ledger"
        ledger.mkdir()
        task = ProviderTask(
            task_id=spec["task_id"], project_id=spec["project_id"],
            input_sha256=spec["source_sha256"],
            target_path=spec["target"],
            instruction="Produce exactly one harmless sandbox file for isolated CI.",
        )
        result = execute_one(task, model=MODEL, ledger_dir=ledger)
        if (result.get("status") != "PROPOSED_UNVERIFIED" or
                result.get("offline_mock") is not False or
                result.get("published") is not False or
                result.get("review_approved") is not False or
                result.get("api_cost_usd") != 0 or
                result.get("attempt_consumed") is not True or
                result.get("model") != MODEL or
                result.get("task_id") != spec["task_id"] or
                result.get("input_sha256") != spec["source_sha256"] or
                len(result.get("proposed_files", [])) != 1):
            _deny("real PROVIDERS adapter did not produce one unverified proposal")
        proposal = result["proposed_files"][0]
        if (proposal.get("relative_path") != TARGET or
                proposal.get("content") != CONTENT or
                proposal.get("applied") is not False or
                proposal.get("verified_by_core") is not False):
            _deny("proposed content or path differs from harmless CI fixture")
        raw = proposal["content"].encode("utf-8")
        digest = sha256(raw).hexdigest()
        if proposal.get("content_sha256") != digest:
            _deny("provider proposal SHA mismatch")
        # Explicit test-operator approval of the precise untrusted model
        # proposal. This private key NEVER leaves the orchestrator and is
        # never shared with SCM service or alternate worker account.
        from windows_named_pipe_pilot_receiver import canon
        body = {k: v for k, v in packet.items()
                if k != "approved_owner_signature"}
        body["content_base64"] = base64.b64encode(raw).decode("ascii")
        body["content_sha256"] = digest
        signature = owner_key.sign(b"NF_WINDOWS_PILOT_V1\x00" + canon(body))
        signed = {**body, "approved_owner_signature":
                  base64.b64encode(signature).decode("ascii")}
        if core.snapshot()["state"] != "CLAIMED":
            _deny("not backed by a real CORE persisted SQLite claim")
        if ledger.is_symlink():
            _deny("provider reservation ledger path swapped")
        from durable_budget import DurableBudget
        snap = DurableBudget(ledger, max_attempts=1,
                             max_reserved_units=50000).snapshot()
        if snap["attempts"] != 1 or len(snap["tasks"]) != 1:
            _deny("no real model attempt was durably reserved")
        provider_state["approved"] = True
        provider_state["digest"] = digest
        return core, spec, claim, signed, CONTENT

    host_fixture.prepare_core_fixture = prepare_core_from_provider
    previous_argv = sys.argv[:]
    try:
        sys.argv = ["test_windows_scm_two_user_recovery.py", "normal"]
        host_fixture.main()
        if not provider_state["approved"]:
            _deny("test signer did not approve a concrete provider proposal")
        if FakeLocalModel.counts["tags"] != 1 or \
           FakeLocalModel.counts["generate"] != 1:
            _deny("unexpected number of model endpoint calls")
        print("NF_ONEPC_REAL_CORE_SQLITE_CLAIM=PASS_TEST_ONLY")
        print("NF_ONEPC_REAL_PROVIDER_HTTP_AND_DURABLE_LEDGER=PASS_FAKE_MODEL_ONLY")
        print("NF_ONEPC_MODEL_PROPOSAL_INERT_AND_UNTRUSTED=PASS_TEST_ONLY")
        print("NF_ONEPC_EXPLICIT_EPHEMERAL_SIGNER_APPROVAL=PASS_TEST_ONLY")
        print("NF_ONEPC_RESTRICTED_SCM_RECEIVER_SIGNED_FILE=PASS_TEST_ONLY")
        print("NF_ONEPC_REAL_QWEN_WEIGHTS_EXECUTED=FALSE")
        print("NF_ONEPC_INDEPENDENT_REVIEW=FALSE")
        print("NF_ONEPC_PRODUCTION_QUEUE=OFF")
    finally:
        sys.argv = previous_argv
        host_fixture.prepare_core_fixture = original
        server.shutdown()
        server.server_close()
        thread.join(timeout=4)


if __name__ == "__main__":
    run()
