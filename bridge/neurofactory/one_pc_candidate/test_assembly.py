"""Safe ONE-PC staging tests. No network to models, Windows services or queue."""
from __future__ import annotations

import hashlib
from http.server import HTTPServer
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import ProxyHandler, build_opener, Request

from assemble import AssemblyDenied, SOURCES, assemble
from local_preview import PreviewDenied, read_verified_bundle, make_handler


class PureSafetyTests(unittest.TestCase):
    def test_requires_all_five_exact_sources(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            with self.assertRaises(AssemblyDenied):
                assemble({}, folder / "candidate", Path(__file__).with_name("local_preview.py"))

    def test_existing_output_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            output = folder / "exists"
            output.mkdir()
            with self.assertRaises(AssemblyDenied):
                assemble({}, output, Path(__file__).with_name("local_preview.py"))

    def test_rejects_wrong_checkout_head_before_stage(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            roots = {}
            for key in SOURCES:
                root = folder / key
                root.mkdir()
                roots[key] = root
            with patch("assemble._git", return_value=b"0" * 40 + b"\n"):
                with self.assertRaises(AssemblyDenied):
                    assemble(roots, folder / "candidate",
                             Path(__file__).with_name("local_preview.py"))
            self.assertFalse((folder / "candidate").exists())

    def test_read_only_preview_refuses_missing_or_forged_manifest(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            (path / "manifest.json").write_text(
                '{"schema":"neurofactory.one_pc_candidate.v1",'
                '"release_approved":true,"release_approved":false}',
                encoding="utf-8")
            with self.assertRaises(PreviewDenied):
                read_verified_bundle(path)


class CompletePinnedCheckoutTest(unittest.TestCase):
    """Enabled in CI after exact immutable checkouts have been populated."""

    def test_stage_then_verify_and_serve_safe_preview(self):
        import os
        if os.environ.get("NF_ONE_PC_ASSEMBLY_CI") != "1":
            self.skipTest("Real pinned multi-checkout test only in isolated CI")
        cwd = Path.cwd()
        checkout = {role: cwd / (".nf_pin_" + role) for role in SOURCES}
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            bundle = directory / "candidate"
            result = assemble(checkout, bundle, Path(__file__).with_name("local_preview.py"))
            self.assertFalse(result["release_approved"])
            self.assertEqual({x["role"] for x in result["files"]}, set(SOURCES))
            self.assertEqual(len(result["files"]), 24)
            saved = read_verified_bundle(bundle)
            self.assertFalse(saved["live_execution_allowed"])
            # Local single-machine preview with exactly four immutable UI assets,
            # no API for commands, no proxy and no model/queue starts.
            server = HTTPServer(("127.0.0.1", 0), make_handler(bundle, saved))
            t = threading.Thread(target=server.serve_forever, daemon=True)
            t.start()
            client = build_opener(ProxyHandler({}))
            base = "http://127.0.0.1:" + str(server.server_address[1])
            try:
                with client.open(base + "/", timeout=3) as stream:
                    page = stream.read().decode("utf-8")
                    self.assertIn("НЕЙРОЗАВОД", page)
                with client.open(base + "/status.json", timeout=3) as stream:
                    state = json.load(stream)
                self.assertEqual(state["component_sources_pinned"], 5)
                self.assertEqual(state["ui_data"], "DEMO_NOT_LIVE")
                self.assertFalse(state["core_queue_running"])
                self.assertFalse(state["model_generation_started"])
                for route in ("/components/core/one_task_core.py", "/manifest.json",
                              "/../config", "/api/tasks"):
                    with self.subTest(route=route):
                        with self.assertRaises(HTTPError) as err:
                            client.open(base + route, timeout=3)
                        self.assertEqual(err.exception.code, 404)
                with self.assertRaises(HTTPError) as err:
                    client.open(Request(base + "/", data=b"start", method="POST"), timeout=3)
                self.assertEqual(err.exception.code, 405)
            finally:
                server.shutdown()
                t.join(timeout=3)
                server.server_close()
            # Mutated copy must not become a trusted local UI.
            ui = bundle / "components" / "ui" / "app.js"
            ui.write_bytes(ui.read_bytes() + b"// modified")
            with self.assertRaises(PreviewDenied):
                read_verified_bundle(bundle)
            with self.assertRaises(AssemblyDenied):
                assemble(checkout, bundle, Path(__file__).with_name("local_preview.py"))


if __name__ == "__main__":
    unittest.main()
