"""Loopback-only read-only preview of a verified one-PC candidate bundle.

Does not activate CORE, trusted host, workers, models or network APIs.
Only verified static UI files plus minimal inert manifest diagnostics are served.
"""
from __future__ import annotations

import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

PUBLIC_UI = frozenset(("index.html", "styles.css", "app.js", "demo-data.js"))
_SHA256 = re.compile(r"[a-f0-9]{64}\Z")


class PreviewDenied(ValueError):
    pass


def read_verified_bundle(root: Path) -> dict:
    if not root.is_dir() or root.is_symlink():
        raise PreviewDenied("Bundle root missing or unsafe")
    manifest_file = root / "manifest.json"
    if manifest_file.is_symlink() or not manifest_file.is_file():
        raise PreviewDenied("Manifest missing or linked")
    if manifest_file.stat().st_size > 32_768:
        raise PreviewDenied("Manifest oversized")
    def unique_pairs(pairs):
        obj = {}
        for k, v in pairs:
            if k in obj:
                raise PreviewDenied("Duplicate manifest key")
            obj[k] = v
        return obj
    try:
        manifest = json.loads(
            manifest_file.read_text("utf-8"), object_pairs_hook=unique_pairs)
    except (OSError, UnicodeError, ValueError) as exc:
        raise PreviewDenied("Invalid manifest") from exc
    if not isinstance(manifest, dict) or manifest.get("schema") != "neurofactory.one_pc_candidate.v1":
        raise PreviewDenied("Unrecognized bundle")
    required_false = (
        "release_approved", "live_execution_allowed", "handoff_active",
        "real_queue_enabled", "independent_review_complete", "owner_pc_installed",
        "components_executable", "provider_model_inference_verified_on_owner_pc",
        "remote_witness_independence",
    )
    if any(manifest.get(field) is not False for field in required_false):
        raise PreviewDenied("Unsafe activation claim in bundle")
    if manifest.get("ui_is_demonstration") is not True or manifest.get("single_windows_pc_pilot") is not True:
        raise PreviewDenied("Incorrect read-only candidate policy")
    entries = manifest.get("files")
    if not isinstance(entries, list) or not 12 <= len(entries) <= 60:
        raise PreviewDenied("Missing bounded component manifest")
    observed = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {
            "role", "file", "source_commit", "git_blob", "sha256", "bytes",
        }:
            raise PreviewDenied("Unknown component field")
        role, name = entry["role"], entry["file"]
        if not isinstance(role, str) or role not in (
            "core", "host", "ui", "providers", "coordinator"):
            raise PreviewDenied("Unknown component")
        if not isinstance(name, str) or not name or "/" in name or "\\" in name or name in (".", ".."):
            raise PreviewDenied("Invalid component name")
        if (role, name) in observed:
            raise PreviewDenied("Duplicate component")
        observed.add((role, name))
        for field, width in (("git_blob", 40), ("source_commit", 40), ("sha256", 64)):
            if not isinstance(entry[field], str) or not re.fullmatch("[a-f0-9]{" + str(width) + "}", entry[field]):
                raise PreviewDenied("Invalid component checksum")
        if type(entry["bytes"]) is not int or not 0 <= entry["bytes"] <= 250_000:
            raise PreviewDenied("Invalid component size")
        component = root / "components" / role / name
        if component.is_symlink() or not component.is_file():
            raise PreviewDenied("Missing/linked component")
        raw = component.read_bytes()
        if len(raw) != entry["bytes"] or hashlib.sha256(raw).hexdigest() != entry["sha256"]:
            raise PreviewDenied("Staged code mutated; refuse preview")
    if not {("ui", n) for n in PUBLIC_UI}.issubset(observed):
        raise PreviewDenied("Missing UI files")
    self_sha = manifest.get("launcher_sha256")
    if not isinstance(self_sha, str) or not _SHA256.fullmatch(self_sha):
        raise PreviewDenied("Invalid launcher digest")
    launcher = root / "local_preview.py"
    if launcher.is_symlink() or not launcher.is_file() or hashlib.sha256(
            launcher.read_bytes()).hexdigest() != self_sha:
        raise PreviewDenied("Launcher mutated")
    return manifest


def make_handler(root: Path, manifest: dict):
    class ReadOnlyHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            url = urlsplit(self.path)
            if url.query or url.fragment:
                self.send_error(404)
                return
            if url.path == "/status.json":
                reply = {
                    "mode": "ONE_WINDOWS_PC_UNRELEASED_READ_ONLY",
                    "component_sources_pinned": len({
                        item["role"] for item in manifest["files"]}),
                    "files_integrity_verified_at_startup": True,
                    "ui_data": "DEMO_NOT_LIVE",
                    "core_queue_running": False,
                    "model_generation_started": False,
                    "trusted_service_installed_by_this_preview": False,
                    "release_approved": False,
                }
                payload = json.dumps(reply, sort_keys=True).encode("utf-8")
                self._respond(200, "application/json; charset=utf-8", payload)
                return
            relative = "index.html" if url.path in ("/", "/index.html") else url.path.lstrip("/")
            if relative not in PUBLIC_UI:
                self.send_error(404)
                return
            path = root / "components" / "ui" / relative
            if path.is_symlink() or not path.is_file():
                self.send_error(404)
                return
            mime = {
                "index.html": "text/html; charset=utf-8",
                "styles.css": "text/css; charset=utf-8",
                "app.js": "application/javascript; charset=utf-8",
                "demo-data.js": "application/javascript; charset=utf-8",
            }[relative]
            self._respond(200, mime, path.read_bytes())

        def _respond(self, status: int, mime: str, content: bytes):
            self.send_response(status)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy",
                             "default-src 'none'; script-src 'self'; style-src 'self';"
                             " img-src 'self' data:; connect-src 'none'; object-src 'none';"
                             " form-action 'none'; base-uri 'none'")
            self.end_headers()
            self.wfile.write(content)

        def do_POST(self):
            self.send_error(405, "Read-only preview")

        def do_PUT(self):
            self.send_error(405, "Read-only preview")

        def do_DELETE(self):
            self.send_error(405, "Read-only preview")

        def log_message(self, format, *args):
            pass

    return ReadOnlyHandler


def main(argv=None):
    parser = argparse.ArgumentParser(description="Start only the safe localhost demo UI")
    parser.add_argument("--bundle", type=Path, default=Path("."))
    parser.add_argument("--port", type=int, default=8765)
    arguments = parser.parse_args(argv)
    if not 1024 <= arguments.port <= 65535:
        raise PreviewDenied("Invalid local preview port")
    root = arguments.bundle.resolve(strict=True)
    manifest = read_verified_bundle(root)
    with HTTPServer(("127.0.0.1", arguments.port), make_handler(root, manifest)) as server:
        print("НЕЙРОЗАВОД — только локальное демо: http://127.0.0.1:" +
              str(arguments.port), flush=True)
        print("Реальная очередь, HOST, ИИ-модели и публикация ОТКЛЮЧЕНЫ.", flush=True)
        server.serve_forever(poll_interval=0.3)


if __name__ == "__main__":
    main()
