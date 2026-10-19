"""Separate *interactive* offline Windows owner console, not a web endpoint.

Run only in a distinct trusted Windows operator account after independent
review and manual installation. DO NOT copy into the unprivileged UI app.
Output is an inert signed permit; a different trusted CORE controller must
independently recheck live SQLite/Git and enqueue at most once.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import stat
import sys

from windows_owner_controller_candidate import (
    WindowsOwnerDenied, enroll, read_manifest, signed_enqueue_only,
)


def fail(reason):
    raise WindowsOwnerDenied(reason)


def read_exact_json(path):
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        fail("Signed request input must be an explicit regular absolute file")
    if os.name == "nt" and (
        path.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT
    ):
        fail("Windows linked request file forbidden")
    if not 1 <= path.stat().st_size <= 8192:
        fail("Owner input file outside strict size bound")
    def unique(items):
        result = {}
        for key, val in items:
            if key in result:
                fail("Duplicate JSON key in owner request")
            result[key] = val
        return result
    try:
        doc = json.loads(
            path.read_bytes().decode("utf-8"), object_pairs_hook=unique)
    except (ValueError, UnicodeError) as exc:
        raise WindowsOwnerDenied("Malformed offline operator input") from exc
    if type(doc) is not dict:
        fail("Operator input must be an object")
    return doc


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="НЕЙРОЗАВОД: отдельный офлайн-контроллер владельца (предрелиз)")
    actions = parser.add_subparsers(dest="action", required=True)
    a = actions.add_parser("enroll")
    a.add_argument("--owner-root", type=Path, required=True)
    a.add_argument("--ui-windows-account", required=True)
    b = actions.add_parser("sign")
    b.add_argument("--owner-root", type=Path, required=True)
    b.add_argument("--draft-request", type=Path, required=True)
    b.add_argument("--task-spec", type=Path, required=True)
    b.add_argument("--externally-pinned-owner-public-b64", required=True)
    b.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if os.name != "nt":
        fail("Only Windows is supported")
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        fail("Offline operator needs a real local interactive console")
    if args.action == "enroll":
        import win32security
        try:
            sid, _, kind = win32security.LookupAccountName(
                None, args.ui_windows_account)
        except Exception as exc:
            raise WindowsOwnerDenied("Unknown separate UI Windows account") from exc
        if kind != win32security.SidTypeUser:
            fail("UI identity must be an actual Windows user")
        ui_sid = win32security.ConvertSidToStringSid(sid)
        manifest = enroll(args.owner_root, ui_sid=ui_sid,
                          confirm=lambda label: input(label + "\n> "))
        print("Владелец зарегистрирован (кандидат, без производственных полномочий).")
        print("Public SHA256 для независимого контроля:", manifest["public_sha256"])
        return 0
    draft = read_exact_json(args.draft_request)
    spec = read_exact_json(args.task_spec)
    try:
        public = base64.b64decode(
            args.externally_pinned_owner_public_b64, validate=True)
    except ValueError as exc:
        raise WindowsOwnerDenied("Invalid independently installed public key") from exc
    read_manifest(args.owner_root, public)
    permit = signed_enqueue_only(
        args.owner_root, prepared_draft=draft, spec=spec,
        pinned_public=public,
        confirm=lambda description: input(description + "\n> "))
    out = args.output
    if (not out.is_absolute() or out.is_symlink() or out.exists()
            or not out.parent.is_dir() or out.parent.is_symlink()):
        fail("Owner permit output must be a new absolute ordinary file")
    if os.name == "nt" and (
        out.parent.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT
    ):
        fail("Windows output directory reparse point")
    payload = (json.dumps(permit, sort_keys=True, ensure_ascii=False,
                          separators=(",", ":")) + "\n").encode("utf-8")
    with out.open("xb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    print("Подписанный запрос сохранён отдельно. CORE НЕ запущен.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except WindowsOwnerDenied as exc:
        print("ДОПУСК ОТКЛОНЁН: " + str(exc), file=sys.stderr)
        sys.exit(2)
