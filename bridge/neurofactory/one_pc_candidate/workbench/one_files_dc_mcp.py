"""Guarded local Desktop Commander MCP transport for ONE Agent project files.

Reads/writes are limited to one standalone candidate workspace. Terminal, remote
MCP, resource handlers and other Desktop Commander tools are NOT exposed.
This is a guard, not a sandbox: use an OS-isolated disposable workspace when
processing untrusted files. It does not connect ChatGPT to the local computer.
"""
from __future__ import annotations

import argparse
import json
import ntpath
import os
from pathlib import PureWindowsPath
import re
import subprocess
import sys
import threading

PACKAGE = "@wonderwhy-er/desktop-commander@0.3.3"
READ_TOOLS = {"read_file": "path", "read_multiple_files": "paths",
              "list_directory": "path", "get_file_info": "path"}
WRITE_TOOLS = {"write_file": "path", "edit_block": "file_path",
               "create_directory": "path"}
MAX_REQUEST = 256_000
FORBIDDEN_SEGMENTS = {".git", ".ssh", ".aws", ".gnupg", ".env", "secrets", "credentials",
                      "private_keys", "node_modules"}
FORBIDDEN_SUFFIXES = (".key", ".pfx", ".p12", ".pem")
WINDOWS_ABSOLUTE = re.compile(r"^[A-Za-z]:\\")


class Denied(ValueError):
    pass


def safe_windows_path(value: str, root: str, *, must_exist_root: bool = False) -> str:
    if not isinstance(value, str) or not WINDOWS_ABSOLUTE.match(value) or len(value) > 480:
        raise Denied("LOCAL_WINDOWS_ABSOLUTE_PATH_REQUIRED")
    if any(c in value[2:] for c in ('\x00', '\r', '\n', '"', '<', '>', '|', '*', '?', ':')):
        raise Denied("UNSAFE_PATH_CHARACTER")
    parts = PureWindowsPath(value).parts
    if '..' in parts or any(p.lower() in FORBIDDEN_SEGMENTS or p.lower().endswith(FORBIDDEN_SUFFIXES)
                          for p in parts[1:]):
        raise Denied("PATH_COMPONENT_DENIED")
    norm = ntpath.normcase(ntpath.normpath(value))
    rootnorm = ntpath.normcase(ntpath.normpath(root))
    try:
        if ntpath.commonpath([norm, rootnorm]) != rootnorm:
            raise Denied("PATH_OUTSIDE_WORKSPACE")
    except ValueError as exc:
        raise Denied("PATH_OUTSIDE_WORKSPACE") from exc
    if os.name == 'nt':
        # Existing Windows junctions/symlinks are checked against the *real* root.
        if must_exist_root and not os.path.isdir(root):
            raise Denied("WORKSPACE_NOT_FOUND")
        realroot = os.path.normcase(os.path.realpath(root))
        realpath = os.path.normcase(os.path.realpath(value))
        if os.path.commonpath([realroot, realpath]) != realroot:
            raise Denied("PATH_REDIRECTED_OUTSIDE_WORKSPACE")
    return value


def verify_workspace(root: str) -> str:
    if not isinstance(root, str) or not WINDOWS_ABSOLUTE.match(root):
        raise Denied("WORKSPACE_REQUIRED")
    prefix = ntpath.normcase(r"C:\ChatGPTProjects\ONE-")
    norm = ntpath.normcase(ntpath.normpath(root))
    if not norm.startswith(prefix) or '..' in PureWindowsPath(root).parts:
        raise Denied("DEDICATED_ONE_WORKSPACE_REQUIRED")
    safe_windows_path(root, root, must_exist_root=True)
    if os.name == 'nt' and os.path.normcase(os.path.realpath(root)) != os.path.normcase(os.path.abspath(root)):
        raise Denied("WORKSPACE_JUNCTION_REFUSED")
    return root


def allowed_tool_names(allow_write: bool) -> set[str]:
    return set(READ_TOOLS) | (set(WRITE_TOOLS) if allow_write else set())


def validate_tool_call(params: object, workspace: str, allow_write: bool) -> None:
    if not isinstance(params, dict) or not isinstance(params.get('name'), str) or not isinstance(params.get('arguments'), dict):
        raise Denied("MCP_TOOL_PARAMS_INVALID")
    name, args = params['name'], params['arguments']
    if name not in allowed_tool_names(allow_write):
        raise Denied("MCP_TOOL_NOT_PERMITTED")
    field = (READ_TOOLS | WRITE_TOOLS)[name]
    value = args.get(field)
    if field == 'paths' and not isinstance(value, list):
        raise Denied("MCP_TOOL_PATH_INVALID")
    paths = value if field == 'paths' else [value]
    if not paths or len(paths) > 12 or any(not isinstance(v, str) for v in paths):
        raise Denied("MCP_TOOL_PATH_INVALID")
    for p in paths:
        safe_windows_path(p, workspace)
    # Avoid smuggling alternative paths/commands through extra tool parameters.
    keys = {
        'read_file': {'path', 'offset', 'length', 'isUrl'},
        'read_multiple_files': {'paths'},
        'list_directory': {'path', 'depth'},
        'get_file_info': {'path'},
        'write_file': {'path', 'content', 'mode'},
        'edit_block': {'file_path', 'old_string', 'new_string', 'expected_replacements'},
        'create_directory': {'path'},
    }[name]
    if set(args) - keys or args.get('isUrl') is True:
        raise Denied("MCP_TOOL_ARGUMENTS_NOT_PERMITTED")
    if name == 'list_directory' and ('depth' in args and (
            type(args['depth']) is not int or not 0 <= args['depth'] <= 3)):
        raise Denied("MCP_DIRECTORY_DEPTH_REFUSED")
    if name == 'read_file':
        for k in ('offset', 'length'):
            if k in args and (type(args[k]) is not int or not 0 <= args[k] <= 2000):
                raise Denied("MCP_READ_BOUND_REFUSED")
    if name in WRITE_TOOLS:
        for k in ('content', 'old_string', 'new_string'):
            if k in args and (not isinstance(args[k], str) or len(args[k]) > 100_000):
                raise Denied("MCP_WRITE_TOO_LARGE")


def reject(request: dict, reason: str) -> dict:
    return {"jsonrpc": "2.0", "id": request.get('id'),
            "error": {"code": -32602, "message": reason}}


def filter_server_response(response: dict, list_requests: set, allow_write: bool) -> dict:
    if response.get('id') in list_requests:
        list_requests.discard(response['id'])
        result = response.get('result')
        if isinstance(result, dict) and isinstance(result.get('tools'), list):
            result['tools'] = [tool for tool in result['tools'] if isinstance(tool, dict)
                               and tool.get('name') in allowed_tool_names(allow_write)]
    return response


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--workspace', required=True)
    parser.add_argument('--allow-write', action='store_true')
    args = parser.parse_args()
    workspace = verify_workspace(args.workspace)
    # STDIO only. No remote tunnel, no listening service, no shell=True.
    child = subprocess.Popen(['npx.cmd', '-y', PACKAGE], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             shell=False, bufsize=0)
    pending_lists: set = set()
    lock = threading.Lock()

    def server_to_client():
        try:
            for raw in child.stdout:
                if len(raw) > 6_000_000:
                    continue
                try:
                    message = json.loads(raw)
                    if isinstance(message, dict):
                        with lock:
                            filter_server_response(message, pending_lists, args.allow_write)
                        raw = (json.dumps(message, ensure_ascii=False, separators=(',', ':')) + '\n').encode('utf-8')
                except (ValueError, TypeError):
                    continue
                sys.stdout.buffer.write(raw)
                sys.stdout.buffer.flush()
        except (BrokenPipeError, OSError):
            pass

    reader = threading.Thread(target=server_to_client, daemon=True)
    reader.start()
    try:
        for raw in sys.stdin.buffer:
            if len(raw) > MAX_REQUEST:
                continue
            try:
                msg = json.loads(raw)
            except ValueError:
                continue
            if not isinstance(msg, dict):
                continue
            method = msg.get('method')
            if isinstance(method, str) and method not in {
                'initialize', 'notifications/initialized', 'ping', 'tools/list',
                'tools/call', 'notifications/cancelled'}:
                if 'id' in msg:
                    sys.stdout.write(json.dumps(reject(msg, 'MCP_METHOD_REFUSED')) + '\n')
                    sys.stdout.flush()
                continue
            if method == 'tools/call':
                if 'id' not in msg:
                    continue
                try:
                    validate_tool_call(msg.get('params'), workspace, args.allow_write)
                except Denied as exc:
                    if 'id' in msg:
                        sys.stdout.write(json.dumps(reject(msg, str(exc))) + '\n')
                        sys.stdout.flush()
                    continue
            if method == 'tools/list' and 'id' in msg:
                with lock:
                    pending_lists.add(msg['id'])
            child.stdin.write(raw)
            child.stdin.flush()
    finally:
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill()


if __name__ == '__main__':
    main()
