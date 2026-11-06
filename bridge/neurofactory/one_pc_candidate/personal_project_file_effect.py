"""Bounded personal HOST effect: one owner/Core-reviewed Qwen source file.

The new artifact is never executed by this service. No arbitrary paths,
overwrites, deletes, shell, imports of generated code, network URLs or model
instructions can be selected by the untrusted Qwen draft. Project folders
are under an operator-provisioned, service-SID-protected ProgramData root.

A durable UNKNOWN, signed remote epoch and exact owner signature are verified
by personal_windows_host_service BEFORE apply_approved_project_file.
"""
from __future__ import annotations

from hashlib import sha256
import os
from pathlib import Path
import re
import stat

PROJECT_FILE_ACTION = "create_project_file"
PROJECT_FILE_SCHEMA = "nf.personal.owner_signed_project_file.v1"
CORE_PERMISSION_SCHEMA = "nf.personal.core_reviewed_qwen_file.v1"
OWNER_FILE_DOMAIN = b"NF_PERSONAL_OWNER_QWEN_PROJECT_FILE_V1\x00"

PROJECT_FILE_FIELDS = frozenset((
    "schema","task_id","project_id","nonce","external_epoch",
    "issued_unix","expires_unix","source_sha40","machine_sha256",
    "package_sha256","operation","relative_path","text","content_sha256",
    "core_permission","owner_signature_base64",
))
CORE_FIELDS = frozenset((
    "schema","task_id","project_id","model","draft_sha256",
    "operation","relative_path","content_sha256","max_bytes",
    "owner_reviewed",
))
HEX32 = re.compile(r"[a-f0-9]{32}\Z")
HEX64 = re.compile(r"[a-f0-9]{64}\Z")
NAME = re.compile(
    r"[A-Za-z][A-Za-z0-9_.-]{0,60}\.(?:py|js|ts|tsx|md|txt|json|html|css|yaml|yml)\Z"
)
DOS_NAMES = frozenset((
    "CON","PRN","AUX","NUL",
    *(f"COM{n}" for n in range(1,10)),
    *(f"LPT{n}" for n in range(1,10)),
))
MODELS = frozenset(("qwen3.5:9b","qwen2.5-coder:1.5b"))
MAX_CONTENT = 2048
MAX_ENVELOPE = 8000


class ProjectFileDenied(ValueError):
    pass


def safe_project_name(relative_path):
    """Only one regular source file name, never a filesystem path."""
    if (type(relative_path) is not str or not NAME.fullmatch(relative_path)
            or relative_path.split(".",1)[0].upper() in DOS_NAMES
            or ".." in relative_path
            or relative_path.endswith(".")
            or len(relative_path)>72):
        raise ProjectFileDenied("Unsafe source file name or extension")
    return relative_path


def check_core_permission(body):
    """CORE-to-HOST trust boundary; owner signature wraps this exact body."""
    if (type(body) is not dict or body.get("schema")!=PROJECT_FILE_SCHEMA
            or set(body)!=PROJECT_FILE_FIELDS-{ "owner_signature_base64" }
            or body.get("operation")!=PROJECT_FILE_ACTION
            or type(body.get("task_id")) is not str
            or HEX32.fullmatch(body["task_id"]) is None
            or type(body.get("project_id")) is not str
            or HEX32.fullmatch(body["project_id"]) is None
            or type(body.get("text")) is not str):
        raise ProjectFileDenied("Exact signed project-source body required")
    target=safe_project_name(body["relative_path"])
    text=body["text"]
    try:
        raw=text.encode("utf-8")
    except UnicodeError as exc:
        raise ProjectFileDenied("Invalid Unicode source data") from exc
    if (not 1<=len(raw)<=MAX_CONTENT
            or any(ord(char)<32 and char not in "\n\t" for char in text)
            or type(body.get("content_sha256")) is not str
            or sha256(raw).hexdigest()!=body["content_sha256"]):
        raise ProjectFileDenied("Source content and SHA256 not exact")
    permission=body.get("core_permission")
    if (type(permission) is not dict or set(permission)!=CORE_FIELDS
            or permission.get("schema")!=CORE_PERMISSION_SCHEMA
            or permission.get("owner_reviewed") is not True
            or permission.get("operation")!=PROJECT_FILE_ACTION
            or permission.get("task_id")!=body["task_id"]
            or permission.get("project_id")!=body["project_id"]
            or permission.get("relative_path")!=target
            or permission.get("content_sha256")!=body["content_sha256"]
            or type(permission.get("draft_sha256")) is not str
            or not HEX64.fullmatch(permission["draft_sha256"])
            or permission["draft_sha256"]!=body["content_sha256"]
            or permission.get("model") not in MODELS
            or type(permission.get("max_bytes")) is not int
            or permission["max_bytes"]!=MAX_CONTENT):
        raise ProjectFileDenied("No exact owner-reviewed CORE/Qwen task scope")
    return raw


def _safe_existing_dir(path):
    if not isinstance(path,Path) or not path.is_absolute() or path.is_symlink():
        raise ProjectFileDenied("Protected project directory unavailable")
    if not path.is_dir():
        raise ProjectFileDenied("Protected project directory not provisioned")
    info=path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or
            os.name=="nt" and info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT):
        raise ProjectFileDenied("Reparse or invalid protected project directory")
    return path


def project_target(projects_root, project_id, relative_path, *, required_existing=True):
    """The sole path resolver, restricted to an existing isolated project."""
    if type(project_id) is not str or HEX32.fullmatch(project_id) is None:
        raise ProjectFileDenied("Unknown project identifier")
    safe_project_name(relative_path)
    _safe_existing_dir(projects_root)
    project=projects_root/project_id
    if required_existing:
        _safe_existing_dir(project)
    elif project.exists() or project.is_symlink():
        _safe_existing_dir(project)
    return project/relative_path


def apply_approved_project_file(*, signed_body, projects_root):
    """Called once, *only after* durable local UNKNOWN and signed remote ACK."""
    content=check_core_permission(signed_body)
    target=project_target(
        projects_root,signed_body["project_id"],signed_body["relative_path"])
    if target.exists() or target.is_symlink():
        raise ProjectFileDenied("No overwrite or replay under protected project")
    flags=os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os,"O_BINARY",0)
    if hasattr(os,"O_NOFOLLOW"):
        flags|=os.O_NOFOLLOW
    fd=os.open(target,flags,0o600)
    with os.fdopen(fd,"wb") as out:
        out.write(content)
        out.flush()
        os.fsync(out.fileno())
    if sha256(target.read_bytes()).hexdigest()!=signed_body["content_sha256"]:
        raise ProjectFileDenied("Created source does not match signed digest")
    return {
        "schema":"nf.personal.project_file_effect.v1",
        "status":"OWNER_CORE_QWEN_PROJECT_FILE_CREATED",
        "task_id":signed_body["task_id"],
        "project_id":signed_body["project_id"],
        "relative_path":signed_body["relative_path"],
        "content_sha256":signed_body["content_sha256"],
        "executed_generated_code":False,
        "automatic_retry_allowed":False,
    }
