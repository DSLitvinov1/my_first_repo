"""Read-only production deployment blocker audit for TRUSTED HOST.

This script NEVER enrolls keys, changes host state, writes artifacts,
starts services, reboots computers or issues execution/release approval.
It intentionally cannot turn local self-assertions or green fixture CI
into production authorization. Its result is ALWAYS fail-closed until
separately implemented and independently audited production controls exist.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys

SCHEMA = "neurofactory.host.deployment_readiness.v1"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
MAX_SOURCE_BYTES = 1024 * 1024
HOST_FILES = (
    "offline_os_separated_effect_receiver.py",
    "offline_operator_anchor.py",
    "offline_operator_ipc.py",
    "offline_owner_grant_admission.py",
    "offline_recipient_protected_journal.py",
    "offline_external_effect_witness.py",
    "offline_kernel_reboot_evidence.py",
    "offline_github_owner_key_enrollment.py",
    "offline_mtls_witness_transport.py",
)
HOST_FOLDER = Path("bridge/neurofactory/trusted_host")
CORE_CLIENT = Path("bridge/neurofactory/development/core_owned/offline_os_receiver_client.py")
REQUIRED_GATES = (
    "independently_authorized_physical_linux_host",
    "independent_operator_and_owner_repository_rights",
    "protected_nonfixture_signer_and_key_custody",
    "nonfixture_receiver_and_authenticated_transport",
    "off_machine_monotonic_rollback_root",
    "actual_kernel_reboot_and_postreboot_ledger_readback",
    "second_distinct_authorized_physical_machine",
    "independent_reviewer_signed_exact_commit_verdict",
)


def _read_bounded_source(path: Path) -> tuple[str, str]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("missing or symlinked required source")
    st = path.stat()
    if st.st_size <= 0 or st.st_size > MAX_SOURCE_BYTES:
        raise ValueError("unbounded, missing or invalid source size")
    raw = path.read_bytes()
    if len(raw) != st.st_size:
        raise ValueError("source changed during read")
    return raw.decode("utf-8"), hashlib.sha256(raw).hexdigest()


def _git_exact_head(repo: Path) -> str | None:
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=False, timeout=6,
        )
        result = proc.stdout.strip()
        return result if proc.returncode == 0 and SHA40.fullmatch(result) else None
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None


def inspect_deployment_readiness(repo: Path, *, check_local_host: bool = True) -> dict:
    """No side effects. No user-provided claim is ever trusted as authorization."""
    repo = Path(repo).resolve()
    sources: dict[str, str] = {}
    blockers: list[str] = []
    contents: dict[str, str] = {}
    for name in HOST_FILES:
        file = repo / HOST_FOLDER / name
        try:
            text, digest = _read_bounded_source(file)
            sources[name] = digest
            contents[name] = text
        except (ValueError, OSError, UnicodeError):
            blockers.append("REQUIRED_HOST_SOURCE_UNAVAILABLE:" + name)
    try:
        core_text, core_sha256 = _read_bounded_source(repo / CORE_CLIENT)
        sources[str(CORE_CLIENT)] = core_sha256
    except (ValueError, OSError, UnicodeError):
        core_text = ""
        blockers.append("REQUIRED_CORE_SIGNED_CLIENT_UNAVAILABLE")
    receiver = contents.get("offline_os_separated_effect_receiver.py", "")
    signer = contents.get("offline_operator_anchor.py", "")
    journal = contents.get("offline_recipient_protected_journal.py", "")
    witness = contents.get("offline_external_effect_witness.py", "")
    if "NF_RECEIVER_OS_FIXTURE_ONLY" in receiver:
        blockers.append("FINAL_RECEIVER_IS_EXPLICITLY_FIXTURE_ONLY")
    if ("nf_test_ephemeral_only" in receiver or
            "postgresql://nf_test" in receiver):
        blockers.append("FINAL_RECEIVER_USES_DISPOSABLE_TEST_DATABASE")
    if "def serve_once(" in receiver:
        blockers.append("FINAL_RECEIVER_IS_ONE_SHOT_NOT_DEPLOYED_SERVICE")
    if "NF_OPERATOR_ANCHOR_FIXTURE_ONLY" in signer:
        blockers.append("SIGNER_IS_EXPLICITLY_FIXTURE_ONLY")
    if "NF_RECEIVER_OS_FIXTURE_ONLY" in journal:
        blockers.append("JOURNAL_IS_EXPLICITLY_FIXTURE_ONLY")
    if "NF_WITNESS_ISOLATED_TEST_ONLY" in witness:
        blockers.append("EXTERNAL_WITNESS_IS_EXPLICITLY_FIXTURE_ONLY")
    if core_text and "signed_owner_grant" not in core_text:
        blockers.append("CORE_CLIENT_LACKS_MANDATORY_OWNER_GRANT")
    if receiver and "downgrade forbidden" not in receiver:
        blockers.append("OWNER_GRANT_NULL_DOWNGRADE_GUARD_NOT_VERIFIED")
    head = _git_exact_head(repo)
    if head is None:
        blockers.append("EXACT_GIT_COMMIT_NOT_AVAILABLE")
    linux = platform.system() == "Linux" if check_local_host else None
    if linux is False:
        blockers.append("CURRENT_ENVIRONMENT_IS_NOT_LINUX")
    # External proof cannot be supplied by fixture env vars, JSON or operator
    # claims from this tool. Those require separate, authenticated review.
    gates = {gate: "NOT_EXTERNALLY_VERIFIED" for gate in REQUIRED_GATES}
    return {
        "schema": SCHEMA,
        "status": "BLOCKED_EXTERNAL_ATTESTATION_REQUIRED",
        "git_head_observed": head,
        "source_sha256": sources,
        "source_blockers": sorted(set(blockers)),
        "gate_status": gates,
        "local_environment": {
            "linux": linux,
            "is_root": bool(os.geteuid() == 0) if check_local_host
            and hasattr(os, "geteuid") else None,
            "python_version": platform.python_version(),
        },
        "physical_linux_server_authorized": False,
        "production_keys_provisioned": False,
        "signed_owner_rights_independently_attested": False,
        "second_physical_node_confirmed": False,
        "actual_full_kernel_reboot_checked": False,
        "independent_review_signed": False,
        "reboot_allowed": False,
        "can_install": False,
        "can_start_services": False,
        "can_publish": False,
        "live_execution_allowed": False,
        "release_approved": False,
        "handoff": "PAUSED_BY_USER",
        "no_files_written": True,
        "secrets_inspected_or_exported": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Read-only, fail-closed TRUSTED HOST physical deployment audit.")
    parser.add_argument("--repository", default=".",
                        help="Repo checkout root; no changes made.")
    args = parser.parse_args()
    report = inspect_deployment_readiness(Path(args.repository))
    print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False))
    return 2  # Explicitly not deployment-approved, including empty test repo.


if __name__ == "__main__":
    sys.exit(main())
