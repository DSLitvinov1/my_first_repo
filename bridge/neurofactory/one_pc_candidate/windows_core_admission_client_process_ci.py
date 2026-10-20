"""Child unprivileged Windows OS process for exact one-shot permit delivery.

Disposably launched as a DIFFERENT Windows account by GitHub-hosted CI.
The command argument is signed authorization data, NOT a private key. Never
launch outside CI; never calls CORE, signer, Qwen, HOST effect or filesystem
writer. stdout prints only constant safe proof labels.
"""
from __future__ import annotations

import stat
from pathlib import Path
import json
import os
import sys

from windows_core_admission_ipc_ci import (
    PREFIX, send_signed_permit_once_ci,
)


def main():
    if os.name != "nt" or len(sys.argv) != 3:
        raise SystemExit(91)
    # The SCM-proven Win32 CreateProcessWithLogonW requires a NULL environment
    # on this disposable Windows runner. The fresh Windows user therefore
    # receives no runner credentials or CI environment. This helper exists
    # ONLY in the checked-out CI test branch, never the Windows installer:
    # enable the existing inert delivery API gate only from this exact
    # disposable GitHub Actions runner checkout. Security still depends on
    # the receiver's real kernel Windows SID, ACL, and owner signature.
    from pathlib import Path
    source = Path(__file__).resolve()
    if (len(source.parts) < 4 or
            source.drive.upper() != "D:" or
            "my_first_repo" not in source.parts or
            not Path(r"D:\a\_temp").is_dir()):
        raise SystemExit(91)
    os.environ["GITHUB_ACTIONS"] = "true"
    os.environ["RUNNER_ENVIRONMENT"] = "github-hosted"
    os.environ["NF_CORE_ADMISSION_PIPE_CI_ONLY"] = "1"
    # Keep the Win32 command line far below its 1,024 character limit.
    # Signed content is a separately ACL-protected regular file, never a
    # private Ed25519 signing key and never model-generated authority.
    name, file_arg = sys.argv[1:]
    if not name.startswith(PREFIX) or len(file_arg) > 240:
        raise SystemExit(92)
    path = Path(file_arg)
    if (not path.is_absolute() or path.is_symlink() or
            path.name != "signed-owner-permit.json" or
            not path.parent.name.startswith("nf-core-admission-ci-") or
            not path.parent.parent.samefile(
                Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData"))) or
            path.parent.is_symlink() or not path.is_file() or
            path.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT or
            not 500 <= path.stat().st_size <= 6500):
        raise SystemExit(92)
    try:
        raw = path.read_bytes()
        if len(raw) != path.stat().st_size:
            raise ValueError("changed read")
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate signed permit field")
                result[key] = value
            return result
        permit = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
    except (ValueError, UnicodeError, TypeError, OSError) as exc:
        raise SystemExit(93) from exc
    if (type(permit) is not dict or
            set(permit) != {"schema", "expected_client_sid",
                            "permit", "denied_read_paths"} or
            permit["schema"] != "nf.onepc.ci.signed_input_and_acl_probes.v1" or
            type(permit["permit"]) is not dict or
            type(permit["denied_read_paths"]) is not list or
            len(permit["denied_read_paths"]) != 3):
        raise SystemExit(94)
    import win32api
    import win32con
    import win32security
    # Process token SID, not an impersonated thread SID; validates the
    # credential-isolated REAL second OS process created by SCM-proven Win32.
    token = win32security.OpenProcessToken(
        win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    actual_sid = win32security.ConvertSidToStringSid(
        win32security.GetTokenInformation(
            token, win32security.TokenUser)[0])
    if actual_sid != permit["expected_client_sid"]:
        raise SystemExit(97)
    for raw_path in permit["denied_read_paths"]:
        if (type(raw_path) is not str or len(raw_path) > 300 or
                not Path(raw_path).is_absolute()):
            raise SystemExit(98)
        try:
            # A successful read is a SECURITY FAILURE, not an acceptable
            # condition to continue with the CORE request.
            Path(raw_path).read_bytes()
        except (PermissionError, OSError):
            continue
        raise SystemExit(99)
    print("NF_WINDOWS_SEPARATE_PROCESS_REAL_NTFS_OWNER_CORE_READ=DENIED")
    response = send_signed_permit_once_ci(name, permit["permit"])
    if response.get("status") != "OBSERVED_QUEUED_TEST_ONLY":
        raise SystemExit(95)
    if (response.get("queue_claim_allowed") is not False or
            response.get("host_execution_allowed") is not False or
            response.get("automatic_retry_allowed") is not False):
        raise SystemExit(96)
    print("NF_WINDOWS_DIFFERENT_OS_PROCESS_SIGNED_CORE_IPC=PASS_CI_ONLY")
    return 0


if __name__ == "__main__":
    sys.exit(main())
