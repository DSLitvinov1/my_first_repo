"""Child unprivileged Windows OS process for exact one-shot permit delivery.

Disposably launched as a DIFFERENT Windows account by GitHub-hosted CI.
The command argument is signed authorization data, NOT a private key. Never
launch outside CI; never calls CORE, signer, Qwen, HOST effect or filesystem
writer. stdout prints only constant safe proof labels.
"""
from __future__ import annotations

import base64
import json
import os
import sys

from windows_core_admission_ipc_ci import (
    PREFIX, send_signed_permit_once_ci,
)


def main():
    if (os.name != "nt" or
            os.environ.get("GITHUB_ACTIONS") != "true" or
            os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted" or
            os.environ.get("NF_CORE_ADMISSION_PIPE_CI_ONLY") != "1" or
            len(sys.argv) != 3):
        raise SystemExit(91)
    name, encoded = sys.argv[1:]
    if (not name.startswith(PREFIX) or
            len(encoded) > 12000 or len(encoded) < 500):
        raise SystemExit(92)
    try:
        raw = base64.b64decode(encoded, validate=True)
        if not 0 < len(raw) <= 6500:
            raise ValueError("oversized envelope")
        permit = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError, TypeError) as exc:
        raise SystemExit(93) from exc
    if type(permit) is not dict:
        raise SystemExit(94)
    response = send_signed_permit_once_ci(name, permit)
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
