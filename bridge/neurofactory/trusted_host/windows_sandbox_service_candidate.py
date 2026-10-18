"""Windows SCM service candidate for ONE sandbox-only receiver; NO installer.

Run only under separately provisioned dedicated non-admin service identity.
Caller must pre-provision strict NTFS ACL, pinned owner public key and
explicit allowed client SID. Service never generates private keys, accepts
a worker-supplied signing key, modifies production projects or runs queues.
Real deployment and credentials require explicit owner approval.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import sys
import time

SERVICE_NAME = "NeurofactorySandboxReceiver"
MAX_CONFIG_BYTES = 2048


class ServiceProvisioningDenied(RuntimeError):
    pass


def load_config(config_path):
    if os.name != "nt":
        raise ServiceProvisioningDenied("Windows required")
    p = Path(config_path)
    if p.is_symlink() or not p.is_file() or p.stat().st_size > MAX_CONFIG_BYTES:
        raise ServiceProvisioningDenied("protected service config unavailable")
    try:
        d=json.loads(p.read_text(encoding="ascii"))
    except (ValueError,UnicodeError,OSError):
        raise ServiceProvisioningDenied("invalid service config") from None
    expected={"schema","mode","pipe_name","sandbox_root",
              "client_sid","owner_public_key_base64",
              "owner_approved_install"}
    if type(d) is not dict or set(d)!=expected or \
       d["schema"]!="nf.windows.service.config.v1" or \
       d["mode"]!="SANDBOX_TEST_ONLY" or \
       d["owner_approved_install"] is not True:
        raise ServiceProvisioningDenied("no independent service provision approval")
    from windows_named_pipe_pilot_receiver import _SAFE_PIPE, PIPE_PREFIX, _private_root
    if (type(d["pipe_name"]) is not str or
        not d["pipe_name"].startswith(PIPE_PREFIX) or
        not _SAFE_PIPE.fullmatch(d["pipe_name"].rsplit("\\",1)[-1]) or
        type(d["sandbox_root"]) is not str or
        type(d["client_sid"]) is not str or
        type(d["owner_public_key_base64"]) is not str):
        raise ServiceProvisioningDenied("invalid protected configuration")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        key=base64.b64decode(d["owner_public_key_base64"],validate=True)
        if len(key)!=32: raise ValueError("key size")
        pub=Ed25519PublicKey.from_public_bytes(key)
        _private_root(d["sandbox_root"])
    except (ValueError,OSError):
        raise ServiceProvisioningDenied("invalid public pin or sandbox root") from None
    # This candidate intentionally refuses to infer NTFS owner/DACL
    # isolation from JSON. A separate installation attestation is required.
    return d,pub


def service_class():
    import servicemanager
    import win32event
    import win32service
    import win32serviceutil
    from windows_named_pipe_pilot_receiver import serve_one_pilot

    class SandboxReceiverService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = "Neurofactory isolated one-file sandbox receiver"
        _svc_description_ = "Nonproduction restricted one-operation receiver; no autonomous queue."
        def __init__(self,args):
            super().__init__(args)
            self.stop_event=win32event.CreateEvent(None,0,0,None)
            self.stopping=False

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self.stopping=True
            win32event.SetEvent(self.stop_event)

        def SvcDoRun(self):
            config=os.environ.get("NF_WINDOWS_SERVICE_OPERATOR_CONFIG")
            # Never default to test runner temp config. Even an operator
            # supplied config is insufficient without external SCM/ACL audit.
            if not config:
                raise ServiceProvisioningDenied("missing separately installed operator config")
            d,pub=load_config(config)
            # The sandbox-only endpoint currently blocks on one bounded
            # request, so stop is processed after that request or process
            # termination. NOT a production continuously available service.
            if not self.stopping:
                serve_one_pilot(d["pipe_name"],d["sandbox_root"],
                                pub,d["client_sid"])
    return SandboxReceiverService


if __name__=="__main__":
    # No 'install' or 'start' CLI in this module. SCM installer is separate
    # and deliberately not supplied before security principal testing.
    raise SystemExit("NO_INSTALLER_OR_LIVE_QUEUE_SECURITY_REVIEW_REQUIRED")
