"""Windows SCM ONE-REQUEST sandbox receiver (nonproduction).

No installation CLI and no generic worker-file access. Owner/operator must
create an actual dedicated non-admin Windows service account, explicit
protected NTFS config and target ACL before starting. SCM is the only
expected start manager. Private key NEVER lives in this service/worker.
The service cannot enable live tasks and stops after one request.
Not suitable for production until external review and off-host antirollback.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import win32event
import win32service
import win32serviceutil
import servicemanager

from windows_named_pipe_pilot_receiver import serve_one_pilot
from windows_receiver_sid_acl_guard import own_sid,verify_receiver_isolation

SERVICE_NAME="NeurofactorySandboxReceiver"
CONFIG_PATH=Path(os.environ.get("PROGRAMDATA","C:/ProgramData"))/"NeurofactorySandboxReceiver"/"service_config.json"
MAX_CONFIG_SIZE=3072


def _read_config():
    if os.name!="nt" or not CONFIG_PATH.is_file() or CONFIG_PATH.is_symlink() or \
            not 100 <= CONFIG_PATH.stat().st_size <= MAX_CONFIG_SIZE:
        raise RuntimeError("not an operator-configured Windows sandbox service")
    body=json.loads(CONFIG_PATH.read_text(encoding="ascii"))
    required={"schema","mode","receiver_sid","worker_sid",
              "pipe","protected_root","owner_public_base64"}
    if type(body) is not dict or set(body)!=required or \
            body["schema"]!="nf.windows.scm.single_file.v1" or \
            body["mode"]!="SANDBOX_ONLY":
        raise RuntimeError("no production or alternate service config accepted")
    for key in required:
        if type(body[key]) is not str:
            raise RuntimeError("invalid pinned config type")
    if body["receiver_sid"]==body["worker_sid"]:
        raise RuntimeError("service cannot share worker identity")
    if own_sid()!=body["receiver_sid"]:
        raise RuntimeError("process not under pinned SCM service account")
    # Before acquiring a network/IPC handle verify the actual ACL. Never
    # rely on a text statement "separate SID" or an installer bool.
    verify_receiver_isolation(body["protected_root"],
                              receiver_sid=body["receiver_sid"],
                              worker_sid=body["worker_sid"])
    # The service config is an operator-installed public pin, not a private
    # key. Its NTFS ACL is checked for worker-write by independent installer.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    encoded=body["owner_public_base64"]
    if len(encoded)!=44:
        raise RuntimeError("bad public key representation")
    raw=base64.b64decode(encoded,validate=True)
    if len(raw)!=32:
        raise RuntimeError("invalid owner public key")
    return body,Ed25519PublicKey.from_public_bytes(raw)


class NeurofactorySandboxReceiverService(win32serviceutil.ServiceFramework):
    _svc_name_=SERVICE_NAME
    _svc_display_name_="Neurofactory sandbox one-shot protected receiver"
    _svc_description_="Signed, SID-separated one inert file only; not a production queue."

    def __init__(self,args):
        win32serviceutil.ServiceFramework.__init__(self,args)
        self.stopping=False
        self.event=win32event.CreateEvent(None,0,0,None)

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.stopping=True
        win32event.SetEvent(self.event)

    def SvcDoRun(self):
        # Service read/write paths are fixed and separately operator-owned.
        # SCM user cannot elevate via message or alter approved target.
        body,key=_read_config()
        if self.stopping:
            return
        self.ReportServiceStatus(win32service.SERVICE_RUNNING)
        try:
            result=serve_one_pilot(body["pipe"],body["protected_root"],key,
                                   body["worker_sid"],
                                   receiver_user_sid=body["receiver_sid"])
            if result.get("live_execution_allowed") is not False:
                raise RuntimeError("service unexpectedly authorized live queue")
        except Exception as exc:
            # Service error log only, no keys/secrets/signed message contents.
            servicemanager.LogErrorMsg(
                "Neurofactory sandbox receiver DENIED or UNKNOWN; operator review required")
            raise
        finally:
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)

if __name__=="__main__":
    raise SystemExit("INSTALLATION_AND_START_ARE_OPERATOR_ACTIONS_NOT_AVAILABLE_HERE")
