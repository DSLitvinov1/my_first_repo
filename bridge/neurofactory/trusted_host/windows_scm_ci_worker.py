"""Separate low-privilege Windows worker. No owner private key and no CORE writer.

The signed proposal is prepared by the authorized *test operator*, using a
verified real CORE claim. This worker cannot change task/target/bytes without
breaking the owner signature. It only speaks to the receiver's pinned pipe.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import sys

def send_signed(packet,pipe_path):
    import win32file
    import win32pipe
    import win32con
    import pywintypes
    from windows_named_pipe_pilot_receiver import canon
    if type(packet) is not dict or type(pipe_path) is not str:
        raise ValueError("bad signed worker task")
    win32pipe.WaitNamedPipe(pipe_path,5000)
    handle=win32file.CreateFile(pipe_path,
        win32con.GENERIC_READ|win32con.GENERIC_WRITE,0,None,
        win32con.OPEN_EXISTING,0,None)
    try:
        win32pipe.SetNamedPipeHandleState(
            handle,win32pipe.PIPE_READMODE_MESSAGE,None,None)
        win32file.WriteFile(handle,canon(packet))
        _,out=win32file.ReadFile(handle,4096)
        return json.loads(out.decode("ascii"))
    finally:
        win32file.CloseHandle(handle)

def identity_and_acl_probe():
    import win32api
    import win32con
    import win32security
    sid=win32security.GetTokenInformation(
        win32security.OpenProcessToken(win32api.GetCurrentProcess(),win32con.TOKEN_QUERY),
        win32security.TokenUser)[0]
    name=win32security.ConvertSidToStringSid(sid)
    protected=Path(os.environ["PROGRAMDATA"])/"NeurofactoryCIReceiver"/"protected_output"
    try:
        list(protected.iterdir())
    except (PermissionError,OSError):
        denied=True
    else:
        denied=False
    return name,denied


if __name__=="__main__":
    if len(sys.argv)!=4 or os.name!="nt":
        raise SystemExit(4)
    msg_path=Path(sys.argv[1])
    result_path=Path(sys.argv[2])
    pipe=sys.argv[3]
    sid,denied=identity_and_acl_probe()
    try:
        packet=json.loads(msg_path.read_text(encoding="ascii"))
        response=send_signed(packet,pipe)
        response["worker_wrote_no_files"]=True
        response["worker_sid_observed"]=sid
        response["protected_directory_read_denied"]=denied
        result_path.write_text(json.dumps(response,sort_keys=True),encoding="ascii")
    except Exception as exc:
        result_path.write_text(json.dumps({
          "status":"WORKER_STOPPED_OR_SERVER_DENIED",
          "error_class":type(exc).__name__,
          "worker_wrote_no_files":True,
          "worker_sid_observed":sid,
          "protected_directory_read_denied":denied,
          "live_execution_allowed":False
        }),encoding="ascii")
        raise SystemExit(2)
