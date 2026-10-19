"""Verify installed, pinned CORE and real provider modules import with embedded Python.

This check is strictly NO inference, NO queue, NO service registration.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

def check(components: Path) -> None:
    # The deployed integrity module lives beside this file.
    from installed_integrity import verify
    status=verify(components)
    if status["files_verified"] != 16 or status["live_execution_allowed"] is not False:
        raise RuntimeError("Installed code not verified")
    provider_dir=components/"providers"
    core_dir=components/"core"
    for directory in (provider_dir,core_dir):
        if directory.is_symlink() or not directory.is_dir():
            raise RuntimeError("Unsafe packaged module directory")
        sys.path.insert(0,str(directory))
    # Imports only: no inference, HTTP, subprocess, file effects, services.
    from ollama_worker import ProviderTask, execute_one, physical_free_memory_bytes
    from provider_interface import parse_core_request
    from local_qwen import LocalQwenAdapter
    from one_task_core import OneTaskCore
    if not (callable(execute_one) and callable(parse_core_request)
            and callable(physical_free_memory_bytes)
            and callable(OneTaskCore) and callable(LocalQwenAdapter)
            and callable(ProviderTask)):
        raise RuntimeError("Packaged provider modules cannot be imported")
    print("NF_INSTALLER_PROVIDER_RUNTIME_IMPORT_AND_CORE_MODULE=PASS_NO_MODEL_NO_QUEUE")

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--components",type=Path,required=True)
    args=parser.parse_args()
    check(args.components)

if __name__=="__main__":
    main()
