"""Read-only DNS/TCP diagnostics for specified SEDD endpoints.

No authentication, proxy/VPN changes, user/device data or document access.
"""
from __future__ import annotations

import argparse
import json
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

TARGETS = (
    ("official_information_portal", "digit.nso.ru", (443,)),
    ("sedd_host", "cm.nso.ru", (80, 443, 8080)),
)


def error_category(exc: Exception) -> str:
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "timeout"
    if isinstance(exc, ConnectionRefusedError):
        return "refused"
    if isinstance(exc, socket.gaierror):
        return "dns_failure"
    if isinstance(exc, PermissionError):
        return "permission_denied"
    if isinstance(exc, OSError):
        return "network_error"
    return "unexpected_error"


def dns_check(host: str, resolver: Callable = socket.getaddrinfo) -> dict:
    try:
        infos = resolver(host, None, type=socket.SOCK_STREAM)
        return {"status": "resolved" if infos else "no_records"}
    except Exception as exc:
        return {"status": error_category(exc)}


def tcp_check(host: str, port: int, timeout: float = 2.5, connector: Callable = socket.create_connection) -> dict:
    try:
        with connector((host, port), timeout=timeout):
            return {"port": port, "status": "tcp_connected"}
    except Exception as exc:
        return {"port": port, "status": error_category(exc)}


def run_diagnostics() -> dict:
    result = {"schema": "sedd-readonly-connectivity-v1",
              "checked_at_utc": datetime.now(timezone.utc).isoformat(),
              "scope": "dns_and_tcp_only_no_authentication_no_vpn_changes",
              "hosts": []}
    for label, host, ports in TARGETS:
        result["hosts"].append({"label": label, "hostname": host,
                                "dns": dns_check(host),
                                "ports": [tcp_check(host, p) for p in ports]})
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Authorized read-only SEDD DNS/TCP diagnostics")
    parser.add_argument("--output", help="Save sanitized findings to a local JSON file")
    args = parser.parse_args(argv)
    payload = json.dumps(run_diagnostics(), ensure_ascii=False, indent=2)
    if args.output:
        out = Path(args.output).expanduser()
        if out.exists():
            parser.error("Output already exists; refusing to overwrite")
        out.write_text(payload + "\n", encoding="utf-8")
    print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
