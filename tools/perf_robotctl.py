#!/usr/bin/env python3
"""Small control utility; it is never imported by the realtime agent path."""

from __future__ import annotations

import argparse
import socket
import sys


DEFAULT_SOCKET = "@perf_robot.control"


def main() -> int:
    parser = argparse.ArgumentParser(description="Control the perf_robot agent")
    parser.add_argument("command", choices=("status", "capture", "stop"))
    parser.add_argument("--socket", default=DEFAULT_SOCKET)
    args = parser.parse_args()

    try:
        address = "\0" + args.socket[1:] if args.socket.startswith("@") else args.socket
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(2.0)
            client.connect(address)
            client.sendall((args.command + "\n").encode())
            response = client.recv(65536).decode().strip()
        print(response)
        return 0
    except (PermissionError, OSError) as exc:
        print(exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
