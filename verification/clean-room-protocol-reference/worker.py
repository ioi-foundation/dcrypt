#!/usr/bin/env python3
"""Isolated refusal worker. This file intentionally contains no crypto backend."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys


PROTOCOL_VERSION = "dcrypt-clean-room-ipc/1"
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
EXPECTED_KEYS = {
    "challenge",
    "operation",
    "parent_pid",
    "request_id",
    "request_sha256",
    "suite_id",
}


def canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        + b"\n"
    )


def fail(code: str, detail: str, envelope: object | None = None) -> int:
    request_id = "invalid"
    request_digest = "0" * 64
    challenge = "0" * 64
    if isinstance(envelope, dict):
        if isinstance(envelope.get("request_id"), str):
            request_id = envelope["request_id"]
        if isinstance(envelope.get("request_sha256"), str) and HEX_64.fullmatch(
            envelope["request_sha256"]
        ):
            request_digest = envelope["request_sha256"]
        if isinstance(envelope.get("challenge"), str) and HEX_64.fullmatch(
            envelope["challenge"]
        ):
            challenge = envelope["challenge"]
    execution_id = hashlib.sha256(
        (challenge + request_digest + str(os.getpid())).encode("ascii")
    ).hexdigest()
    response = {
        "accepted_evidence_count": 0,
        "accepted_fixture_count": 0,
        "challenge": challenge,
        "error": {"code": code, "detail": detail},
        "execution_id": execution_id,
        "protocol_version": PROTOCOL_VERSION,
        "release_status": "release-blocked",
        "request_id": request_id,
        "request_sha256": request_digest,
        "status": "refused",
    }
    sys.stdout.buffer.write(canonical(response))
    return 3


def read_namespace_inode(pid: int) -> int | None:
    try:
        return os.stat(f"/proc/{pid}/ns/net").st_ino
    except (FileNotFoundError, PermissionError, OSError):
        return None


def network_isolation_proven(parent_pid: int) -> bool:
    parent_net = read_namespace_inode(parent_pid)
    worker_net = read_namespace_inode(os.getpid())
    if parent_net is None or worker_net is None or parent_net == worker_net:
        return False
    try:
        interfaces = set(os.listdir("/sys/class/net"))
    except (FileNotFoundError, PermissionError, OSError):
        return False
    # A distinct namespace with any non-loopback interface remains networked.
    return interfaces <= {"lo"}


def main() -> int:
    if __name__ != "__main__":
        return fail("same-process-forbidden", "worker must execute as a standalone process")
    if not sys.flags.isolated or not sys.flags.no_site:
        return fail(
            "python-isolation-missing",
            "worker requires Python -I -S and refuses inherited import state",
        )
    raw = sys.stdin.buffer.read(65537)
    if len(raw) > 65536:
        return fail("request-too-large", "worker envelope exceeds 65536 bytes")
    try:
        text = raw.decode("ascii")
        envelope = json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return fail("malformed-envelope", "worker envelope is not canonical JSON")
    if canonical(envelope) != raw:
        return fail("noncanonical-envelope", "worker envelope is not canonical JSON", envelope)
    if not isinstance(envelope, dict) or set(envelope) != EXPECTED_KEYS:
        return fail("closed-envelope-violation", "worker envelope members differ", envelope)
    parent_pid = envelope.get("parent_pid")
    if not isinstance(parent_pid, int) or isinstance(parent_pid, bool):
        return fail("invalid-parent", "parent_pid must be an integer", envelope)
    if parent_pid != os.getppid() or parent_pid == os.getpid():
        return fail("same-process-forbidden", "parent/worker process boundary is invalid", envelope)
    for key in ("challenge", "request_sha256"):
        if not isinstance(envelope.get(key), str) or not HEX_64.fullmatch(envelope[key]):
            return fail("invalid-envelope-digest", f"invalid {key}", envelope)
    if envelope.get("operation") == "status":
        return fail(
            "scaffold-only",
            "no reference backend, fixtures, or assurance evidence is installed",
            envelope,
        )
    if not network_isolation_proven(parent_pid):
        return fail(
            "network-isolation-unproven",
            "cryptographic work requires a distinct OS network namespace",
            envelope,
        )
    return fail(
        "backend-not-approved",
        "the reviewed backend digest allowlist is empty and protocol binding is pending",
        envelope,
    )


if __name__ == "__main__":
    raise SystemExit(main())
