#!/usr/bin/env python3
"""Target-host Mail Security acceptance and scanner-upgrade campaign.

The default mode is a read-only plan. --execute stops and starts only the
configured scanner unit, injects synthetic mail into a .test/.invalid domain,
and optionally runs an explicitly supplied package-upgrade executable while
the scanner is stopped. The ingress unit is never intentionally restarted.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import gzip
import hashlib
import json
import os
import platform
import shutil
import smtplib
import ssl
import statistics
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http.cookiejar import CookieJar
from pathlib import Path


def parse_counts(value: str) -> list[int]:
    try:
        counts = [int(item) for item in value.split(",")]
    except ValueError as error:
        raise argparse.ArgumentTypeError("message counts must be comma-separated integers") from error
    if not counts or any(count < 100 or count > 100_000 for count in counts):
        raise argparse.ArgumentTypeError("each message count must be between 100 and 100000")
    return counts


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--ca-file", type=Path, required=True)
    parser.add_argument("--admin-url", required=True)
    parser.add_argument("--admin-username", default="admin")
    parser.add_argument("--admin-password-file", type=Path, required=True)
    parser.add_argument("--peer-admin-url")
    parser.add_argument("--peer-admin-username", default="admin")
    parser.add_argument("--peer-admin-password-file", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--smtp-host", default="127.0.0.1")
    parser.add_argument("--smtp-port", type=int, default=25)
    parser.add_argument("--recipient", required=True)
    parser.add_argument("--sender", default="campaign@sender.invalid")
    parser.add_argument("--messages", type=parse_counts, default=parse_counts("10000,25000,50000"))
    parser.add_argument("--message-bytes", type=int, default=4096)
    parser.add_argument(
        "--message-profile",
        choices=("text", "mixed"),
        default="text",
        help="text, or a deterministic five-part representative MIME mix",
    )
    parser.add_argument("--concurrency", type=int, default=32)
    parser.add_argument("--messages-per-connection", type=int, default=100)
    parser.add_argument("--drain-timeout-seconds", type=int, default=1800)
    parser.add_argument("--scanner-unit", default="workglen-security-scanner.service")
    parser.add_argument("--ingress-unit", default="workglen-security.service")
    parser.add_argument("--upgrade-executable", type=Path)
    parser.add_argument("--upgrade-arg", action="append", default=[])
    parser.add_argument("--outage-hold-seconds", type=int, default=5)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--confirm-disposable-host", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.smtp_port <= 65535:
        parser.error("--smtp-port must be between 1 and 65535")
    if not 256 <= args.message_bytes <= 10 * 1024 * 1024:
        parser.error("--message-bytes must be between 256 and 10485760")
    if args.message_profile == "mixed" and args.message_bytes < 4096:
        parser.error("--message-profile=mixed requires --message-bytes of at least 4096")
    if not 1 <= args.concurrency <= 100:
        parser.error("--concurrency must be between 1 and 100")
    if not 1 <= args.messages_per_connection <= 500:
        parser.error("--messages-per-connection must be between 1 and 500")
    if args.execute and not args.confirm_disposable_host:
        parser.error("--execute requires --confirm-disposable-host")
    if args.upgrade_executable and not args.execute:
        parser.error("--upgrade-executable is meaningful only with --execute")
    if bool(args.peer_admin_url) != bool(args.peer_admin_password_file):
        parser.error("--peer-admin-url and --peer-admin-password-file must be supplied together")
    return args


def checked_path(path: Path, label: str, executable: bool = False) -> Path:
    resolved = path.expanduser().resolve(strict=True)
    if not resolved.is_file():
        raise RuntimeError(f"{label} is not a regular file: {resolved}")
    if executable and not os.access(resolved, os.X_OK):
        raise RuntimeError(f"{label} is not executable: {resolved}")
    return resolved


def test_address(value: str, label: str) -> None:
    local, separator, domain = value.rpartition("@")
    if not separator or not local or not domain.lower().endswith((".test", ".invalid")):
        raise RuntimeError(f"{label} must use a reserved .test or .invalid domain")


def run(command: list[str], *, input_text: str | None = None, timeout: int = 300) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        input=input_text,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(command)}\n{detail}")
    return result


class SecurityApi:
    def __init__(self, origin: str, ca_file: Path, username: str, password_file: Path):
        parsed = urllib.parse.urlsplit(origin)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
        ):
            raise RuntimeError("--admin-url must be a canonical HTTPS origin")
        self.origin = origin.rstrip("/")
        self.csrf: str | None = None
        self.username = username
        self.password = password_file.read_text(encoding="utf-8").rstrip("\r\n")
        if not self.password:
            raise RuntimeError("admin password file is empty")
        context = ssl.create_default_context(cafile=str(ca_file))
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context),
            urllib.request.HTTPCookieProcessor(CookieJar()),
        )
        self.login()

    def login(self) -> None:
        self.csrf = None
        session = self.post(
            "/api/login",
            {"username": self.username, "password": self.password},
            csrf=False,
            retry=False,
        )
        self.csrf = session.get("csrf")
        if not isinstance(self.csrf, str) or not self.csrf:
            raise RuntimeError("gateway login did not return a CSRF token")

    def post(self, path: str, value: dict, *, csrf: bool = True, retry: bool = True) -> dict:
        body = json.dumps(value).encode()
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Origin": self.origin,
        }
        if csrf and self.csrf:
            headers["X-CSRF-Token"] = self.csrf
        request = urllib.request.Request(self.origin + path, data=body, headers=headers, method="POST")
        try:
            with self.opener.open(request, timeout=30) as response:
                result = json.load(response)
        except urllib.error.HTTPError as error:
            if csrf and retry and error.code in (401, 403):
                self.login()
                return self.post(path, value, csrf=csrf, retry=False)
            detail = error.read(4096).decode(errors="replace")
            raise RuntimeError(f"gateway API returned HTTP {error.code}: {detail}") from error
        if not isinstance(result, dict):
            raise RuntimeError("gateway API did not return an object")
        return result

    def status(self) -> dict:
        return self.post(
            "/api/command",
            {"action": "status", "data": {}, "request_id": str(uuid.uuid4())},
        )


def ha_readiness(local: dict, peer: dict) -> dict:
    violations: list[str] = []
    local_cluster = local.get("cluster", {})
    peer_cluster = peer.get("cluster", {})
    local_id = local_cluster.get("node_id")
    peer_id = peer_cluster.get("node_id")
    if not local_id or not peer_id or local_id == peer_id:
        violations.append("nodes must report distinct non-empty durable node IDs")
    if not local_cluster.get("cluster_id") or local_cluster.get("cluster_id") != peer_cluster.get("cluster_id"):
        violations.append("nodes must report the same non-empty cluster ID")
    local_min = int(local_cluster.get("minimum_protocol_version", 0))
    local_max = int(local_cluster.get("protocol_version", 0))
    peer_min = int(peer_cluster.get("minimum_protocol_version", 0))
    peer_max = int(peer_cluster.get("protocol_version", 0))
    if max(local_min, peer_min) > min(local_max, peer_max):
        violations.append("node replication protocol windows do not overlap")
    local_peers = {item.get("node_id") for item in local_cluster.get("peers", [])}
    peer_peers = {item.get("node_id") for item in peer_cluster.get("peers", [])}
    if peer_id not in local_peers or local_id not in peer_peers:
        violations.append("each node must list the other as a configured replication peer")
    for label, cluster in (("local", local_cluster), ("peer", peer_cluster)):
        if cluster.get("topology") != "authenticated-peer-log":
            violations.append(f"{label} node is not using authenticated peer-log topology")
        if cluster.get("synchronized") is not True:
            violations.append(f"{label} node lacks fresh bidirectional contact or has replication debt")
        for debt_name in ("replication_debt", "state_replication_debt"):
            if int(cluster.get(debt_name, {}).get("operations", 0)) != 0:
                violations.append(f"{label} node has nonzero {debt_name} operations")
    return {
        "passed": not violations,
        "local_node_id": local_id,
        "peer_node_id": peer_id,
        "cluster_id": local_cluster.get("cluster_id"),
        "protocol_intersection": [max(local_min, peer_min), min(local_max, peer_max)],
        "violations": violations,
    }


def os_release() -> dict[str, str]:
    values: dict[str, str] = {}
    for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value.strip().strip('"')
    return values


def unit_state(unit: str) -> dict[str, str]:
    properties = [
        "Id", "LoadState", "ActiveState", "SubState", "FragmentPath", "ExecMainPID",
        "Restart", "NoNewPrivileges", "ProtectSystem", "PrivateTmp", "ReadWritePaths",
        "MemoryCurrent", "MemoryPeak", "MemoryHigh", "MemoryMax", "MemorySwapMax",
    ]
    result = run(["systemctl", "show", unit, "--property=" + ",".join(properties)])
    return dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)


def percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int((len(ordered) - 1) * fraction))]


MIXED_MESSAGE_VARIANTS = (
    "text",
    "benign-attachment",
    "compression-heavy",
    "nested-message",
    "malformed-base64",
)


def message_variant(index: int, profile: str) -> str:
    return "text" if profile == "text" else MIXED_MESSAGE_VARIANTS[index % len(MIXED_MESSAGE_VARIANTS)]


def fit_message(prefix: bytes, suffix: bytes, size: int) -> bytes:
    minimum = len(prefix) + len(suffix)
    if minimum > size:
        raise RuntimeError(f"message profile needs at least {minimum} bytes; requested {size}")
    return prefix + (b"x" * (size - minimum)) + suffix


def message(
    index: int,
    size: int,
    sender: str,
    recipient: str,
    campaign: str,
    profile: str = "text",
) -> bytes:
    variant = message_variant(index, profile)
    headers = (
        f"From: {sender}\r\nTo: {recipient}\r\n"
        f"Subject: Workglen Ubuntu campaign {campaign} {index}\r\n"
        f"Message-ID: <{campaign}-{index}@sender.invalid>\r\n"
        f"X-Workglen-Campaign-Profile: {variant}\r\n"
        "MIME-Version: 1.0\r\n"
    ).encode()
    if variant == "text":
        return fit_message(
            headers + b"Content-Type: text/plain; charset=utf-8\r\n\r\n",
            b"\r\n",
            size,
        )

    boundary = f"workglen-{campaign}-{index}".encode()
    multipart = headers + b'Content-Type: multipart/mixed; boundary="' + boundary + b'"\r\n\r\n'
    first_part = (
        b"--" + boundary + b"\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
        b"Synthetic representative campaign content.\r\n"
    )
    closing = b"\r\n--" + boundary + b"--\r\n"

    if variant == "benign-attachment":
        attachment = base64.b64encode((b"quarterly-ledger-row," * 24) + b"\r\n")
        second_part = (
            b"--" + boundary + b"\r\n"
            b"Content-Type: text/csv; name=ledger.csv\r\n"
            b"Content-Disposition: attachment; filename=ledger.csv\r\n"
            b"Content-Transfer-Encoding: base64\r\n\r\n" + attachment + b"\r\n"
        )
    elif variant == "compression-heavy":
        expanded_size = min(4 * 1024 * 1024, max(256 * 1024, size * 2))
        compressed = gzip.compress(b"archive-campaign-row\n" * (expanded_size // 21), mtime=0)
        second_part = (
            b"--" + boundary + b"\r\n"
            b"Content-Type: application/gzip; name=representative.txt.gz\r\n"
            b"Content-Disposition: attachment; filename=representative.txt.gz\r\n"
            b"Content-Transfer-Encoding: base64\r\n\r\n"
            + base64.b64encode(compressed)
            + b"\r\n"
        )
    elif variant == "nested-message":
        nested = (
            f"From: nested@sender.invalid\r\nTo: {recipient}\r\n"
            f"Subject: Nested campaign message {index}\r\n"
            "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
            "Nested body for parser coverage.\r\n"
        ).encode()
        second_part = (
            b"--" + boundary + b"\r\n"
            b"Content-Type: message/rfc822\r\n"
            b"Content-Disposition: attachment; filename=nested.eml\r\n\r\n"
            + nested
        )
    else:
        second_part = (
            b"--" + boundary + b"\r\n"
            b"Content-Type: application/octet-stream; name=malformed.bin\r\n"
            b"Content-Disposition: attachment; filename=malformed.bin\r\n"
            b"Content-Transfer-Encoding: base64\r\n\r\n"
            b"%%% deliberately-invalid-base64 %%%\r\n"
        )
    return fit_message(multipart + first_part + second_part, closing, size)


def inject(args: argparse.Namespace, count: int, campaign: str) -> dict:
    lock = threading.Lock()
    next_index = 0
    accepted = 0
    deferred = 0
    rejected = 0
    failures: list[str] = []
    latencies: list[float] = []
    accepted_variants = {variant: 0 for variant in MIXED_MESSAGE_VARIANTS}
    context = ssl.create_default_context(cafile=str(args.ca_file))

    def worker() -> None:
        nonlocal next_index, accepted, deferred, rejected
        while True:
            with lock:
                start = next_index
                next_index += args.messages_per_connection
            if start >= count:
                return
            stop = min(count, start + args.messages_per_connection)
            try:
                with smtplib.SMTP(args.smtp_host, args.smtp_port, timeout=30) as client:
                    client.ehlo()
                    client.starttls(context=context)
                    client.ehlo()
                    for index in range(start, stop):
                        began = time.monotonic()
                        try:
                            client.sendmail(
                                args.sender,
                                [args.recipient],
                                message(
                                    index,
                                    args.message_bytes,
                                    args.sender,
                                    args.recipient,
                                    campaign,
                                    args.message_profile,
                                ),
                            )
                            elapsed = time.monotonic() - began
                            with lock:
                                accepted += 1
                                latencies.append(elapsed)
                                accepted_variants[message_variant(index, args.message_profile)] += 1
                        except smtplib.SMTPResponseException as error:
                            with lock:
                                if 400 <= error.smtp_code < 500:
                                    deferred += 1
                                else:
                                    rejected += 1
                                failures.append(f"SMTP {error.smtp_code}: {error.smtp_error!r}")
            except Exception as error:  # The report retains a bounded diagnostic sample.
                with lock:
                    failures.append(f"{type(error).__name__}: {error}")

    began = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futures = [pool.submit(worker) for _ in range(args.concurrency)]
        for future in futures:
            future.result()
    elapsed = time.monotonic() - began
    return {
        "requested": count,
        "accepted": accepted,
        "deferred": deferred,
        "rejected": rejected,
        "unattempted_or_connection_failed": count - accepted - deferred - rejected,
        "seconds": elapsed,
        "accepted_per_second": accepted / elapsed if elapsed else None,
        "message_profile": args.message_profile,
        "accepted_variants": {
            variant: value for variant, value in accepted_variants.items() if value
        },
        "latency_ms": {
            "p50": (percentile(latencies, 0.50) or 0) * 1000 if latencies else None,
            "p95": (percentile(latencies, 0.95) or 0) * 1000 if latencies else None,
            "p99": (percentile(latencies, 0.99) or 0) * 1000 if latencies else None,
            "mean": statistics.fmean(latencies) * 1000 if latencies else None,
        },
        "failure_sample": failures[:20],
    }


def wait_for_drain(api: SecurityApi, baseline: int, timeout: int) -> dict:
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = api.status()
        if int(last.get("scanner", {}).get("receive_records", 0)) <= baseline:
            return last
        time.sleep(2)
    raise RuntimeError(
        f"receive queue did not drain to baseline {baseline}; last depth "
        f"{(last or {}).get('scanner', {}).get('receive_records')}"
    )


def wait_for_ha_readiness(local_api: SecurityApi, peer_api: SecurityApi, timeout: int) -> tuple[dict, dict, dict]:
    deadline = time.monotonic() + timeout
    last_local: dict = {}
    last_peer: dict = {}
    last_readiness: dict = {"passed": False, "violations": ["not checked"]}
    while time.monotonic() < deadline:
        last_local = local_api.status()
        last_peer = peer_api.status()
        last_readiness = ha_readiness(last_local, last_peer)
        if last_readiness["passed"]:
            return last_local, last_peer, last_readiness
        time.sleep(2)
    raise RuntimeError("dual-node synchronization did not settle: " + "; ".join(last_readiness["violations"]))


def main() -> int:
    args = arguments()
    release = os_release()
    if release.get("ID") != "ubuntu":
        raise RuntimeError(f"campaign requires Ubuntu; detected {release.get('ID', 'unknown')}")
    if not Path("/run/systemd/system").is_dir() or shutil.which("systemctl") is None:
        raise RuntimeError("campaign requires a running systemd host")
    test_address(args.sender, "sender")
    test_address(args.recipient, "recipient")
    args.binary = checked_path(args.binary, "binary", executable=True)
    args.config = checked_path(args.config, "config")
    args.ca_file = checked_path(args.ca_file, "CA file")
    args.admin_password_file = checked_path(args.admin_password_file, "admin password file")
    if args.admin_password_file.stat().st_mode & 0o077:
        raise RuntimeError("admin password file must not be accessible by group or other users")
    if args.peer_admin_password_file:
        args.peer_admin_password_file = checked_path(
            args.peer_admin_password_file, "peer admin password file"
        )
        if args.peer_admin_password_file.stat().st_mode & 0o077:
            raise RuntimeError("peer admin password file must not be accessible by group or other users")
    if args.upgrade_executable:
        args.upgrade_executable = checked_path(args.upgrade_executable, "upgrade executable", executable=True)
    output = args.output.expanduser().resolve()
    if output.exists():
        raise RuntimeError(f"evidence path already exists: {output}")
    api = SecurityApi(
        args.admin_url,
        args.ca_file,
        args.admin_username,
        args.admin_password_file,
    )
    peer_api = (
        SecurityApi(
            args.peer_admin_url,
            args.ca_file,
            args.peer_admin_username,
            args.peer_admin_password_file,
        )
        if args.peer_admin_url and args.peer_admin_password_file
        else None
    )
    local_status = api.status()
    peer_status = peer_api.status() if peer_api else None

    preflight = {
        "schema": 1,
        "mode": "execute" if args.execute else "plan",
        "started_at": int(time.time()),
        "host": {
            "hostname": platform.node(),
            "platform": platform.platform(),
            "cpu_count": os.cpu_count(),
            "ubuntu": release.get("PRETTY_NAME"),
            "filesystem": shutil.disk_usage(args.config.parent)._asdict(),
        },
        "binary_sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest(),
        "config_sha256": hashlib.sha256(args.config.read_bytes()).hexdigest(),
        "ingress_unit": unit_state(args.ingress_unit),
        "scanner_unit": unit_state(args.scanner_unit),
        "status": local_status,
        "peer_status": peer_status,
        "ha_readiness": ha_readiness(local_status, peer_status) if peer_status else None,
        "campaign": {
            "message_counts": args.messages,
            "message_bytes": args.message_bytes,
            "message_profile": args.message_profile,
            "message_variants": (
                list(MIXED_MESSAGE_VARIANTS) if args.message_profile == "mixed" else ["text"]
            ),
            "concurrency": args.concurrency,
            "messages_per_connection": args.messages_per_connection,
            "package_upgrade_driver": bool(args.upgrade_executable),
        },
    }
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    (output / "preflight.json").write_text(json.dumps(preflight, indent=2) + "\n", encoding="utf-8")
    if preflight["ingress_unit"].get("ActiveState") != "active":
        raise RuntimeError("ingress unit is not active")
    if not args.execute:
        print(json.dumps({"planned": True, "evidence": str(output), "preflight": preflight}, indent=2))
        return 0
    if preflight["ha_readiness"] is not None and not preflight["ha_readiness"]["passed"]:
        raise RuntimeError(
            "dual-node preflight failed: " + "; ".join(preflight["ha_readiness"]["violations"])
        )
    if os.geteuid() != 0:
        raise RuntimeError("--execute requires root for controlled systemd scanner transitions")
    baseline = int(preflight["status"].get("scanner", {}).get("receive_records", 0))
    if baseline != 0:
        raise RuntimeError(f"execute mode requires an empty receive queue; found {baseline} record(s)")
    capacity = preflight["status"].get("capacity", {})
    required_records = sum(args.messages)
    for kind in ("messages", "jobs"):
        used = int(capacity.get(kind, {}).get("used", 0))
        limit = int(capacity.get(kind, {}).get("limit", 0))
        if limit and used + required_records > limit:
            raise RuntimeError(
                f"cumulative campaign needs {used + required_records} {kind}; configured limit is {limit}"
            )

    phases = []
    scanner_stopped = False
    try:
        for number, count in enumerate(args.messages, 1):
            run(["systemctl", "stop", args.scanner_unit])
            scanner_stopped = True
            if unit_state(args.scanner_unit).get("ActiveState") != "inactive":
                raise RuntimeError("scanner unit did not stop cleanly")
            campaign = f"{int(time.time())}-{number}"
            upgrade = None
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                load = pool.submit(inject, args, count, campaign)
                time.sleep(1)
                if args.upgrade_executable:
                    began = time.monotonic()
                    result = run(
                        [str(args.upgrade_executable), *args.upgrade_arg],
                        timeout=max(300, args.drain_timeout_seconds),
                    )
                    upgrade = {
                        "seconds": time.monotonic() - began,
                        "stdout_sha256": hashlib.sha256(result.stdout.encode()).hexdigest(),
                        "stderr_sha256": hashlib.sha256(result.stderr.encode()).hexdigest(),
                    }
                elapsed = time.monotonic() + args.outage_hold_seconds
                while time.monotonic() < elapsed:
                    time.sleep(min(0.25, elapsed - time.monotonic()))
                injection = load.result()
            if unit_state(args.ingress_unit).get("ActiveState") != "active":
                raise RuntimeError("ingress unit stopped during scanner replacement")
            queued = api.status()
            peer_queued = peer_api.status() if peer_api else None
            run(["systemctl", "start", args.scanner_unit])
            scanner_stopped = False
            drained = wait_for_drain(api, baseline, args.drain_timeout_seconds)
            if peer_api:
                drained, peer_drained, post_ha = wait_for_ha_readiness(
                    api, peer_api, args.drain_timeout_seconds
                )
            else:
                peer_drained = None
                post_ha = None
            phase = {
                "messages": count,
                "injection": injection,
                "upgrade": upgrade,
                "queued_status": queued,
                "drained_status": drained,
                "peer_queued_status": peer_queued,
                "peer_drained_status": peer_drained,
                "ha_readiness": post_ha,
                "ingress_unit": unit_state(args.ingress_unit),
                "scanner_unit": unit_state(args.scanner_unit),
                "binary_sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest(),
            }
            phase["passed"] = (
                injection["accepted"] == count
                and injection["deferred"] == 0
                and injection["rejected"] == 0
                and injection["unattempted_or_connection_failed"] == 0
            )
            phases.append(phase)
            (output / f"phase-{count}.json").write_text(json.dumps(phase, indent=2) + "\n", encoding="utf-8")
            if not phase["passed"]:
                raise RuntimeError(f"SMTP injection phase for {count} messages did not pass")
    finally:
        if scanner_stopped:
            subprocess.run(["systemctl", "start", args.scanner_unit], check=False)

    report = {
        "schema": 1,
        "passed": all(phase["passed"] for phase in phases),
        "completed_at": int(time.time()),
        "qualification": (
            "dual-node Ubuntu/systemd scanner replacement with an explicit package-upgrade driver"
            if args.upgrade_executable and peer_api
            else "Ubuntu/systemd scanner replacement with an explicit package-upgrade driver"
            if args.upgrade_executable
            else "dual-node-observed Ubuntu/systemd scanner stop/start campaign; no package upgrade driver was supplied"
            if peer_api
            else "Ubuntu/systemd scanner stop/start campaign; no package upgrade driver was supplied"
        ),
        "excluded": [
            "host power-loss injection",
            "physical filesystem exhaustion",
            "detection-efficacy claims",
            "public DNS, MX, firewall, or real-provider validation",
        ],
        "phases": phases,
    }
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": report["passed"], "evidence": str(output)}, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
