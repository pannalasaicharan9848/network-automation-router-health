#!/usr/bin/env python3
"""
router_fleet_health.py
======================

Read-only health-check automation for small or large router fleets.

Designed workflow:
    1. Load and validate inventory.
    2. Prompt for credentials or read them from environment variables.
    3. Connect to routers with controlled concurrency.
    4. Collect hostname, interface, BGP, CPU, memory, and route information.
    5. Classify every router as HEALTHY, WARNING, or UNHEALTHY.
    6. Continue processing even when individual routers fail.
    7. Write CSV and JSON reports plus a detailed log.

Supported command profiles:
    - cisco_ios
    - cisco_xe
    - cisco_nxos
    - arista_eos
    - juniper_junos

This is a starter framework. Device output varies by platform and software
release. Test the parser and thresholds in a lab before using it in production.

Requirements:
    python -m pip install netmiko

Create a sample inventory:
    python router_fleet_health.py --create-sample

Run:
    python router_fleet_health.py --inventory inventory.csv --workers 30

Environment variables (optional):
    ROUTER_USERNAME
    ROUTER_PASSWORD
    ROUTER_SECRET

Inventory CSV columns:
    name,host,device_type,port,username,expected_bgp_peers,
    expected_up_interfaces,max_cpu_percent,max_memory_percent

Notes:
    - expected_up_interfaces uses semicolons:
      GigabitEthernet0/0;GigabitEthernet0/1
    - Empty expected values are treated as unknown rather than failed.
    - Begin with 5-10 workers in a lab. Increase carefully.
"""

from __future__ import annotations

import argparse
import csv
import getpass
import ipaddress
import json
import logging
import os
import re
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from netmiko import ConnectHandler
    from netmiko.exceptions import (
        NetmikoAuthenticationException,
        NetmikoTimeoutException,
    )
except ImportError:
    print(
        "Netmiko is not installed.\n"
        "Install it with: python -m pip install netmiko",
        file=sys.stderr,
    )
    raise SystemExit(2)


SUPPORTED_DEVICE_TYPES = {
    "cisco_ios",
    "cisco_xe",
    "cisco_nxos",
    "arista_eos",
    "juniper_junos",
}

COMMANDS: dict[str, dict[str, str]] = {
    "cisco_ios": {
        "hostname": "show running-config | include ^hostname",
        "interfaces": "show ip interface brief",
        "bgp": "show ip bgp summary",
        "cpu": "show processes cpu | include CPU utilization",
        "memory": "show memory statistics",
        "routes": "show ip route summary",
    },
    "cisco_xe": {
        "hostname": "show running-config | include ^hostname",
        "interfaces": "show ip interface brief",
        "bgp": "show ip bgp summary",
        "cpu": "show processes cpu | include CPU utilization",
        "memory": "show memory statistics",
        "routes": "show ip route summary",
    },
    "cisco_nxos": {
        "hostname": "show hostname",
        "interfaces": "show ip interface brief",
        "bgp": "show bgp ipv4 unicast summary",
        "cpu": "show system resources",
        "memory": "show system resources",
        "routes": "show ip route summary",
    },
    "arista_eos": {
        "hostname": "show hostname",
        "interfaces": "show ip interface brief",
        "bgp": "show ip bgp summary",
        "cpu": "show processes top once",
        "memory": "show version",
        "routes": "show ip route summary",
    },
    "juniper_junos": {
        "hostname": "show configuration system host-name | display set",
        "interfaces": "show interfaces terse",
        "bgp": "show bgp summary",
        "cpu": "show chassis routing-engine",
        "memory": "show chassis routing-engine",
        "routes": "show route summary",
    },
}


@dataclass(frozen=True)
class Router:
    name: str
    host: str
    device_type: str
    port: int = 22
    username: str = ""
    expected_bgp_peers: int | None = None
    expected_up_interfaces: tuple[str, ...] = ()
    max_cpu_percent: float = 80.0
    max_memory_percent: float = 85.0


@dataclass
class HealthResult:
    name: str
    host: str
    device_type: str
    checked_at_utc: str
    reachable: bool
    authenticated: bool
    detected_hostname: str
    interface_status: str
    expected_interfaces_up: int
    expected_interfaces_total: int
    bgp_status: str
    bgp_established: int | None
    bgp_expected: int | None
    cpu_status: str
    cpu_percent: float | None
    memory_status: str
    memory_percent: float | None
    route_status: str
    route_count: int | None
    overall_status: str
    duration_seconds: float
    error: str


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def optional_int(value: str) -> int | None:
    value = value.strip()
    return int(value) if value else None


def optional_float(value: str, default: float) -> float:
    value = value.strip()
    return float(value) if value else default


def parse_interfaces(value: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in value.split(";") if item.strip())


def validate_host(host: str) -> None:
    """Accept an IP address or a resolvable hostname-like value."""
    try:
        ipaddress.ip_address(host)
        return
    except ValueError:
        pass

    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,252}", host):
        raise ValueError(f"Invalid host value: {host!r}")


def load_inventory(path: Path) -> list[Router]:
    required = {"name", "host", "device_type"}
    routers: list[Router] = []
    seen_names: set[str] = set()
    seen_hosts: set[str] = set()

    with path.open("r", newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise ValueError("Inventory has no header row.")

        missing = required - set(reader.fieldnames)
        if missing:
            raise ValueError(
                f"Inventory missing required columns: {', '.join(sorted(missing))}"
            )

        for line_number, row in enumerate(reader, start=2):
            name = (row.get("name") or "").strip()
            host = (row.get("host") or "").strip()
            device_type = (row.get("device_type") or "").strip()
            username = (row.get("username") or "").strip()

            if not name or not host or not device_type:
                raise ValueError(
                    f"Inventory line {line_number}: name, host, and device_type are required."
                )

            validate_host(host)

            if device_type not in SUPPORTED_DEVICE_TYPES:
                raise ValueError(
                    f"Inventory line {line_number}: unsupported device_type "
                    f"{device_type!r}. Supported: {sorted(SUPPORTED_DEVICE_TYPES)}"
                )

            if name in seen_names:
                raise ValueError(f"Duplicate router name: {name}")
            if host in seen_hosts:
                raise ValueError(f"Duplicate router host: {host}")

            seen_names.add(name)
            seen_hosts.add(host)

            router = Router(
                name=name,
                host=host,
                device_type=device_type,
                port=int((row.get("port") or "22").strip()),
                username=username,
                expected_bgp_peers=optional_int(
                    row.get("expected_bgp_peers") or ""
                ),
                expected_up_interfaces=parse_interfaces(
                    row.get("expected_up_interfaces") or ""
                ),
                max_cpu_percent=optional_float(
                    row.get("max_cpu_percent") or "", 80.0
                ),
                max_memory_percent=optional_float(
                    row.get("max_memory_percent") or "", 85.0
                ),
            )
            routers.append(router)

    if not routers:
        raise ValueError("Inventory contains no routers.")

    return routers


def create_sample_inventory(path: Path) -> None:
    fields = [
        "name",
        "host",
        "device_type",
        "port",
        "username",
        "expected_bgp_peers",
        "expected_up_interfaces",
        "max_cpu_percent",
        "max_memory_percent",
    ]
    rows = [
        {
            "name": "lab-r1",
            "host": "192.0.2.10",
            "device_type": "cisco_ios",
            "port": "22",
            "username": "networkadmin",
            "expected_bgp_peers": "2",
            "expected_up_interfaces": "GigabitEthernet0/0;GigabitEthernet0/1",
            "max_cpu_percent": "80",
            "max_memory_percent": "85",
        },
        {
            "name": "lab-r2",
            "host": "192.0.2.11",
            "device_type": "arista_eos",
            "port": "22",
            "username": "networkadmin",
            "expected_bgp_peers": "2",
            "expected_up_interfaces": "Ethernet1;Ethernet2",
            "max_cpu_percent": "80",
            "max_memory_percent": "85",
        },
    ]

    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def extract_first_percent(output: str, patterns: list[str]) -> float | None:
    for pattern in patterns:
        match = re.search(pattern, output, flags=re.IGNORECASE | re.MULTILINE)
        if match:
            return float(match.group(1))
    return None


def parse_hostname(output: str, fallback: str) -> str:
    patterns = [
        r"^\s*hostname\s+(\S+)",
        r"^\s*Hostname:\s*(\S+)",
        r"^\s*set system host-name\s+(\S+)",
        r"^\s*(\S+)\s*$",
    ]
    for pattern in patterns:
        match = re.search(pattern, output, flags=re.IGNORECASE | re.MULTILINE)
        if match:
            return match.group(1).strip()
    return fallback


def parse_cpu(device_type: str, output: str) -> float | None:
    patterns = [
        r"CPU utilization for five seconds:\s*(\d+(?:\.\d+)?)%",
        r"CPU states\s*:\s*(\d+(?:\.\d+)?)%\s*user",
        r"CPU utilization:\s*(\d+(?:\.\d+)?)%",
        r"CPU utilization\s+(\d+(?:\.\d+)?)\s*percent",
    ]

    if device_type == "juniper_junos":
        idle = extract_first_percent(
            output, [r"Idle\s+(\d+(?:\.\d+)?)\s*percent"]
        )
        return 100.0 - idle if idle is not None else None

    return extract_first_percent(output, patterns)


def parse_memory(device_type: str, output: str) -> float | None:
    direct_patterns = [
        r"Memory utilization\s+(\d+(?:\.\d+)?)\s*percent",
        r"Memory usage:\s*(\d+(?:\.\d+)?)%",
        r"Memory utilization:\s*(\d+(?:\.\d+)?)%",
    ]
    direct = extract_first_percent(output, direct_patterns)
    if direct is not None:
        return direct

    if device_type in {"cisco_ios", "cisco_xe"}:
        match = re.search(
            r"Processor\s+\S+\s+(\d+)\s+(\d+)\s+(\d+)",
            output,
            flags=re.IGNORECASE,
        )
        if match:
            total = float(match.group(1))
            used = float(match.group(2))
            return (used / total * 100.0) if total else None

    if device_type == "cisco_nxos":
        match = re.search(
            r"Memory usage:\s*(\d+)K total,\s*(\d+)K used",
            output,
            flags=re.IGNORECASE,
        )
        if match:
            total = float(match.group(1))
            used = float(match.group(2))
            return (used / total * 100.0) if total else None

    if device_type == "juniper_junos":
        return extract_first_percent(
            output, [r"Memory utilization\s+(\d+(?:\.\d+)?)\s*percent"]
        )

    return None


def parse_bgp_established(device_type: str, output: str) -> int | None:
    """
    Estimate established peer count from common summary outputs.

    Cisco/Arista:
        A numeric last column normally represents prefixes for Established peers.

    Junos:
        Summary rows generally include Establ in the state field.
    """
    established = 0
    peer_rows = 0

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        if device_type == "juniper_junos":
            if re.match(r"^[0-9A-Fa-f:.]+\s+", line):
                peer_rows += 1
                if re.search(r"\bEstabl\b|\bEstablished\b", line, re.IGNORECASE):
                    established += 1
            continue

        if re.match(r"^[0-9A-Fa-f:.]+\s+", line):
            columns = line.split()
            if len(columns) >= 3:
                peer_rows += 1
                last = columns[-1]
                if last.isdigit():
                    established += 1
                elif re.search(r"\bEstab(?:lished)?\b", line, re.IGNORECASE):
                    established += 1

    return established if peer_rows > 0 else None


def parse_route_count(output: str) -> int | None:
    patterns = [
        r"Total number of routes:\s*(\d+)",
        r"Total routes:\s*(\d+)",
        r"(\d+)\s+routes",
        r"(\d+)\s+destinations",
    ]
    for pattern in patterns:
        match = re.search(pattern, output, flags=re.IGNORECASE)
        if match:
            return int(match.group(1))
    return None


def interface_is_up(output: str, interface: str) -> bool:
    """
    Generic line-based check for expected interfaces.
    Platform output varies; verify this logic against your router software.
    """
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line.lower().startswith(interface.lower()):
            continue

        lowered = line.lower()

        negative_states = [
            "administratively down",
            "admin down",
            "disabled",
            "down down",
            "down/down",
        ]
        if any(state in lowered for state in negative_states):
            return False

        positive_patterns = [
            r"\bup\s+up\b",
            r"\bup/up\b",
            r"\bup\b.*\bup\b",
        ]
        return any(re.search(pattern, lowered) for pattern in positive_patterns)

    return False


def classify_metric(value: float | None, maximum: float) -> str:
    if value is None:
        return "UNKNOWN"
    if value > maximum:
        return "FAIL"
    if value > maximum * 0.8:
        return "WARNING"
    return "PASS"


def overall_status(statuses: list[str]) -> str:
    if "FAIL" in statuses:
        return "UNHEALTHY"
    if "WARNING" in statuses or "UNKNOWN" in statuses:
        return "WARNING"
    return "HEALTHY"


def failed_result(
    router: Router,
    started: float,
    error: str,
    *,
    reachable: bool = False,
    authenticated: bool = False,
) -> HealthResult:
    return HealthResult(
        name=router.name,
        host=router.host,
        device_type=router.device_type,
        checked_at_utc=utc_now(),
        reachable=reachable,
        authenticated=authenticated,
        detected_hostname="",
        interface_status="UNKNOWN",
        expected_interfaces_up=0,
        expected_interfaces_total=len(router.expected_up_interfaces),
        bgp_status="UNKNOWN",
        bgp_established=None,
        bgp_expected=router.expected_bgp_peers,
        cpu_status="UNKNOWN",
        cpu_percent=None,
        memory_status="UNKNOWN",
        memory_percent=None,
        route_status="UNKNOWN",
        route_count=None,
        overall_status="UNHEALTHY",
        duration_seconds=round(time.monotonic() - started, 2),
        error=error,
    )


def check_router(
    router: Router,
    default_username: str,
    password: str,
    secret: str,
    retries: int,
    timeout: int,
) -> HealthResult:
    started = time.monotonic()
    connection = None
    username = router.username or default_username

    if not username:
        return failed_result(router, started, "No username provided.")

    parameters: dict[str, Any] = {
        "device_type": router.device_type,
        "host": router.host,
        "port": router.port,
        "username": username,
        "password": password,
        "secret": secret or None,
        "conn_timeout": timeout,
        "auth_timeout": timeout,
        "banner_timeout": timeout,
        "read_timeout_override": timeout,
        "fast_cli": False,
    }

    last_error = ""

    for attempt in range(1, retries + 2):
        try:
            logging.info(
                "%s (%s): connection attempt %d",
                router.name,
                router.host,
                attempt,
            )

            connection = ConnectHandler(**parameters)

            if secret:
                try:
                    connection.enable()
                except Exception as exc:
                    logging.warning(
                        "%s: could not enter enable mode: %s",
                        router.name,
                        exc,
                    )

            commands = COMMANDS[router.device_type]
            outputs: dict[str, str] = {}

            for check_name, command in commands.items():
                try:
                    outputs[check_name] = connection.send_command(
                        command,
                        read_timeout=timeout,
                        strip_prompt=True,
                        strip_command=True,
                    )
                except Exception as exc:
                    outputs[check_name] = ""
                    logging.warning(
                        "%s: command failed (%s): %s",
                        router.name,
                        check_name,
                        exc,
                    )

            detected_hostname = parse_hostname(
                outputs["hostname"], router.name
            )

            expected_total = len(router.expected_up_interfaces)
            expected_up = sum(
                interface_is_up(outputs["interfaces"], interface)
                for interface in router.expected_up_interfaces
            )

            if expected_total == 0:
                interface_status = "UNKNOWN"
            elif expected_up == expected_total:
                interface_status = "PASS"
            elif expected_up == 0:
                interface_status = "FAIL"
            else:
                interface_status = "WARNING"

            bgp_established = parse_bgp_established(
                router.device_type, outputs["bgp"]
            )
            if router.expected_bgp_peers is None:
                bgp_status = (
                    "PASS" if bgp_established is not None else "UNKNOWN"
                )
            elif bgp_established is None:
                bgp_status = "UNKNOWN"
            elif bgp_established == router.expected_bgp_peers:
                bgp_status = "PASS"
            elif bgp_established == 0:
                bgp_status = "FAIL"
            else:
                bgp_status = "WARNING"

            cpu_percent = parse_cpu(router.device_type, outputs["cpu"])
            cpu_status = classify_metric(
                cpu_percent, router.max_cpu_percent
            )

            memory_percent = parse_memory(
                router.device_type, outputs["memory"]
            )
            memory_status = classify_metric(
                memory_percent, router.max_memory_percent
            )

            route_count = parse_route_count(outputs["routes"])
            route_status = "PASS" if route_count is not None else "UNKNOWN"

            statuses = [
                interface_status,
                bgp_status,
                cpu_status,
                memory_status,
                route_status,
            ]

            return HealthResult(
                name=router.name,
                host=router.host,
                device_type=router.device_type,
                checked_at_utc=utc_now(),
                reachable=True,
                authenticated=True,
                detected_hostname=detected_hostname,
                interface_status=interface_status,
                expected_interfaces_up=expected_up,
                expected_interfaces_total=expected_total,
                bgp_status=bgp_status,
                bgp_established=bgp_established,
                bgp_expected=router.expected_bgp_peers,
                cpu_status=cpu_status,
                cpu_percent=cpu_percent,
                memory_status=memory_status,
                memory_percent=memory_percent,
                route_status=route_status,
                route_count=route_count,
                overall_status=overall_status(statuses),
                duration_seconds=round(time.monotonic() - started, 2),
                error="",
            )

        except NetmikoAuthenticationException:
            return failed_result(
                router,
                started,
                "Authentication failed.",
                reachable=True,
                authenticated=False,
            )
        except (NetmikoTimeoutException, socket.timeout, EOFError) as exc:
            last_error = f"Connection timeout/reset: {exc}"
            logging.warning(
                "%s: %s (attempt %d)",
                router.name,
                last_error,
                attempt,
            )
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            logging.exception("%s: unexpected failure", router.name)
        finally:
            if connection is not None:
                try:
                    connection.disconnect()
                except Exception:
                    pass
                connection = None

        if attempt <= retries:
            time.sleep(min(2**attempt, 10))

    return failed_result(router, started, last_error or "Unknown failure.")


def save_reports(results: list[HealthResult], output_dir: Path) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = output_dir / f"router_health_{stamp}.csv"
    json_path = output_dir / f"router_health_{stamp}.json"

    rows = [asdict(item) for item in results]
    if rows:
        with csv_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)

    with json_path.open("w", encoding="utf-8") as handle:
        json.dump(rows, handle, indent=2)

    return csv_path, json_path


def configure_logging(output_dir: Path, verbose: bool) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = output_dir / f"router_health_{stamp}.log"

    handlers: list[logging.Handler] = [
        logging.FileHandler(log_path, encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ]

    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(threadName)s %(message)s",
        handlers=handlers,
    )
    return log_path


def print_summary(results: list[HealthResult]) -> None:
    counts = {"HEALTHY": 0, "WARNING": 0, "UNHEALTHY": 0}
    for result in results:
        counts[result.overall_status] += 1

    print("\nFleet Health Summary")
    print("=" * 60)
    print(f"Total routers : {len(results)}")
    print(f"Healthy       : {counts['HEALTHY']}")
    print(f"Warning       : {counts['WARNING']}")
    print(f"Unhealthy     : {counts['UNHEALTHY']}")
    print("=" * 60)

    failures = [
        item for item in results if item.overall_status != "HEALTHY"
    ]
    if failures:
        print("\nRouters requiring review:")
        for item in failures:
            reason = item.error or (
                f"interface={item.interface_status}, "
                f"bgp={item.bgp_status}, cpu={item.cpu_status}, "
                f"memory={item.memory_status}, routes={item.route_status}"
            )
            print(f"  {item.name:<24} {item.overall_status:<10} {reason}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run read-only health checks across a router fleet."
    )
    parser.add_argument(
        "--inventory",
        type=Path,
        default=Path("inventory.csv"),
        help="CSV inventory path (default: inventory.csv)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=20,
        help="Maximum simultaneous router checks (default: 20)",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=1,
        help="Retries for temporary connection failures (default: 1)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Connection and command timeout in seconds (default: 30)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("output"),
        help="Report and log directory (default: output)",
    )
    parser.add_argument(
        "--create-sample",
        action="store_true",
        help="Create a sample inventory and exit.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable detailed logging.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.create_sample:
        if args.inventory.exists():
            print(f"Refusing to overwrite existing file: {args.inventory}")
            return 1
        create_sample_inventory(args.inventory)
        print(f"Sample inventory created: {args.inventory.resolve()}")
        return 0

    if not 1 <= args.workers <= 200:
        print("--workers must be between 1 and 200.", file=sys.stderr)
        return 2
    if not 0 <= args.retries <= 5:
        print("--retries must be between 0 and 5.", file=sys.stderr)
        return 2
    if not 5 <= args.timeout <= 300:
        print("--timeout must be between 5 and 300 seconds.", file=sys.stderr)
        return 2
    if not args.inventory.exists():
        print(
            f"Inventory not found: {args.inventory}\n"
            f"Create one with: python {Path(__file__).name} --create-sample",
            file=sys.stderr,
        )
        return 2

    log_path = configure_logging(args.output_dir, args.verbose)

    try:
        routers = load_inventory(args.inventory)
    except (OSError, ValueError) as exc:
        logging.error("Inventory error: %s", exc)
        return 2

    default_username = os.getenv("ROUTER_USERNAME", "").strip()
    if not default_username and any(not router.username for router in routers):
        default_username = input("Default router username: ").strip()

    password = os.getenv("ROUTER_PASSWORD")
    if password is None:
        password = getpass.getpass("Router password: ")

    secret = os.getenv("ROUTER_SECRET")
    if secret is None:
        secret = getpass.getpass(
            "Enable secret (press Enter if not required): "
        )

    print(
        f"\nChecking {len(routers)} routers with "
        f"up to {args.workers} concurrent sessions.\n"
    )

    results: list[HealthResult] = []

    with ThreadPoolExecutor(
        max_workers=args.workers,
        thread_name_prefix="router-check",
    ) as executor:
        future_map = {
            executor.submit(
                check_router,
                router,
                default_username,
                password,
                secret,
                args.retries,
                args.timeout,
            ): router
            for router in routers
        }

        completed = 0
        for future in as_completed(future_map):
            router = future_map[future]
            try:
                result = future.result()
            except Exception as exc:
                logging.exception(
                    "%s: worker crashed unexpectedly", router.name
                )
                result = failed_result(
                    router,
                    time.monotonic(),
                    f"Worker failure: {exc}",
                )

            results.append(result)
            completed += 1
            print(
                f"[{completed:>4}/{len(routers)}] "
                f"{result.name:<24} {result.overall_status}"
            )

    results.sort(key=lambda item: item.name.lower())
    csv_path, json_path = save_reports(results, args.output_dir)

    print_summary(results)
    print(f"\nCSV report : {csv_path.resolve()}")
    print(f"JSON report: {json_path.resolve()}")
    print(f"Log file   : {log_path.resolve()}")

    return 1 if any(
        item.overall_status == "UNHEALTHY" for item in results
    ) else 0


if __name__ == "__main__":
    raise SystemExit(main())
