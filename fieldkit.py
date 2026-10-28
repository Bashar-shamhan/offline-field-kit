#!/usr/bin/env python3
"""Offline Field Kit v0.1 — local network documentation and port check.

Works fully offline. Uses only the Python standard library.
Sends no data to any server and collects no passwords or personal data.
Intended only for scanning your own machine / your own local network
(or a network you have explicit permission to scan).

Usage:
    python3 fieldkit.py [--output output]
"""
from __future__ import annotations

import argparse
import datetime
import ipaddress
import json
import platform
import socket
import subprocess
import sys
from pathlib import Path

COMMON_PORTS = {
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    53: "DNS",
    3306: "MySQL",
    5432: "PostgreSQL",
    8080: "HTTP-alt",
}
CONNECT_TIMEOUT = 0.6  # seconds, kept short to avoid burdening the network


def local_ip_and_subnet() -> tuple[str | None, str | None]:
    """Best-effort local IP / subnet detection without any external call."""
    try:
        # UDP "connect" does not send traffic; it only selects a local route.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))
            local_ip = s.getsockname()[0]
    except OSError:
        local_ip = None
    if not local_ip or local_ip.startswith("127."):
        # Fall back to hostname resolution (still local only).
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
        except OSError:
            local_ip = None
    subnet = None
    if local_ip and not local_ip.startswith("127."):
        try:
            # Assume a /24 when the real netmask is unavailable; labelled as such.
            subnet = str(ipaddress.ip_network(f"{local_ip}/24", strict=False))
        except ValueError:
            subnet = None
    return local_ip, subnet


def gateway() -> str | None:
    """Parse the default gateway from the OS routing table (local only)."""
    try:
        if platform.system() == "Windows":
            out = subprocess.run(
                ["route", "print", "0.0.0.0"],
                capture_output=True, text=True, timeout=5, check=False,
            ).stdout
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[0] == "0.0.0.0":
                    try:
                        ipaddress.ip_address(parts[2])
                        return parts[2]
                    except ValueError:
                        continue
            return None
        # Linux / macOS: `ip route` preferred, `netstat -rn` as fallback.
        for cmd in (["ip", "route", "show", "default"],
                    ["netstat", "-rn"]):
            try:
                out = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=5, check=False,
                ).stdout
            except (OSError, subprocess.TimeoutExpired):
                continue
            for line in out.splitlines():
                parts = line.split()
                if not parts:
                    continue
                if parts[0] == "default" and len(parts) >= 3:
                    candidate = parts[2]
                elif parts[0] == "0.0.0.0" and len(parts) >= 2:
                    candidate = parts[1]
                else:
                    continue
                try:
                    ipaddress.ip_address(candidate)
                    return candidate
                except ValueError:
                    continue
    except Exception:
        pass
    return None


def tcp_reachable(host: str, port: int = 80) -> bool:
    """One short TCP connect attempt. False on any failure (incl. no route)."""
    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT):
            return True
    except OSError:
        return False


def scan_ports(host: str) -> list[dict]:
    """Scan only COMMON_PORTS on one host; record open ports only."""
    open_ports = []
    for port, service in sorted(COMMON_PORTS.items()):
        try:
            with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT):
                open_ports.append({"port": port, "service": service})
        except OSError:
            pass
    return open_ports


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline Field Kit v0.1")
    parser.add_argument("--output", default="output",
                        help="Output directory (default: output)")
    args = parser.parse_args(argv)

    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    local_ip, subnet = local_ip_and_subnet()
    gw = gateway()

    connectivity = {
        "gateway": (tcp_reachable(gw, 80) if gw else None),
        "dns_8_8_8_8": tcp_reachable("8.8.8.8", 53),
    }
    targets = {"localhost": "127.0.0.1"}
    if gw:
        targets["gateway"] = gw
    port_results = {name: scan_ports(host) for name, host in targets.items()}

    report = {
        "tool": "Offline Field Kit",
        "version": "0.1",
        "generated_at_utc": timestamp,
        "hostname": socket.gethostname(),
        "local_ip": local_ip,
        "subnet_assumed_slash24": subnet,
        "gateway": gw,
        "connectivity": connectivity,
        "open_ports": port_results,
        "notes": [
            "Scan limited to common ports with short timeouts.",
            "Subnet is shown as /24 when the real netmask is unavailable.",
            "connectivity.gateway is null when no gateway was detected.",
            "No data was sent to any server by this tool; checks are local "
            "TCP connects only.",
        ],
    }

    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    def fmt_bool(value: bool | None) -> str:
        return "reachable" if value is True else (
            "unreachable" if value is False else "not detected")

    lines = [
        "# Offline Field Kit Report — v0.1",
        "",
        f"- Generated (UTC): {timestamp}",
        f"- Hostname: {report['hostname']}",
        f"- Local IP: {local_ip or 'not detected'}",
        f"- Subnet (assumed /24): {subnet or 'not detected'}",
        f"- Gateway: {gw or 'not detected'}",
        "",
        "## Connectivity",
        "",
        f"- Gateway: {fmt_bool(connectivity['gateway'])}",
        f"- DNS 8.8.8.8 (port 53): {fmt_bool(connectivity['dns_8_8_8_8'])}",
        "",
        "## Open ports (common ports only)",
        "",
    ]
    for name, ports in port_results.items():
        host = targets[name]
        if ports:
            lines.append(f"### {name} ({host})")
            lines.append("")
            for p in ports:
                lines.append(f"- {p['port']} ({p['service']}): open")
            lines.append("")
        else:
            lines.append(f"- {name} ({host}): no common ports open")
            lines.append("")
    lines += [
        "## Notes",
        "",
        "- Scan limited to common ports with short timeouts.",
        "- No data was sent to any server; no passwords or personal data collected.",
        "",
    ]
    (out_dir / "report.md").write_text("\n".join(lines), encoding="utf-8")

    print(f"Local IP: {local_ip or 'not detected'}")
    print(f"Gateway: {gw or 'not detected'}")
    print(f"Connectivity: gateway={fmt_bool(connectivity['gateway'])}, "
          f"dns_8.8.8.8={fmt_bool(connectivity['dns_8_8_8_8'])}")
    for name, ports in port_results.items():
        opened = ", ".join(str(p['port']) for p in ports) or "none"
        print(f"Open ports on {name} ({targets[name]}): {opened}")
    print(f"Reports written to {out_dir}/report.md and {out_dir}/report.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
