#!/usr/bin/env python3
"""Offline Field Kit v0.2 — local network documentation and port check.

v0.2 adds a network device list read passively from the local ARP
cache only (no ARP spoofing, no network-wide scan, no external lookup).

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
import re
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


_MAC_RE = re.compile(r"(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}")
_IP_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]*::[0-9a-fA-F:]+")
_STATE_WORDS = {
    "REACHABLE", "STALE", "DELAY", "PROBE", "FAILED", "INCOMPLETE",
    "PERMANENT", "DYNAMIC", "STATIC",
}


def _normalize_mac(raw: str) -> str:
    """Canonical lowercase colon-separated MAC (Windows uses hyphens)."""
    return raw.replace("-", ":").lower()


def _ip_sort_key(ip: str) -> tuple:
    try:
        addr = ipaddress.ip_address(ip)
        return (0, int(addr))
    except ValueError:
        return (1, ip)


def parse_arp_text(text: str) -> list[dict]:
    """Parse ARP cache text from Linux / Windows / macOS formats.

    Returns entries of {"ip", "mac", "state"} where mac/state are None
    when the format carries no such value. Entries are deduplicated by
    IP (preferring an entry that carries a MAC) and sorted by IP.
    Pure function: safe to unit-test with sample outputs.
    """
    by_ip: dict[str, dict] = {}

    def add(ip: str, mac: str | None, state: str | None) -> None:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return
        existing = by_ip.get(ip)
        if existing is None:
            by_ip[ip] = {"ip": ip, "mac": mac, "state": state}
        else:
            if existing["mac"] is None and mac is not None:
                existing["mac"] = mac
            if existing["state"] is None and state is not None:
                existing["state"] = state

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("Interface:", "Internet Address")):
            continue
        tokens = line.split()

        # Linux `ip neigh`: "192.168.1.1 dev eth0 lladdr aa:... REACHABLE"
        # or "192.168.1.10 dev eth0 FAILED" (no lladdr).
        if len(tokens) >= 3 and tokens[1] == "dev":
            mac = None
            state = None
            if "lladdr" in tokens:
                idx = tokens.index("lladdr")
                if idx + 1 < len(tokens):
                    mac = _normalize_mac(tokens[idx + 1])
                if idx + 2 < len(tokens):
                    state = tokens[idx + 2].upper()
            else:
                state = tokens[3].upper() if len(tokens) > 3 else None
            add(tokens[0], mac, state)
            continue

        # macOS / BSD `arp -a` and Linux `arp -a`:
        # "? (192.168.1.1) at aa:... [ether] on en0 ifscope"
        # "? (192.168.1.2) at (incomplete) on en0 ifscope"
        paren = re.search(r"\(([^)]+)\)\s+at\s+(\S+)", line)
        if paren:
            mac_raw = paren.group(2)
            mac = None if mac_raw == "(incomplete)" else (
                _normalize_mac(mac_raw) if _MAC_RE.fullmatch(mac_raw) else None)
            state = "incomplete" if mac_raw == "(incomplete)" else None
            add(paren.group(1), mac, state)
            continue

        # Windows `arp -a` table rows and Linux `arp -n` rows:
        # "  192.168.1.1           00-11-22-33-44-55     dynamic"
        # "192.168.1.1  ether  aa:...  C  eth0"  (C = complete flag)
        if len(tokens) >= 3:
            try:
                ipaddress.ip_address(tokens[0])
            except ValueError:
                continue
            mac = None
            state = None
            if _MAC_RE.fullmatch(tokens[1]):
                mac = _normalize_mac(tokens[1])
                state = tokens[2].lower() if tokens[2].lower() in (
                    "dynamic", "static") else tokens[2]
            elif tokens[1] == "ether" and len(tokens) >= 4:
                if _MAC_RE.fullmatch(tokens[2]):
                    mac = _normalize_mac(tokens[2])
                state = tokens[3] if len(tokens) > 3 else None
            elif tokens[1] == "(incomplete)":
                state = "incomplete"
            if mac is not None or state is not None or tokens[1] in (
                    "(incomplete)",):
                add(tokens[0], mac, state)
                continue

        # Generic fallback: an IP plus a MAC anywhere on the line, plus
        # a known state word if one appears.
        ip_match = _IP_RE.search(line)
        mac_match = _MAC_RE.search(line)
        if ip_match and mac_match:
            state = None
            for word in tokens:
                if word.upper() in _STATE_WORDS:
                    state = word.lower() if word.lower() in (
                        "dynamic", "static") else word.upper()
                    break
            add(ip_match.group(0), _normalize_mac(mac_match.group(0)), state)

    return sorted(by_ip.values(), key=lambda d: _ip_sort_key(d["ip"]))


def collect_arp_devices() -> tuple[list[dict], str | None]:
    """Read the local ARP cache passively; never sends ARP requests.

    Tries `ip neigh` first on non-Windows systems, then `arp -n` /
    `arp -a`. A missing command is skipped gracefully. Returns
    (devices, source_command) where source_command is None when no
    ARP command was available at all.
    """
    if platform.system() == "Windows":
        commands = [["arp", "-a"]]
    else:
        commands = [["ip", "neigh"], ["arp", "-n"], ["arp", "-a"]]
    for cmd in commands:
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=5, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if result.returncode != 0 and not result.stdout:
            continue
        return parse_arp_text(result.stdout), " ".join(cmd)
    return [], None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline Field Kit v0.2")
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
    arp_devices, arp_source = collect_arp_devices()

    report = {
        "tool": "Offline Field Kit",
        "version": "0.2",
        "generated_at_utc": timestamp,
        "hostname": socket.gethostname(),
        "local_ip": local_ip,
        "subnet_assumed_slash24": subnet,
        "gateway": gw,
        "connectivity": connectivity,
        "open_ports": port_results,
        "arp_devices": arp_devices,
        "arp_source": arp_source,
        "notes": [
            "Scan limited to common ports with short timeouts.",
            "Subnet is shown as /24 when the real netmask is unavailable.",
            "connectivity.gateway is null when no gateway was detected.",
            "No data was sent to any server by this tool; checks are local "
            "TCP connects only.",
            "arp_devices is read passively from the local ARP cache only; "
            "no ARP spoofing, no network-wide scan, no external lookup.",
            "arp_source is null when no ARP command was available.",
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
        "# Offline Field Kit Report — v0.2",
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
        "## Network devices (ARP table)",
        "",
    ]
    if arp_source:
        lines.append(f"- Source: `{arp_source}` (local ARP cache, passive read)")
        lines.append("")
    if arp_devices:
        lines += [
            "| IP | MAC | State/Type |",
            "| --- | --- | --- |",
        ]
        for d in arp_devices:
            lines.append(
                f"| {d['ip']} | {d['mac'] or '—'} | {d['state'] or '—'} |")
        lines.append("")
    else:
        lines.append("- no devices found in ARP table")
        if arp_source is None:
            lines.append("- Note: no ARP command was available on this system.")
        lines.append("")
    lines += [
        "## Notes",
        "",
        "- Scan limited to common ports with short timeouts.",
        "- Device list is read passively from the local ARP cache only.",
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
    if arp_devices:
        print(f"ARP devices ({len(arp_devices)}): "
              + ", ".join(d["ip"] for d in arp_devices))
    else:
        print("ARP devices: no devices found in ARP table")
    print(f"Reports written to {out_dir}/report.md and {out_dir}/report.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
