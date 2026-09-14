"""
EndpointRadar scanning engine.

Wraps the host checks in ``os_check`` and adds network discovery plus
agentless remote collection over WinRM. It provides functions that:
- Run a full posture scan on the local system
- Discover and port-scan devices on a subnet without credentials
- Stage and run the scanner on a remote Windows host over WinRM
- Normalize every result into one standard record shape
- Save and load multi-system results.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import os
import re
import socket
import subprocess
import time
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import installed_apps, os_check, risk

PACKAGE_NAME = __package__ or "endpointradar"
PACKAGE_DIR = Path(__file__).resolve().parent

# Results land in the directory the tool is run from unless this is overridden.
DATA_DIR = Path(os.environ.get("ENDPOINTRADAR_DATA_DIR") or ".")
SCAN_RESULTS_FILE = DATA_DIR / "scan_results.json"
UNAUTH_SCAN_RESULTS_FILE = DATA_DIR / "unauth_scan_results.json"

# Only stdlib-dependent modules are staged, so the remote host needs no pip packages.
REMOTE_SCAN_FILES = ["__init__.py", "os_check.py", "installed_apps.py", "risk.py", "scanner.py"]
REMOTE_SCAN_DIR = r"C:\temp\endpointradar_remote_scan"
REMOTE_SCAN_PACKAGE_DIR = REMOTE_SCAN_DIR + "\\" + PACKAGE_NAME
REMOTE_SCAN_RESULT_FILE = REMOTE_SCAN_DIR + r"\scan_result.json"
REMOTE_SCAN_RUNNER_FILE = REMOTE_SCAN_DIR + r"\_remote_runner.py"
REMOTE_SCAN_SENTINEL = "SCAN_COMPLETE"
REMOTE_SCAN_STAGE_CHUNK_SIZE = 400
REMOTE_SCAN_RESULT_MAX_BYTES = 5 * 1024 * 1024
LIMITED_VISIBILITY_LABEL = "Unauthenticated (Limited Visibility)"
LIMITED_VISIBILITY_NOTE = "Limited Data - Authentication Required for Deep Scan"

UNAUTHENTICATED_PORT_MAP: dict[int, dict[str, Any]] = {
    22: {
        "service": "SSH",
        "severity": "MEDIUM",
        "weight": 3,
        "reason": "SSH is reachable from the network and exposes a remote administration surface.",
        "fix": "Restrict SSH to trusted administrator systems and disable it where it is not required.",
    },
    80: {
        "service": "HTTP",
        "severity": "LOW",
        "weight": 2,
        "reason": "HTTP is exposed and may reveal a management page, application, or banner information.",
        "fix": "Confirm the web service is required, patch it regularly, and limit access if it is administrative.",
    },
    443: {
        "service": "HTTPS",
        "severity": "LOW",
        "weight": 2,
        "reason": "HTTPS is exposed and may provide a reachable application or management interface.",
        "fix": "Confirm the HTTPS service is required, keep it patched, and restrict access if it is administrative.",
    },
    445: {
        "service": "SMB",
        "severity": "HIGH",
        "weight": 8,
        "reason": "SMB is exposed and can increase the risk of wormable attacks and lateral movement.",
        "fix": "Disable SMB where possible, or restrict it to trusted networks and harden file-sharing access.",
    },
    3389: {
        "service": "RDP",
        "severity": "MEDIUM",
        "weight": 5,
        "reason": "RDP is exposed and can attract brute-force attempts or remote-access abuse.",
        "fix": "Disable RDP if it is not needed, or place it behind VPN, allow-lists, and strong authentication controls.",
    },
}

KNOWN_OUI_VENDORS = {
    "F0:18:98": "Apple",
    "3C:22:FB": "Apple",
    "A4:B1:C1": "Apple",
    "28:CF:DA": "Apple",
    "D8:1D:72": "Apple",
    "FC:C2:DE": "Samsung",
    "58:CB:52": "Samsung",
    "64:77:91": "Samsung",
    "F8:A9:D0": "Samsung",
    "D0:17:C2": "Samsung",
    "84:C7:EA": "Google",
    "D4:3A:2E": "Google",
    "FC:FC:48": "Google",
    "64:09:80": "Xiaomi",
    "28:6C:07": "Xiaomi",
    "7C:1D:D9": "Xiaomi",
    "48:46:FB": "Huawei",
    "04:F1:3E": "Huawei",
    "E0:19:1D": "Huawei",
    "08:EA:44": "OnePlus",
    "9C:28:BF": "OnePlus",
    "2C:BE:08": "Oppo",
    "D4:7E:35": "Vivo",
    "B4:CE:F6": "Motorola",
    "80:8D:B7": "Realme",
}

WINDOWS_OS_HINTS = ("windows",)
MOBILE_OS_HINTS = ("android", "iphone", "ios", "ipad", "mobile")
WINDOWS_HOSTNAME_HINTS = ("desktop", "laptop", "win-", "win_", "surface", "thinkpad", "workstation")
MOBILE_HOSTNAME_HINTS = (
    "iphone",
    "ipad",
    "android",
    "mobile",
    "phone",
    "samsung",
    "galaxy",
    "pixel",
    "oneplus",
    "oppo",
    "vivo",
    "realme",
    "redmi",
    "xiaomi",
    "huawei",
    "honor",
    "motorola",
)
MOBILE_VENDOR_HINTS = ("samsung", "google", "xiaomi", "huawei", "honor", "oneplus", "oppo", "vivo", "realme", "motorola")
APPLE_MOBILE_HINTS = ("iphone", "ipad", "ios")


class RemoteScanError(RuntimeError):
    def __init__(self, message: str, code: str = "connection_failed") -> None:
        super().__init__(message)
        self.code = code


RemoteProgressCallback = Callable[[str, float, int | None], None]


def _run_command(command: list[str], timeout_s: int = 30) -> tuple[int, str, str]:
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
        return completed.returncode, (completed.stdout or "").strip(), (completed.stderr or "").strip()
    except Exception as e:
        return 1, "", str(e)


def _make_json_safe(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {k: _make_json_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_make_json_safe(v) for v in value]
    return value


def _contains_any(text: str, hints: Iterable[str]) -> bool:
    haystack = str(text or "").lower()
    return any(hint in haystack for hint in hints)


def normalize_mac_address(value: Any) -> str:
    raw = re.sub(r"[^0-9A-Fa-f]", "", str(value or ""))
    if len(raw) != 12:
        return ""
    return ":".join(raw[index : index + 2].upper() for index in range(0, 12, 2))


def lookup_mac_vendor(mac_address: Any) -> str:
    normalized = normalize_mac_address(mac_address)
    if not normalized:
        return ""
    return KNOWN_OUI_VENDORS.get(normalized[:8], "")


def _read_arp_table() -> dict[str, str]:
    code, stdout, _stderr = _run_command(["arp", "-a"], timeout_s=10)
    if code != 0 or not stdout:
        return {}

    arp_entries: dict[str, str] = {}
    for line in stdout.splitlines():
        match = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9A-Fa-f:-]{11,17})\s+(dynamic|static)", line, re.IGNORECASE)
        if not match:
            continue
        ip_address = str(match.group(1) or "").strip()
        mac_address = normalize_mac_address(match.group(2) or "")
        if ip_address and mac_address:
            arp_entries[ip_address] = mac_address
    return arp_entries


def describe_device_type(device_type: Any) -> str:
    normalized = str(device_type or "Unknown").strip().title()
    if normalized == "Windows":
        return "Windows PC"
    if normalized == "Mobile":
        return "Mobile Device"
    return "Unknown Device"


def enrich_device_metadata(record: dict[str, Any] | None) -> dict[str, Any]:
    data = dict(record or {})
    system_info = data.get("system_info") or {}
    hostname = str(data.get("hostname") or system_info.get("hostname") or "").strip()
    mac_address = normalize_mac_address(
        data.get("mac_address")
        or data.get("mac")
        or system_info.get("mac_address")
        or system_info.get("mac")
        or ""
    )
    mac_vendor = str(data.get("mac_vendor") or lookup_mac_vendor(mac_address) or "").strip()
    os_hints = " ".join(
        str(system_info.get(field) or "").strip()
        for field in ("os_name", "os_release", "os_version", "platform")
    ).lower()
    hostname_hints = hostname.lower()
    existing_type = str(data.get("device_type") or "").strip().title()

    device_type = "Unknown"
    reason = "No strong OS, hostname, or MAC-vendor indicators were available."

    if _contains_any(os_hints, WINDOWS_OS_HINTS):
        device_type = "Windows"
        reason = "OS hints report Windows."
    elif _contains_any(os_hints, MOBILE_OS_HINTS):
        device_type = "Mobile"
        reason = "OS hints indicate a mobile operating system."
    elif _contains_any(hostname_hints, MOBILE_HOSTNAME_HINTS):
        device_type = "Mobile"
        reason = f"Hostname '{hostname}' matches a mobile-device naming pattern."
    elif _contains_any(hostname_hints, WINDOWS_HOSTNAME_HINTS):
        device_type = "Windows"
        reason = f"Hostname '{hostname}' matches a Windows-PC naming pattern."
    elif mac_vendor:
        vendor_hints = mac_vendor.lower()
        if _contains_any(vendor_hints, MOBILE_VENDOR_HINTS):
            device_type = "Mobile"
            reason = f"MAC vendor lookup matched {mac_vendor}, which is commonly used for mobile devices."
        elif "apple" in vendor_hints:
            if _contains_any(hostname_hints, APPLE_MOBILE_HINTS):
                device_type = "Mobile"
                reason = "Apple MAC vendor plus hostname hints indicate a mobile Apple device."
            else:
                device_type = "Unknown"
                reason = "Apple MAC vendor detected, but the device could be either a Mac or an iPhone/iPad."

    if device_type == "Unknown" and existing_type in {"Windows", "Mobile"}:
        device_type = existing_type
        reason = str(data.get("device_type_reason") or reason)

    data["device_type"] = device_type
    data["device_type_label"] = describe_device_type(device_type)
    data["scan_supported"] = device_type != "Mobile"
    data["device_type_reason"] = reason
    if mac_address:
        data["mac_address"] = mac_address
    if mac_vendor:
        data["mac_vendor"] = mac_vendor
    return data


def get_device_id(scan: dict[str, Any]) -> str:
    return str(
        scan.get("device_id")
        or scan.get("target_ip")
        or (scan.get("system_info") or {}).get("ip_address")
        or scan.get("hostname")
        or "Unknown"
    )


def upsert_scan_result(results: list[dict[str, Any]], new_scan: dict[str, Any]) -> list[dict[str, Any]]:
    device_id = get_device_id(new_scan).lower()
    for idx, item in enumerate(results):
        if get_device_id(item).lower() == device_id:
            results[idx] = new_scan
            return results
    results.append(new_scan)
    return results


def guess_default_subnet() -> str:
    try:
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        parts = ip.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    except Exception:
        pass
    return "192.168.1.0/24"


def _iter_subnet_hosts(subnet: str) -> Iterable[str]:
    text = str(subnet or "").strip().replace("–", "-")
    if not text:
        raise ValueError("Subnet is required.")

    if "/" in text:
        network = ipaddress.ip_network(text, strict=False)
        for host in network.hosts():
            yield str(host)
        return

    range_match = re.fullmatch(r"(\d+\.\d+\.\d+)\.(\d+)-(\d+)", text)
    if range_match:
        prefix = range_match.group(1)
        start = int(range_match.group(2))
        end = int(range_match.group(3))
        for octet in range(min(start, end), max(start, end) + 1):
            yield f"{prefix}.{octet}"
        return

    triple_match = re.fullmatch(r"(\d+\.\d+\.\d+)", text)
    if triple_match:
        prefix = triple_match.group(1)
        for octet in range(1, 255):
            yield f"{prefix}.{octet}"
        return

    try:
        ipaddress.ip_address(text)
        yield text
        return
    except ValueError as exc:
        raise ValueError("Use a subnet like 192.168.1.0/24 or 192.168.1.1-254.") from exc


def _resolve_hostname(ip_address: str) -> str:
    try:
        host, _aliases, _ips = socket.gethostbyaddr(ip_address)
        return host
    except Exception:
        return _resolve_netbios_hostname(ip_address)


def _resolve_netbios_hostname(ip_address: str) -> str:
    code, stdout, _stderr = _run_command(["nbtstat", "-A", ip_address], timeout_s=5)
    if code != 0 or not stdout:
        return ""

    for line in stdout.splitlines():
        text = line.strip()
        match = re.match(r"([A-Za-z0-9_. -]+)\s+<00>\s+UNIQUE", text, re.IGNORECASE)
        if not match:
            continue
        hostname = str(match.group(1) or "").strip()
        if hostname and hostname.lower() != "is":
            return hostname
    return ""


def _tcp_port_open(ip_address: str, port: int, timeout_s: float = 0.35) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout_s)
            return sock.connect_ex((ip_address, int(port))) == 0
    except Exception:
        return False


def _scan_common_ports(ip_address: str, timeout_s: float = 0.35) -> list[dict[str, Any]]:
    open_ports: list[dict[str, Any]] = []
    for port in sorted(UNAUTHENTICATED_PORT_MAP):
        if not _tcp_port_open(ip_address, port, timeout_s=timeout_s):
            continue
        port_meta = UNAUTHENTICATED_PORT_MAP[port]
        open_ports.append(
            {
                "port": port,
                "service": str(port_meta.get("service") or f"TCP/{port}"),
                "severity": str(port_meta.get("severity") or "LOW").upper(),
                "reason": str(port_meta.get("reason") or "").strip(),
                "fix": str(port_meta.get("fix") or "").strip(),
            }
        )
    return open_ports


def _risk_reason_title(service: str, port: int) -> str:
    if port == 445:
        return "SMB exposure detected (Port 445)"
    if port == 3389:
        return "RDP exposure detected (Port 3389)"
    return f"{service} exposure detected (Port {port})"


def _calculate_unauthenticated_risk(open_ports: list[dict[str, Any]]) -> tuple[int, str, list[str]]:
    open_port_numbers = {int(item.get("port")) for item in open_ports if str(item.get("port") or "").isdigit()}
    score = 0
    reasons: list[str] = []

    for item in open_ports:
        port = int(item.get("port") or 0)
        score += int((UNAUTHENTICATED_PORT_MAP.get(port) or {}).get("weight") or 1)

    if 445 in open_port_numbers:
        reasons.append("SMB exposure on port 445 creates a high-risk lateral-movement path.")
    if 3389 in open_port_numbers:
        reasons.append("RDP exposure on port 3389 presents a remote-access attack surface.")

    open_count = len(open_ports)
    if open_count >= 3:
        score += 3
        reasons.append("Multiple externally reachable services increase the exposed attack surface.")
    elif open_count >= 2:
        score += 1
        reasons.append("More than one management or application port is reachable without authentication.")

    if score >= 7 or 445 in open_port_numbers or (3389 in open_port_numbers and open_count >= 2):
        level = "HIGH"
    elif score >= 4 or 3389 in open_port_numbers or open_count >= 2:
        level = "MEDIUM"
    else:
        level = "LOW"

    if not reasons:
        reasons.append("Only a limited number of monitored ports were exposed during the unauthenticated scan.")
    return score, level, reasons


def _refine_device_type_with_exposure(record: dict[str, Any], open_ports: list[dict[str, Any]]) -> dict[str, Any]:
    enriched = enrich_device_metadata(record)
    if str(enriched.get("device_type") or "").strip().title() in {"Windows", "Mobile"}:
        return enriched

    open_port_numbers = {int(item.get("port")) for item in open_ports if str(item.get("port") or "").isdigit()}
    if 445 in open_port_numbers or 3389 in open_port_numbers:
        enriched["device_type"] = "Windows"
        enriched["device_type_label"] = describe_device_type("Windows")
        enriched["scan_supported"] = True
        enriched["device_type_reason"] = "Port exposure patterns (SMB or RDP) strongly suggest a Windows endpoint."
    elif any(str(item.get("service") or "").upper() in {"HTTP", "HTTPS"} for item in open_ports):
        mac_vendor = str(enriched.get("mac_vendor") or "").lower()
        hostname = str(enriched.get("hostname") or "").lower()
        if _contains_any(mac_vendor, MOBILE_VENDOR_HINTS) or _contains_any(hostname, MOBILE_HOSTNAME_HINTS):
            enriched["device_type"] = "Mobile"
            enriched["device_type_label"] = describe_device_type("Mobile")
            enriched["scan_supported"] = False
            enriched["device_type_reason"] = "Vendor or hostname hints plus web exposure suggest a mobile device."
    return enriched


def _build_unauthenticated_vulnerabilities(open_ports: list[dict[str, Any]], risk_notes: list[str]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for item in open_ports:
        port = int(item.get("port") or 0)
        service = str(item.get("service") or f"TCP/{port}")
        severity = str(item.get("severity") or "LOW").upper()
        findings.append(
            {
                "title": _risk_reason_title(service, port),
                "severity": severity,
                "description": str(item.get("reason") or "").strip() or f"{service} is reachable from the network.",
                "fix": str(item.get("fix") or "").strip(),
            }
        )

    if len(open_ports) >= 2:
        findings.append(
            {
                "title": "Multiple exposed services detected",
                "severity": "MEDIUM" if len(open_ports) < 4 else "HIGH",
                "description": "Several monitored services are reachable without authentication, increasing the attack surface.",
                "fix": "Review which services must remain exposed and reduce unnecessary network reachability.",
            }
        )

    for note in risk_notes:
        if note.lower().startswith("multiple externally") or note.lower().startswith("more than one"):
            continue
        findings.append(
            {
                "title": note,
                "severity": "HIGH" if "high-risk" in note.lower() else "MEDIUM",
                "description": note,
                "fix": "Restrict exposed services to trusted networks and follow least-exposure hardening practices.",
            }
        )
    return findings


def _build_unauthenticated_scan_record(device: dict[str, Any], open_ports: list[dict[str, Any]]) -> dict[str, Any]:
    ip_address = str(device.get("ip") or "").strip()
    hostname = str(device.get("hostname") or ip_address or "Unknown").strip() or ip_address or "Unknown"
    enriched_device = _refine_device_type_with_exposure(
        {
            "hostname": hostname,
            "device_id": ip_address or hostname,
            "target_ip": ip_address,
            "status": device.get("status") or "Online",
            "online": bool(device.get("online")),
            "mac_address": device.get("mac_address") or "",
            "mac_vendor": device.get("mac_vendor") or "",
            "device_type": device.get("device_type") or "Unknown",
            "device_type_reason": device.get("device_type_reason") or "",
            "system_info": {
                "hostname": hostname,
                "ip_address": ip_address,
            },
        },
        open_ports,
    )
    risk_score, risk_level, risk_notes = _calculate_unauthenticated_risk(open_ports)
    vulnerabilities = _build_unauthenticated_vulnerabilities(open_ports, risk_notes)

    risky_open = [
        {
            "port": int(item.get("port") or 0),
            "severity": str(item.get("severity") or "LOW").upper(),
            "reason": str(item.get("reason") or "").strip(),
            "service": str(item.get("service") or ""),
        }
        for item in open_ports
    ]
    service_breakdown: dict[str, int] = {}
    for item in open_ports:
        service_name = str(item.get("service") or "Unknown").strip() or "Unknown"
        service_breakdown[service_name] = service_breakdown.get(service_name, 0) + 1

    scan_out = {
        "hostname": hostname,
        "device_id": ip_address or hostname,
        "target_ip": ip_address or hostname,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "device_type": str(enriched_device.get("device_type") or "Unknown"),
        "device_type_label": str(enriched_device.get("device_type_label") or describe_device_type(enriched_device.get("device_type"))),
        "scan_supported": bool(enriched_device.get("scan_supported", True)),
        "device_type_reason": str(enriched_device.get("device_type_reason") or ""),
        "mac_address": str(enriched_device.get("mac_address") or ""),
        "mac_vendor": str(enriched_device.get("mac_vendor") or ""),
        "scan_mode": "unauthenticated",
        "scan_type": LIMITED_VISIBILITY_LABEL,
        "connection_status": "Unauthenticated Scan",
        "last_scan_at": datetime.now().astimezone().isoformat(),
        "vulnerabilities": vulnerabilities,
        "system_info": {
            "hostname": hostname,
            "ip_address": ip_address,
        },
        "antivirus": {"visibility": "limited"},
        "patches": {"visibility": "limited"},
        "firewall": {"profiles": {}, "visibility": "limited"},
        "open_ports": {
            "method": "TCP connect scan",
            "scanned_ports": sorted(UNAUTHENTICATED_PORT_MAP),
            "listening_ports": [int(item.get("port") or 0) for item in open_ports],
            "risky_open": risky_open,
            "open_count": len(open_ports),
            "error": None,
        },
        "services": {"highlighted": [], "visibility": "limited"},
        "third_party_software": {"risky_apps": [], "visibility": "limited"},
        "installed_apps": [],
        "risky_apps": [],
        "limited_visibility": True,
        "limited_visibility_note": LIMITED_VISIBILITY_NOTE,
        "risk_notes": risk_notes,
        "external_exposure": {
            "scan_type": LIMITED_VISIBILITY_LABEL,
            "limited_visibility_note": LIMITED_VISIBILITY_NOTE,
            "ip_address": ip_address,
            "hostname": hostname,
            "device_type": str(enriched_device.get("device_type") or "Unknown"),
            "device_type_label": str(enriched_device.get("device_type_label") or describe_device_type(enriched_device.get("device_type"))),
            "device_type_reason": str(enriched_device.get("device_type_reason") or ""),
            "mac_address": str(enriched_device.get("mac_address") or ""),
            "mac_vendor": str(enriched_device.get("mac_vendor") or ""),
            "open_ports": open_ports,
            "open_port_count": len(open_ports),
            "service_breakdown": service_breakdown,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "risk_notes": risk_notes,
        },
    }
    return _make_json_safe(enrich_device_metadata(scan_out))


def _sort_key_for_ip(value: Any) -> tuple[int, ...]:
    text = str(value or "").strip()
    parts = text.split(".")
    if len(parts) == 4 and all(part.isdigit() for part in parts):
        return tuple(int(part) for part in parts)
    return (999, 999, 999, 999)


def _scan_online_device_unauthenticated(device: dict[str, Any]) -> dict[str, Any]:
    open_ports = _scan_common_ports(str(device.get("ip") or ""))
    return _build_unauthenticated_scan_record(device, open_ports)


def run_unauthenticated_scan(subnet: str, progress_callback: RemoteProgressCallback | None = None) -> list[dict[str, Any]]:
    discovered = discover_devices(subnet)
    online_devices = [device for device in discovered if bool(device.get("online"))]

    total = max(1, len(online_devices))
    _emit_remote_progress(
        progress_callback,
        f"ICMP discovery completed for {subnet}. Found {len(online_devices)} active device(s).",
        25,
        None,
    )

    if not online_devices:
        return []

    results: list[dict[str, Any]] = []
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=min(32, max(4, len(online_devices)))) as executor:
        future_map = {executor.submit(_scan_online_device_unauthenticated, device): device for device in online_devices}
        for index, future in enumerate(as_completed(future_map), start=1):
            device = future_map[future]
            try:
                results.append(future.result())
            except Exception:
                results.append(_build_unauthenticated_scan_record(device, []))

            elapsed = max(0.1, time.time() - start_time)
            remaining = total - index
            avg_seconds = elapsed / max(1, index)
            eta_seconds = int(round(avg_seconds * remaining)) if remaining else 0
            percent = 25 + ((index / total) * 75)
            _emit_remote_progress(
                progress_callback,
                f"Scanning exposed services on {device.get('ip') or device.get('hostname') or 'device'} ({index}/{total})...",
                percent,
                eta_seconds,
            )

    results.sort(key=lambda item: _sort_key_for_ip(item.get("target_ip")))
    return results


def discover_devices(subnet: str, timeout_ms: int = 400, max_workers: int = 32) -> list[dict[str, Any]]:
    hosts = list(_iter_subnet_hosts(subnet))

    def _probe(ip_address: str) -> dict[str, Any]:
        code, out, _err = _run_command(["ping", "-n", "1", "-w", str(timeout_ms), ip_address], timeout_s=3)
        online = bool(code == 0 and ("ttl=" in out.lower() or "reply from" in out.lower()))
        hostname = _resolve_hostname(ip_address) if online else ""
        return {
            "ip": ip_address,
            "hostname": hostname,
            "online": online,
            "status": "Online" if online else "Offline",
            "last_scan_at": None,
        }

    discovered: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {executor.submit(_probe, ip_address): ip_address for ip_address in hosts}
        for future in as_completed(future_map):
            try:
                discovered.append(future.result())
            except Exception:
                ip_address = future_map[future]
                discovered.append(
                    {
                        "ip": ip_address,
                        "hostname": "",
                        "online": False,
                        "status": "Offline",
                        "last_scan_at": None,
                    }
                )

    arp_entries = _read_arp_table()
    for index, item in enumerate(discovered):
        mac_address = arp_entries.get(str(item.get("ip") or "").strip(), "")
        discovered[index] = enrich_device_metadata(
            {
                **item,
                "mac_address": mac_address,
                "mac_vendor": lookup_mac_vendor(mac_address),
            }
        )

    discovered.sort(key=lambda item: tuple(int(part) for part in item["ip"].split(".")))
    return discovered


def _probe_winrm_endpoint(ip_address: str, timeout_s: int = 3) -> tuple[str, int]:
    scheme, port = "http", 5985
    try:
        with socket.create_connection((ip_address, port), timeout=timeout_s):
            return scheme, port
    except OSError:
        pass
    raise RemoteScanError(
        "WinRM is not reachable on http://<IP>:5985/wsman. Enable WinRM on the target PC and allow port 5985 through the firewall.",
        code="connection_failed",
    )


def _normalize_winrm_username(username: str) -> str:
    value = str(username or "").strip()
    if not value:
        return value
    if value.startswith("./"):
        return f".\\{value[2:]}"
    return value


def _looks_like_unqualified_local_username(username: str) -> bool:
    value = str(username or "").strip()
    return bool(value) and "\\" not in value and "/" not in value and "@" not in value


def _build_winrm_username_candidates(username: str) -> list[str]:
    normalized = _normalize_winrm_username(username)
    if not normalized:
        return []

    candidates: list[str] = []
    seen: set[str] = set()

    def _add(candidate: str) -> None:
        value = str(candidate or "").strip()
        if not value:
            return
        key = value.lower()
        if key in seen:
            return
        seen.add(key)
        candidates.append(value)

    _add(normalized)

    # Local Windows accounts are often entered as plain usernames in the GUI,
    # but pywinrm is more reliable when the username is explicitly scoped.
    if _looks_like_unqualified_local_username(normalized):
        _add(f".\\{normalized}")
    elif normalized.startswith(".\\"):
        _add(normalized[2:])

    return candidates


def _build_winrm_transport_attempts() -> list[str]:
    # Prefer NTLM to match typical PowerShell remoting behavior over HTTP.
    return ["ntlm", "basic"]


def _emit_remote_progress(
    progress_callback: RemoteProgressCallback | None,
    message: str,
    percent: float,
    eta_seconds: int | None = None,
) -> None:
    if progress_callback is None:
        return
    try:
        progress_callback(message, max(0.0, min(100.0, float(percent))), eta_seconds)
    except Exception:
        pass


def _escape_ps_single_quoted(value: str) -> str:
    return str(value or "").replace("'", "''")


def _chunk_text(value: str, chunk_size: int = REMOTE_SCAN_STAGE_CHUNK_SIZE) -> Iterable[str]:
    for index in range(0, len(value), chunk_size):
        yield value[index : index + chunk_size]


def _decode_winrm_result(result: Any) -> tuple[int, str, str]:
    stdout = result.std_out.decode("utf-8", errors="ignore") if getattr(result, "std_out", None) else ""
    stderr = result.std_err.decode("utf-8", errors="ignore") if getattr(result, "std_err", None) else ""
    return int(getattr(result, "status_code", 1)), stdout, stderr


def _run_remote_ps(session: Any, script: str) -> tuple[int, str, str]:
    return _decode_winrm_result(session.run_ps(script))


def _verify_winrm_session(session: Any) -> None:
    status_code, stdout, stderr = _run_remote_ps(session, "Write-Output 'WINRM_AUTH_OK'")
    if status_code != 0:
        message = stderr.strip() or stdout.strip() or "WinRM authentication probe failed."
        raise RemoteScanError(f"Connection Failed: {message}", code="connection_failed")


def _build_remote_runner_text() -> str:
    return (
        "import json\n"
        "import sys\n"
        "from pathlib import Path\n"
        "sys.path.insert(0, str(Path(__file__).resolve().parent))\n"
        f"from {PACKAGE_NAME} import scanner\n"
        f"output_path = Path(r'{REMOTE_SCAN_RESULT_FILE}')\n"
        "output_path.parent.mkdir(parents=True, exist_ok=True)\n"
        "result = scanner.run_single_scan()\n"
        "with output_path.open('w', encoding='utf-8') as handle:\n"
        "    json.dump(result, handle, ensure_ascii=False)\n"
        f"print('{REMOTE_SCAN_SENTINEL}')\n"
    )


def _build_remote_stage_payloads() -> list[dict[str, Any]]:
    payloads: list[dict[str, Any]] = []
    for filename in REMOTE_SCAN_FILES:
        # Resolve against the installed package, not the current working directory.
        local_path = PACKAGE_DIR / filename
        payloads.append(
            {
                "label": f"{PACKAGE_NAME}/{local_path.name}",
                "remote_path": REMOTE_SCAN_PACKAGE_DIR + "\\" + local_path.name,
                "data": local_path.read_bytes(),
            }
        )
    payloads.append(
        {
            "label": "_remote_runner.py",
            "remote_path": REMOTE_SCAN_RUNNER_FILE,
            "data": _build_remote_runner_text().encode("utf-8"),
        }
    )
    return payloads


def _estimate_stage_chunk_count(stage_payloads: list[dict[str, Any]]) -> int:
    total_chunks = 0
    for item in stage_payloads:
        payload_length = len(base64.b64encode(bytes(item["data"])))
        total_chunks += max(1, (payload_length + REMOTE_SCAN_STAGE_CHUNK_SIZE - 1) // REMOTE_SCAN_STAGE_CHUNK_SIZE)
    return max(1, total_chunks)


def _emit_stage_upload_progress(
    progress_callback: RemoteProgressCallback | None,
    progress_state: dict[str, Any],
    label: str,
) -> None:
    total_chunks = max(1, int(progress_state.get("total_chunks") or 1))
    uploaded_chunks = max(0, int(progress_state.get("uploaded_chunks") or 0))
    started_at = float(progress_state.get("started_at") or time.monotonic())
    elapsed = max(0.1, time.monotonic() - started_at)
    default_chunk_time = float(progress_state.get("default_chunk_time") or 0.3)
    avg_chunk_time = (elapsed / uploaded_chunks) if uploaded_chunks > 0 else default_chunk_time
    remaining_chunks = max(0, total_chunks - uploaded_chunks)
    eta_seconds = int(round((remaining_chunks * avg_chunk_time) + float(progress_state.get("post_stage_eta") or 18.0)))
    percent = 10.0 + (uploaded_chunks / total_chunks) * 50.0
    current_file_index = max(1, int(progress_state.get("current_file_index") or 1))
    total_files = max(1, int(progress_state.get("total_files") or 1))
    _emit_remote_progress(
        progress_callback,
        f"Uploading file {current_file_index}/{total_files}: {label}",
        percent,
        eta_seconds,
    )


def _ensure_remote_scan_dir(session: Any) -> None:
    script = (
        "$ErrorActionPreference = 'Stop'\n"
        f"$root = '{_escape_ps_single_quoted(REMOTE_SCAN_DIR)}'\n"
        f"$pkg = '{_escape_ps_single_quoted(REMOTE_SCAN_PACKAGE_DIR)}'\n"
        "New-Item -ItemType Directory -Force -Path $root | Out-Null\n"
        "New-Item -ItemType Directory -Force -Path $pkg | Out-Null\n"
    )
    status_code, stdout, stderr = _run_remote_ps(session, script)
    if status_code != 0:
        message = stderr.strip() or stdout.strip() or "Failed to create remote scan directory."
        raise RemoteScanError(message, code="execution_error")


def _stage_remote_bytes(
    session: Any,
    data: bytes,
    remote_path: str,
    label: str,
    progress_callback: RemoteProgressCallback | None = None,
    progress_state: dict[str, Any] | None = None,
) -> None:
    remote_temp_path = remote_path + ".b64"
    escaped_remote_path = _escape_ps_single_quoted(remote_path)
    escaped_temp_path = _escape_ps_single_quoted(remote_temp_path)
    payload = base64.b64encode(data).decode("ascii")

    init_script = (
        "$ErrorActionPreference = 'Stop'\n"
        f"if (Test-Path -LiteralPath '{escaped_temp_path}') {{ Remove-Item -LiteralPath '{escaped_temp_path}' -Force }}\n"
        f"if (Test-Path -LiteralPath '{escaped_remote_path}') {{ Remove-Item -LiteralPath '{escaped_remote_path}' -Force }}\n"
    )
    status_code, stdout, stderr = _run_remote_ps(session, init_script)
    if status_code != 0:
        message = stderr.strip() or stdout.strip() or f"Failed to initialize upload for {label}."
        raise RemoteScanError(message, code="execution_error")

    for chunk_index, chunk in enumerate(_chunk_text(payload), start=1):
        append_script = (
            "$ErrorActionPreference = 'Stop'\n"
            f"[System.IO.File]::AppendAllText('{escaped_temp_path}', '{chunk}')\n"
        )
        status_code, stdout, stderr = _run_remote_ps(session, append_script)
        if status_code != 0:
            message = stderr.strip() or stdout.strip() or f"Failed uploading chunk {chunk_index} for {label}."
            raise RemoteScanError(message, code="execution_error")
        if progress_state is not None:
            progress_state["uploaded_chunks"] = int(progress_state.get("uploaded_chunks") or 0) + 1
            _emit_stage_upload_progress(progress_callback, progress_state, label)

    finalize_script = (
        "$ErrorActionPreference = 'Stop'\n"
        f"if (-not (Test-Path -LiteralPath '{escaped_temp_path}')) {{ throw 'UPLOAD_MISSING' }}\n"
        f"$base64 = [System.IO.File]::ReadAllText('{escaped_temp_path}')\n"
        "$bytes = [Convert]::FromBase64String($base64)\n"
        f"[System.IO.File]::WriteAllBytes('{escaped_remote_path}', $bytes)\n"
        f"Remove-Item -LiteralPath '{escaped_temp_path}' -Force\n"
    )
    status_code, stdout, stderr = _run_remote_ps(session, finalize_script)
    if status_code != 0:
        message = stderr.strip() or stdout.strip() or f"Failed to finalize upload for {label}."
        raise RemoteScanError(message, code="execution_error")


def _verify_remote_file_exists(session: Any, remote_path: str, label: str) -> None:
    escaped_remote_path = _escape_ps_single_quoted(remote_path)
    script = (
        "$ErrorActionPreference = 'Stop'\n"
        f"if (-not (Test-Path -LiteralPath '{escaped_remote_path}')) {{ throw 'REMOTE_FILE_NOT_FOUND' }}\n"
        f"(Get-Item -LiteralPath '{escaped_remote_path}').Length\n"
    )
    status_code, stdout, stderr = _run_remote_ps(session, script)
    if status_code != 0:
        detail = stderr.strip() or stdout.strip()
        message = f"Remote script transfer failed: {label}"
        raise RemoteScanError(f"{message} ({detail})" if detail else message, code="execution_error")
    try:
        size = int(str(stdout).strip().splitlines()[-1])
    except Exception:
        raise RemoteScanError(f"Remote script transfer failed: {label}", code="execution_error")
    if size <= 0:
        raise RemoteScanError(f"Remote script transfer failed: {label}", code="execution_error")


def _stage_remote_scanner_files(
    session: Any,
    stage_payloads: list[dict[str, Any]],
    progress_callback: RemoteProgressCallback | None = None,
) -> None:
    _ensure_remote_scan_dir(session)
    progress_state: dict[str, Any] = {
        "total_chunks": _estimate_stage_chunk_count(stage_payloads),
        "uploaded_chunks": 0,
        "started_at": time.monotonic(),
        "post_stage_eta": 18.0,
        "default_chunk_time": 0.3,
        "total_files": max(1, len(stage_payloads)),
        "current_file_index": 1,
    }
    for file_index, item in enumerate(stage_payloads, start=1):
        label = str(item["label"])
        remote_path = str(item["remote_path"])
        progress_state["current_file_index"] = file_index
        _emit_stage_upload_progress(progress_callback, progress_state, label)
        print(f"[WinRM] Staging: {label}")
        _stage_remote_bytes(
            session,
            bytes(item["data"]),
            remote_path,
            label,
            progress_callback=progress_callback,
            progress_state=progress_state,
        )
        _verify_remote_file_exists(session, remote_path, label)


def _build_remote_execution_powershell() -> str:
    escaped_runner = _escape_ps_single_quoted(REMOTE_SCAN_RUNNER_FILE)
    return "\n".join(
        [
            "$ErrorActionPreference = 'Stop'",
            "$pythonExe = $null",
            "try {",
            "  & py -3 --version *> $null",
            "  if ($LASTEXITCODE -eq 0) {",
            "    $pythonExe = ((& py -3 -c \"import sys; print(sys.executable)\" 2>$null) | Out-String).Trim()",
            "  }",
            "} catch { }",
            "if ([string]::IsNullOrWhiteSpace($pythonExe)) { throw 'Python not found on remote host. Install Python or adjust the remote runner path.' }",
            f"$output = & $pythonExe '{escaped_runner}' 2>&1",
            "if ($LASTEXITCODE -ne 0) { throw ('Remote scan runner failed: ' + ($output | Out-String)) }",
            "$output | Out-String",
        ]
    )


def _run_remote_scan_runner(session: Any, progress_callback: RemoteProgressCallback | None = None) -> None:
    _emit_remote_progress(progress_callback, "Running security scan on the target device...", 70, 25)
    status_code, stdout, stderr = _run_remote_ps(session, _build_remote_execution_powershell())
    if status_code != 0:
        message = stderr.strip() or stdout.strip() or "Remote execution failed"
        raise RemoteScanError(f"Remote execution failed: {message}", code="execution_error")
    if REMOTE_SCAN_SENTINEL not in stdout:
        raise RemoteScanError("Remote execution failed", code="execution_error")
    _emit_remote_progress(progress_callback, "Remote scan finished. Preparing to retrieve results...", 85, 8)


def _get_remote_result_file_size(session: Any, progress_callback: RemoteProgressCallback | None = None) -> int:
    _emit_remote_progress(progress_callback, "Checking remote scan result file...", 90, 6)
    escaped_result = _escape_ps_single_quoted(REMOTE_SCAN_RESULT_FILE)
    script = (
        "$ErrorActionPreference = 'Stop'\n"
        f"if (-not (Test-Path -LiteralPath '{escaped_result}')) {{ throw 'RESULT_FILE_NOT_FOUND' }}\n"
        f"(Get-Item -LiteralPath '{escaped_result}').Length\n"
    )
    status_code, stdout, stderr = _run_remote_ps(session, script)
    if status_code != 0:
        message = stderr.strip() or stdout.strip() or "Scan failed or file not generated"
        if "RESULT_FILE_NOT_FOUND" in message:
            raise RemoteScanError("Scan failed or file not generated", code="execution_error")
        raise RemoteScanError(message, code="execution_error")
    try:
        return int(str(stdout).strip().splitlines()[-1])
    except Exception as exc:
        raise RemoteScanError("Invalid scan data", code="execution_error") from exc


def _read_remote_result_file(session: Any, progress_callback: RemoteProgressCallback | None = None) -> str:
    _emit_remote_progress(progress_callback, "Downloading scan results from the target device...", 95, 3)
    escaped_result = _escape_ps_single_quoted(REMOTE_SCAN_RESULT_FILE)
    script = (
        "$ErrorActionPreference = 'Stop'\n"
        f"if (-not (Test-Path -LiteralPath '{escaped_result}')) {{ throw 'RESULT_FILE_NOT_FOUND' }}\n"
        f"Get-Content -Raw -LiteralPath '{escaped_result}'\n"
    )
    status_code, stdout, stderr = _run_remote_ps(session, script)
    if status_code != 0:
        message = stderr.strip() or stdout.strip() or "Scan failed or file not generated"
        if "RESULT_FILE_NOT_FOUND" in message:
            raise RemoteScanError("Scan failed or file not generated", code="execution_error")
        raise RemoteScanError(message, code="execution_error")
    return stdout


def _parse_remote_scan_data(raw_text: str) -> dict[str, Any]:
    text = str(raw_text or "").lstrip("\ufeff").strip()
    if not text:
        raise RemoteScanError("Invalid scan data", code="execution_error")
    try:
        data = json.loads(text)
    except Exception as exc:
        raise RemoteScanError("Invalid scan data", code="execution_error") from exc
    if not isinstance(data, dict):
        raise RemoteScanError("Invalid scan data", code="execution_error")
    return data


def _raise_winrm_error(exc: Exception, operation: str = "scan") -> None:
    message = str(exc)
    class_name = exc.__class__.__name__
    prefix = "[WinRM]" if operation == "scan" else "[WinRM] Live Applications"
    print(f"{prefix} {class_name}: {message}")
    lower_message = message.lower()

    if class_name in {"InvalidCredentialsError", "AuthenticationError"}:
        raise RemoteScanError("Invalid Credentials", code="invalid_credentials") from exc

    if class_name == "BasicAuthDisabledError":
        if operation == "scan":
            raise RemoteScanError(
                "Connection Failed: WinRM Basic authentication is disabled on the target PC.",
                code="connection_failed",
            ) from exc
        raise RemoteScanError("Unable to fetch running applications", code="connection_failed") from exc

    if class_name == "WinRMOperationTimeoutError" or "timed out" in lower_message or "timeout" in lower_message:
        if operation == "scan":
            raise RemoteScanError("Connection Failed (Timeout)", code="timeout") from exc
        raise RemoteScanError("Unable to fetch running applications", code="timeout") from exc

    if class_name == "WinRMTransportError":
        if "401" in lower_message or "unauthorized" in lower_message or "credentials" in lower_message:
            raise RemoteScanError("Invalid Credentials", code="invalid_credentials") from exc
        if "actively refused" in lower_message or "connection refused" in lower_message:
            if operation == "scan":
                raise RemoteScanError(
                    "WinRM is reachable but the endpoint refused the connection. Check that the WinRM service is running and listening on the target PC.",
                    code="connection_failed",
                ) from exc
            raise RemoteScanError("Unable to fetch running applications", code="connection_failed") from exc
        if operation == "scan":
            raise RemoteScanError(f"Connection Failed: {message}", code="connection_failed") from exc
        raise RemoteScanError("Unable to fetch running applications", code="connection_failed") from exc

    if "401" in lower_message or "unauthorized" in lower_message or "credentials" in lower_message:
        raise RemoteScanError("Invalid Credentials", code="invalid_credentials") from exc

    if operation == "scan":
        raise RemoteScanError(f"Connection Failed: {message}", code="connection_failed") from exc
    raise RemoteScanError("Unable to fetch running applications", code="execution_error") from exc


def create_winrm_session(ip_address: str, username: str, password: str, timeout_s: int = 90) -> Any:
    try:
        import winrm
    except Exception as exc:
        raise RemoteScanError(
            "pywinrm is not installed. Run: python -m pip install pywinrm",
            code="missing_dependency",
        ) from exc

    try:
        _probe_winrm_endpoint(ip_address)
        normalized_username = _normalize_winrm_username(username)
        username_candidates = _build_winrm_username_candidates(username)
        endpoint = f"http://{ip_address}:5985/wsman"
        attempt_errors: list[Exception] = []
        for candidate_username in username_candidates:
            for transport in _build_winrm_transport_attempts():
                try:
                    print(f"[WinRM] Endpoint: {endpoint}")
                    print(f"[WinRM] Username: {candidate_username}")
                    print(f"[WinRM] IP Address: {ip_address}")
                    print(f"[WinRM] Transport: {transport}")
                    session = winrm.Session(
                        endpoint,
                        auth=(candidate_username, password),
                        transport=transport,
                        proxy=None,
                        read_timeout_sec=timeout_s,
                        operation_timeout_sec=max(20, min(timeout_s - 10, timeout_s)),
                    )
                    _verify_winrm_session(session)
                    try:
                        session._endpoint_dashboard_username = candidate_username
                    except Exception:
                        pass
                    print("[WinRM] Authentication probe succeeded.")
                    return session
                except Exception as exc:
                    attempt_errors.append(exc)
                    print(f"[WinRM] {transport} authentication failed for {candidate_username}: {exc}")
        if attempt_errors:
            try:
                _raise_winrm_error(attempt_errors[-1], operation="scan")
            except RemoteScanError as exc:
                if exc.code == "invalid_credentials" and _looks_like_unqualified_local_username(normalized_username):
                    raise RemoteScanError(
                        f"{exc}. Tried {', '.join(username_candidates)}. If this is a local account, try COMPUTERNAME\\{normalized_username}.",
                        code=exc.code,
                    ) from attempt_errors[-1]
                raise
        raise RemoteScanError("Connection Failed", code="connection_failed")
    except RemoteScanError:
        raise
    except Exception as exc:
        _raise_winrm_error(exc, operation="scan")


def run_remote_scan_with_session(
    ip_address: str,
    session: Any,
    progress_callback: RemoteProgressCallback | None = None,
) -> dict[str, Any]:
    try:
        stage_payloads = _build_remote_stage_payloads()
        estimated_stage_seconds = int(round((_estimate_stage_chunk_count(stage_payloads) * 0.3) + 18))
        _emit_remote_progress(progress_callback, "Preparing remote scan files...", 10, max(20, estimated_stage_seconds))
        _stage_remote_scanner_files(session, stage_payloads, progress_callback=progress_callback)
        _run_remote_scan_runner(session, progress_callback=progress_callback)
        result_size = _get_remote_result_file_size(session, progress_callback=progress_callback)
        print(f"[WinRM] Remote result size: {result_size} bytes")
        if result_size > REMOTE_SCAN_RESULT_MAX_BYTES:
            raise RemoteScanError(
                f"Scan result file is too large to retrieve safely ({result_size} bytes).",
                code="execution_error",
            )
        raw_result = _read_remote_result_file(session, progress_callback=progress_callback)
        _emit_remote_progress(progress_callback, "Processing retrieved scan data...", 98, 1)
        scan_out = _parse_remote_scan_data(raw_result)
    except RemoteScanError:
        raise
    except Exception as exc:
        _raise_winrm_error(exc, operation="scan")

    scan_out["target_ip"] = ip_address
    scan_out["device_id"] = ip_address
    scan_out["connection_status"] = "Online"
    scan_out["last_scan_at"] = datetime.now().astimezone().isoformat()
    _emit_remote_progress(progress_callback, "Remote scan complete. Loading results into the dashboard...", 100, 0)
    return _make_json_safe(enrich_device_metadata(scan_out))


def run_remote_scan(
    ip_address: str,
    username: str,
    password: str,
    timeout_s: int = 90,
    progress_callback: RemoteProgressCallback | None = None,
) -> dict[str, Any]:
    _emit_remote_progress(progress_callback, f"Checking WinRM connectivity for {ip_address}...", 3, max(30, timeout_s))
    _emit_remote_progress(progress_callback, f"Connecting to {ip_address} over WinRM...", 6, max(25, timeout_s - 10))
    session = create_winrm_session(ip_address, username, password, timeout_s=timeout_s)
    return run_remote_scan_with_session(ip_address, session, progress_callback=progress_callback)


def fetch_live_processes_with_session(
    ip_address: str,
    session: Any,
    limit: int = 50,
) -> list[dict[str, Any]]:
    max_items = max(1, min(int(limit or 50), 100))
    ps_script = "\n".join(
        [
            "$ErrorActionPreference = 'Stop'",
            f"$limit = {max_items}",
            "$processes = @(",
            "  Get-Process |",
            "  Sort-Object CPU -Descending |",
            "  Select-Object -First $limit "
            "@{Name='ProcessName';Expression={$_.ProcessName}}, "
            "@{Name='Id';Expression={$_.Id}}, "
            "@{Name='CPU';Expression={if ($_.CPU -ne $null) {[math]::Round([double]$_.CPU, 2)} else {$null}}}, "
            "@{Name='WorkingSetMB';Expression={[math]::Round([double]$_.WorkingSet64 / 1MB, 1)}}",
            ")",
            "$processes | ConvertTo-Json -Compress -Depth 3",
        ]
    )

    try:
        status_code, stdout, stderr = _run_remote_ps(session, ps_script)
        if status_code != 0:
            message = stderr.strip() or stdout.strip() or "Unable to fetch running applications"
            raise RemoteScanError(message, code="execution_error")
    except RemoteScanError:
        raise
    except Exception as exc:
        _raise_winrm_error(exc, operation="live_processes")

    payload = str(stdout or "").lstrip("\ufeff").strip()
    return _parse_process_payload(payload, limit=max_items)


def fetch_live_processes(
    ip_address: str,
    username: str,
    password: str,
    limit: int = 50,
    timeout_s: int = 45,
) -> list[dict[str, Any]]:
    session = create_winrm_session(ip_address, username, password, timeout_s=timeout_s)
    return fetch_live_processes_with_session(ip_address, session, limit=limit)


def _parse_process_payload(payload: str, limit: int = 50) -> list[dict[str, Any]]:
    text = str(payload or "").lstrip("\ufeff").strip()
    if not text:
        return []

    try:
        raw_items = json.loads(text)
    except Exception as exc:
        raise RemoteScanError("Unable to fetch running applications", code="execution_error") from exc

    if isinstance(raw_items, dict):
        items = [raw_items]
    elif isinstance(raw_items, list):
        items = [item for item in raw_items if isinstance(item, dict)]
    else:
        raise RemoteScanError("Unable to fetch running applications", code="execution_error")

    processes: list[dict[str, Any]] = []
    for item in items:
        name = str(item.get("ProcessName") or item.get("Name") or "").strip()
        if not name:
            continue
        try:
            pid = int(item.get("Id") or 0)
        except Exception:
            pid = 0

        memory_value = item.get("WorkingSetMB")
        try:
            memory_mb = round(float(memory_value), 1) if memory_value not in (None, "", "None") else None
        except Exception:
            memory_mb = None

        cpu_value = item.get("CPU")
        try:
            cpu_usage = round(float(cpu_value), 2) if cpu_value not in (None, "", "None") else None
        except Exception:
            cpu_usage = None

        processes.append(
            {
                "name": name,
                "pid": pid,
                "memory_mb": memory_mb,
                "cpu": cpu_usage,
            }
        )

    processes.sort(
        key=lambda row: (
            -float(row.get("cpu") or 0.0),
            -float(row.get("memory_mb") or 0.0),
            str(row.get("name") or "").lower(),
        )
    )
    return processes[: max(1, min(int(limit or 50), 100))]


def fetch_local_processes(limit: int = 50) -> list[dict[str, Any]]:
    max_items = max(1, min(int(limit or 50), 100))
    ps_script = (
        "$ErrorActionPreference = 'Stop'; "
        f"$limit = {max_items}; "
        "$processes = @(Get-Process | Sort-Object CPU -Descending | "
        "Select-Object -First $limit "
        "@{Name='ProcessName';Expression={$_.ProcessName}}, "
        "@{Name='Id';Expression={$_.Id}}, "
        "@{Name='CPU';Expression={if ($_.CPU -ne $null) {[math]::Round([double]$_.CPU, 2)} else {$null}}}, "
        "@{Name='WorkingSetMB';Expression={[math]::Round([double]$_.WorkingSet64 / 1MB, 1)}}); "
        "$processes | ConvertTo-Json -Compress -Depth 3"
    )
    code, stdout, stderr = _run_command(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
        timeout_s=20,
    )
    if code != 0:
        message = stderr.strip() or stdout.strip() or "Unable to fetch running applications"
        raise RemoteScanError(message, code="execution_error")
    return _parse_process_payload(stdout, limit=max_items)


def get_third_party_software() -> dict[str, Any]:
    """
    Basic third-party software inventory using PowerShell uninstall registry keys.
    Includes a simple "potentially outdated" signal using InstallDate age and missing version.
    """
    result: dict[str, Any] = {"apps": [], "potentially_outdated": [], "error": None, "method": "PowerShell registry query"}
    ps_cmd = (
        "$paths = @("
        " 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
        " 'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
        " 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'"
        ");"
        "Get-ItemProperty $paths -ErrorAction SilentlyContinue | "
        "Where-Object {$_.DisplayName -and $_.DisplayName.Trim() -ne ''} | "
        "Select-Object DisplayName,DisplayVersion,Publisher,InstallDate | "
        "Sort-Object DisplayName | Format-Table -AutoSize"
    )
    code, out, err = _run_command(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd],
        timeout_s=45,
    )
    if code != 0 or not out:
        result["error"] = err or "Could not read installed software."
        return result

    lines = [ln.rstrip() for ln in out.splitlines() if ln.strip()]
    # Skip header/separator lines
    data_lines = [ln for ln in lines if not re.fullmatch(r"-{3,}(\s+-{3,})*", ln.strip()) and "DisplayName" not in ln]

    apps: list[dict[str, Any]] = []
    now = datetime.now(timezone.utc).astimezone()
    for ln in data_lines:
        parts = re.split(r"\s{2,}", ln.strip())
        if not parts:
            continue
        name = parts[0].strip()
        version = parts[1].strip() if len(parts) > 1 else ""
        publisher = parts[2].strip() if len(parts) > 2 else ""
        install_date_raw = parts[3].strip() if len(parts) > 3 else ""

        app = {
            "name": name,
            "version": version or "Unknown",
            "publisher": publisher or "Unknown",
            "install_date": install_date_raw or "Unknown",
        }
        apps.append(app)

    result["apps"] = apps[:120]  # keep UI manageable

    potentially_outdated: list[dict[str, Any]] = []
    for app in result["apps"]:
        reason_parts: list[str] = []
        if app["version"] == "Unknown":
            reason_parts.append("version not available")

        date_raw = str(app.get("install_date") or "")
        if re.fullmatch(r"\d{8}", date_raw):
            try:
                dt = datetime.strptime(date_raw, "%Y%m%d").replace(tzinfo=now.tzinfo)
                age_days = (now - dt).days
                if age_days > 365 * 3:
                    reason_parts.append(f"installed ~{age_days} days ago")
            except Exception:
                pass

        if reason_parts:
            potentially_outdated.append(
                {
                    "name": app["name"],
                    "version": app["version"],
                    "reason": ", ".join(reason_parts),
                }
            )
    result["potentially_outdated"] = potentially_outdated[:40]
    return result


def run_single_scan() -> dict[str, Any]:
    """
    Runs a full scan using the host checks in os_check and
    returns a normalized result dictionary:

    {
      "hostname": "...",
      "risk_score": 10,
      "risk_level": "HIGH",
      "vulnerabilities": [
        {
          "title": "...",
          "severity": "HIGH",
          "description": "...",
          "fix": "..."
        }
      ]
    }
    """
    system_info = os_check.get_system_info()
    av_info = os_check.check_antivirus()
    patch_info = os_check.check_patches()
    assessment = os_check.vulnerability_check(system_info, av_info, patch_info)
    software_info = get_third_party_software()
    installed_inventory = installed_apps.get_installed_apps()
    software_analysis = risk.analyze_software_risk(installed_inventory)
    risky_apps = risk.filter_risky_apps(software_analysis)
    software_info["risky_apps"] = risky_apps

    hostname = system_info.get("hostname") or "Unknown"
    risk_score = int(assessment.get("risk_score") or 0)
    risk_level = str(assessment.get("risk_level") or "UNKNOWN").upper()

    vulns_out: list[dict[str, Any]] = []
    for v in assessment.get("vulnerabilities") or []:
        title = str(v.get("title") or "Finding")
        severity = str(v.get("severity") or "INFO").upper()
        details = str(v.get("details") or "")
        meaning = str(v.get("meaning") or "")
        why = str(v.get("why") or "")
        fix = str(v.get("fix") or "")

        # Simple, readable description combining technical and plain language.
        parts = []
        if details:
            parts.append(details)
        if meaning:
            parts.append(f"What this means: {meaning}")
        if why:
            parts.append(f"Why it matters: {why}")
        description = " ".join(parts) if parts else title

        vulns_out.append(
            {
                "title": title,
                "severity": severity,
                "description": description,
                "fix": fix,
            }
        )

    scan_out = {
        "hostname": hostname,
        "device_id": system_info.get("ip_address") or hostname,
        "target_ip": system_info.get("ip_address") or hostname,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "connection_status": "Local Scan",
        "last_scan_at": datetime.now().astimezone().isoformat(),
        "vulnerabilities": vulns_out,
        # Extra structured details for dashboard component breakdown.
        "system_info": system_info,
        "antivirus": av_info,
        "patches": patch_info,
        "firewall": assessment.get("firewall") or {},
        "open_ports": assessment.get("open_ports") or {},
        "services": assessment.get("services") or {},
        "third_party_software": software_info,
        "installed_apps": installed_inventory,
        "risky_apps": risky_apps,
    }
    return _make_json_safe(enrich_device_metadata(scan_out))


def load_scan_results(path: Path | None = None) -> list[dict[str, Any]]:
    """
    Loads existing scan results from JSON.
    Returns an empty list if the file does not exist or is invalid.
    """
    p = path or SCAN_RESULTS_FILE
    if not p.exists():
        return []
    try:
        with p.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return [enrich_device_metadata(item) for item in data if isinstance(item, dict)]
        return []
    except Exception:
        return []


def load_unauthenticated_scan_results(path: Path | None = None) -> list[dict[str, Any]]:
    return load_scan_results(path=path or UNAUTH_SCAN_RESULTS_FILE)


def save_scan_results(results: list[dict[str, Any]], path: Path | None = None) -> None:
    """
    Saves all scan results to JSON in a simple, readable format.
    """
    p = path or SCAN_RESULTS_FILE
    try:
        with p.open("w", encoding="utf-8") as f:
            json.dump(_make_json_safe(results), f, indent=2, ensure_ascii=False)
    except Exception:
        # In a real tool you might log this; here we fail silently to keep it beginner-friendly.
        pass


def save_unauthenticated_scan_results(results: list[dict[str, Any]], path: Path | None = None) -> None:
    save_scan_results(results, path=path or UNAUTH_SCAN_RESULTS_FILE)


def add_scan_to_results() -> dict[str, Any]:
    """
    Convenience helper:
    - Loads existing scan_results.json
    - Runs a new scan
    - Adds/updates the entry for this hostname
    - Saves back to disk
    Returns the new scan result.
    """
    new_scan = run_single_scan()
    results = load_scan_results()
    upsert_scan_result(results, new_scan)
    save_scan_results(results)
    return new_scan


def add_unauthenticated_scan_to_results(subnet: str, progress_callback: RemoteProgressCallback | None = None) -> list[dict[str, Any]]:
    new_results = run_unauthenticated_scan(subnet, progress_callback=progress_callback)
    save_unauthenticated_scan_results(new_results)
    return new_results


if __name__ == "__main__":
    # Simple manual smoke test: run a scan and print normalized JSON.
    scan = add_scan_to_results()
    print(json.dumps(scan, indent=2, ensure_ascii=True))
