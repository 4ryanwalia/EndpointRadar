"""
threat_analysis.py

Generates an NIST-aligned Threat Analysis from an existing scan result.
This does not modify scan logic or scan JSON output; it only interprets findings.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import dashboard_data


RISK_LEVELS = {
    "LOW": (1, 5),
    "MEDIUM": (6, 14),
    "HIGH": (15, 25),
}


def _risk_level_from_score(score: int) -> str:
    if RISK_LEVELS["LOW"][0] <= score <= RISK_LEVELS["LOW"][1]:
        return "LOW"
    if RISK_LEVELS["MEDIUM"][0] <= score <= RISK_LEVELS["MEDIUM"][1]:
        return "MEDIUM"
    return "HIGH"


def _nist_csf_function_for_category(category: str) -> str:
    """
    Hardcoded NIST CSF 2.0 mapping rules (as requested).
    """
    mapping = {
        "Firewall": "Protect",
        "Open Ports": "Protect",
        "OS / Patching": "Protect",
        "Antivirus": "Detect",  # antivirus disabled -> Detect
        "Services": "Protect",  # service exposure -> Protect
        "Third-party Software": "Protect",
        # "Logging issues": "Detect"  # no local logging checks in this tool
    }
    return mapping.get(category, "Protect")


def _likelihood_impact_to_risk(likelihood: int, impact: int) -> tuple[int, str]:
    score = int(likelihood) * int(impact)  # (1-5) x (1-5)
    level = _risk_level_from_score(score)
    return score, level


def _add_threat(
    threats: List[Dict[str, Any]],
    *,
    category: str,
    title: str,
    likelihood: int,
    impact: int,
    description: str,
    recommendation: str,
) -> None:
    score, level = _likelihood_impact_to_risk(likelihood, impact)
    threats.append(
        {
            "category": category,
            "threat_title": title,
            "risk_level": level,
            "nist_function": _nist_csf_function_for_category(category),
            "description": description,
            "recommendation": recommendation,
            "likelihood": likelihood,
            "impact": impact,
            "score": score,
        }
    )


def generate_threats(scan: Dict[str, Any], max_threats: int = 10) -> List[Dict[str, Any]]:
    """
    Generates 5-10 threats max, grouped by requested categories:
    Firewall, Antivirus, OS / Patching, Open Ports, Services, Third-party Software.

    Uses hardcoded likelihood/impact based on existing scan findings.
    """
    threats: List[Dict[str, Any]] = []
    limited_visibility = dashboard_data.is_limited_visibility_scan(scan)

    fw = scan.get("firewall") or {}
    fw_profiles = fw.get("profiles") or {}
    fw_off_profiles = [
        prof for prof in ("Domain", "Private", "Public") if str((fw_profiles.get(prof) or {}).get("state") or "").upper() == "OFF"
    ]
    fw_any_off = len(fw_off_profiles) > 0

    av = scan.get("antivirus") or {}
    av_found = bool(av.get("found"))
    av_status = str(av.get("status") or "UNKNOWN").upper()
    rtp = av.get("realtime_protection")

    patches = scan.get("patches") or {}
    days = patches.get("days_since_last_patch")
    total_patches = int(patches.get("total_patches") or 0)

    ports = scan.get("open_ports") or {}
    risky_open = ports.get("risky_open") or []
    risky_ports = {int(item.get("port")) for item in risky_open if isinstance(item.get("port"), int) or str(item.get("port")).isdigit()}

    services = scan.get("services") or {}
    highlighted = services.get("highlighted") or []
    service_names = {str(s.get("name") or "") for s in highlighted}
    service_sev = {str(s.get("name") or ""): str(s.get("severity") or "MEDIUM").upper() for s in highlighted}

    # --- Firewall threats (1-2) ---
    if fw_any_off and not limited_visibility:
        _add_threat(
            threats,
            category="Firewall",
            title="Unauthorized network access risk",
            likelihood=4,
            impact=4,
            description="Firewall is OFF for one or more profiles, allowing more inbound traffic than intended.",
            recommendation="Enable Windows Firewall for all profiles and restrict inbound rules to only required services.",
        )

        # Optional second threat if multiple profiles are OFF
        if len(fw_off_profiles) >= 2:
            _add_threat(
                threats,
                category="Firewall",
                title="Reduced inbound protection across networks",
                likelihood=3,
                impact=4,
                description="Multiple network types have firewall protection disabled, increasing attack surface.",
                recommendation="Re-enable firewall for Domain/Private/Public as appropriate and verify policy via Windows Security.",
            )

    # --- Antivirus threats (1-2) ---
    if not limited_visibility and not av_found:
        _add_threat(
            threats,
            category="Antivirus",
            title="Malware execution risk",
            likelihood=4,
            impact=4,
            description="No antivirus product was detected (or access is restricted).",
            recommendation="Install a reputable antivirus and ensure real-time protection is enabled.",
        )
    elif not limited_visibility:
        # Antivirus disabled
        if av_status == "DISABLED":
            _add_threat(
                threats,
                category="Antivirus",
                title="Antivirus disabled protection gap",
                likelihood=4,
                impact=4,
                description="Antivirus appears installed but disabled, reducing protection against malware.",
                recommendation="Enable antivirus immediately and confirm the security product is active.",
            )
        # Real-time protection off
        if rtp is False:
            _add_threat(
                threats,
                category="Antivirus",
                title="Malware can run before scans complete",
                likelihood=4,
                impact=3,
                description="Real-time protection is OFF (best effort), so malware may execute before detection.",
                recommendation="Turn on real-time protection and verify scheduled scan policies are enabled.",
            )

    # --- OS / Patching threats (1-2) ---
    if not limited_visibility and days is not None:
        if isinstance(days, int) and days > 30:
            _add_threat(
                threats,
                category="OS / Patching",
                title="Known vulnerabilities may be present",
                likelihood=4,
                impact=4,
                description="Most recent patch is older than 30 days, increasing exposure to known vulnerabilities.",
                recommendation="Run Windows Update and ensure the latest cumulative/security updates are installed.",
            )
        elif isinstance(days, int) and days > 14:
            _add_threat(
                threats,
                category="OS / Patching",
                title="Patching behind schedule",
                likelihood=3,
                impact=3,
                description="Patch recency is older than ideal; some security updates may be missing.",
                recommendation="Update Windows and confirm update reporting/automation for ongoing patch compliance.",
            )

    if not limited_visibility and total_patches == 0:
        _add_threat(
            threats,
            category="OS / Patching",
            title="Patch inventory may be incomplete",
            likelihood=3,
            impact=3,
            description="HotFix inventory appears empty; the device may be missing updates or update reporting is blocked.",
            recommendation="Verify Windows Update status and re-check hotfix inventory after updates are applied.",
        )
    elif not limited_visibility and total_patches < 15:
        # Low patch count: medium risk
        _add_threat(
            threats,
            category="OS / Patching",
            title="Potential missing cumulative updates",
            likelihood=3,
            impact=2,
            description="Unusually low number of HotFix entries suggests patching may not be complete.",
            recommendation="Confirm Windows Update compliance and install missing cumulative updates.",
        )

    # --- Open Ports threats (1-2) ---
    if 445 in risky_ports:
        _add_threat(
            threats,
            category="Open Ports",
            title="SMB exploitation risk (Port 445)",
            likelihood=4,
            impact=4,
            description="SMB (file sharing) port is exposed, increasing risk of wormable/malware-based attacks.",
            recommendation="Disable SMB if not required, or restrict access using firewall rules (especially on Public networks).",
        )

    if 3389 in risky_ports:
        _add_threat(
            threats,
            category="Open Ports",
            title="Remote access brute-force risk (Port 3389)",
            likelihood=4,
            impact=3,
            description="RDP port is exposed; attackers can attempt credential guessing or exploit weaknesses.",
            recommendation="Disable RDP if unused. If required, restrict via VPN/allow-list and enforce strong authentication.",
        )

    if limited_visibility and len(risky_ports) >= 3:
        _add_threat(
            threats,
            category="Open Ports",
            title="Multiple exposed network services",
            likelihood=4,
            impact=3,
            description="Several monitored services are reachable without authentication, increasing the chance of opportunistic discovery and misuse.",
            recommendation="Reduce the number of externally reachable services and restrict any required services to trusted network paths.",
        )

    # --- Services threats (1-2) ---
    # Only score services that our scan highlights as risky.
    if not limited_visibility and "LanmanServer" in service_names:
        _add_threat(
            threats,
            category="Services",
            title="SMB server service exposure",
            likelihood=3,
            impact=4,
            description="SMB server service is running, increasing exposure to file-sharing attacks if vulnerable.",
            recommendation="Disable file sharing if not required, otherwise harden SMB and restrict network access via firewall.",
        )

    if not limited_visibility and "TermService" in service_names:
        _add_threat(
            threats,
            category="Services",
            title="Remote Desktop service exposure",
            likelihood=3,
            impact=4,
            description="Remote Desktop Services is running, increasing the risk from remote access attacks.",
            recommendation="Disable Remote Desktop if not required. If required, restrict access and enable NLA/MFA.",
        )

    # --- Third-party software threats (1-2) ---
    risky_apps = scan.get("risky_apps")
    if not isinstance(risky_apps, list):
        risky_apps = dashboard_data.filter_risky_apps(dashboard_data.analyze_software_risk(scan.get("installed_apps") or []))

    high_risk_apps = [item for item in risky_apps if str(item.get("risk_level") or item.get("risk") or "").upper() == "HIGH"]
    medium_risk_apps = [item for item in risky_apps if str(item.get("risk_level") or item.get("risk") or "").upper() == "MEDIUM"]

    if not limited_visibility and high_risk_apps:
        sample_names = ", ".join(str(item.get("name") or "") for item in high_risk_apps[:3] if str(item.get("name") or "").strip())
        detail = f" Examples: {sample_names}." if sample_names else ""
        _add_threat(
            threats,
            category="Third-party Software",
            title="Outdated software exploitation",
            likelihood=4,
            impact=4,
            description="Outdated or deprecated third-party applications may contain known vulnerabilities." + detail,
            recommendation="Update all outdated software to the latest supported versions and remove deprecated applications.",
        )

    if not limited_visibility and medium_risk_apps:
        _add_threat(
            threats,
            category="Third-party Software",
            title="Software inventory gaps reduce vulnerability visibility",
            likelihood=3,
            impact=3,
            description="Some installed applications do not expose usable version data, making patch verification difficult.",
            recommendation="Capture software versions consistently and review unversioned applications for manual validation or replacement.",
        )

    # Reduce threats to max_threats (but keep variety)
    if len(threats) > max_threats:
        # Prefer: keep up to 2 per category, in insertion order
        kept: List[Dict[str, Any]] = []
        cat_counts: Dict[str, int] = {}
        for t in threats:
            cat = str(t.get("category") or "Unknown")
            cat_counts[cat] = cat_counts.get(cat, 0) + 1
            if cat_counts[cat] <= 2:
                kept.append(t)
            if len(kept) >= max_threats:
                break
        threats = kept

    return threats


def export_threats(threats: List[Dict[str, Any]], output_path: Path | str = "threat_analysis.json") -> Path:
    """
    Exports Threat Analysis to JSON (default).
    """
    out_path = Path(output_path)
    payload = {"exported_at": datetime.now().isoformat(), "threats": threats}
    out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return out_path

