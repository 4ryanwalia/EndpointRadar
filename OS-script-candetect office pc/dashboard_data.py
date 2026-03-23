"""
dashboard_data.py

Data processing helpers for the GUI dashboard.
Keeps UI rendering code separate from score/explanation calculations.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple


COMPONENTS = [
    "Firewall",
    "SMB / Open Ports",
    "Patching",
    "Antivirus",
    "Services",
    "Third-party Software",
]

COMPONENT_COLORS = {
    "Firewall": "#E53935",
    "SMB / Open Ports": "#FB8C00",
    "Patching": "#FDD835",
    "Antivirus": "#1E88E5",
    "Services": "#8E24AA",
    "Third-party Software": "#26A69A",
}


def is_limited_visibility_scan(scan: Dict[str, Any] | None) -> bool:
    data = scan or {}
    return bool(data.get("limited_visibility")) or str(data.get("scan_mode") or "").strip().lower() == "unauthenticated"


def _parse_version_major(version: Any) -> int | None:
    text = str(version or "").strip()
    if not text or text.upper() == "N/A":
        return None
    match = re.search(r"(\d+)", text)
    if not match:
        return None
    try:
        return int(match.group(1))
    except Exception:
        return None


def analyze_software_risk(apps: List[Dict[str, Any]] | None) -> List[Dict[str, str]]:
    """
    Applies simple software risk heuristics to installed applications.
    Returns one assessment row per application with a risk level and reason.
    """
    analysis: List[Dict[str, str]] = []
    for app in apps or []:
        name = str(app.get("name") or "").strip()
        if not name:
            continue

        version = str(app.get("version") or "N/A").strip() or "N/A"
        lower_name = name.lower()
        reasons: List[str] = []
        rank = 0  # 0=LOW, 1=MEDIUM, 2=HIGH

        if version.upper() == "N/A":
            rank = max(rank, 1)
            reasons.append("Version not available, cannot verify security status")

        if any(term in lower_name for term in ("java", "flash", "old")):
            rank = max(rank, 2)
            reasons.append("Known high-risk or deprecated software")

        if "chrome" in lower_name or "edge" in lower_name:
            major = _parse_version_major(version)
            if major is not None and major < 120:
                rank = max(rank, 2)
                reasons.append("Outdated browser version")

        if rank >= 2:
            risk_level = "HIGH"
        elif rank == 1:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
            reasons.append("No immediate software risk heuristics matched")

        analysis.append(
            {
                "name": name,
                "version": version,
                "risk_level": risk_level,
                "reason": "; ".join(reasons),
            }
        )
    return analysis


def filter_risky_apps(analysis: List[Dict[str, Any]] | None) -> List[Dict[str, str]]:
    """
    Returns only MEDIUM/HIGH software findings for scoring, export, and JSON output.
    """
    risky_apps: List[Dict[str, str]] = []
    for item in analysis or []:
        risk_level = str(item.get("risk_level") or item.get("risk") or "LOW").upper()
        if risk_level not in {"HIGH", "MEDIUM"}:
            continue
        risky_apps.append(
            {
                "name": str(item.get("name") or "").strip(),
                "version": str(item.get("version") or "N/A").strip() or "N/A",
                "risk_level": risk_level,
                "reason": str(item.get("reason") or "").strip(),
            }
        )
    return risky_apps


def _clamp(value: int, lo: int = 0, hi: int = 100) -> int:
    return max(lo, min(hi, int(value)))


def _severity_points(severity: Any, high: int, medium: int, low: int = 1) -> int:
    level = str(severity or "").upper()
    if level == "HIGH":
        return high
    if level == "MEDIUM":
        return medium
    if level == "LOW":
        return low
    return medium


def compute_component_scores(scan: Dict[str, Any]) -> Dict[str, int]:
    """
    Returns component risk scores in range 0-100 where higher means riskier.
    Scores are derived only from actual detected issues in structured scan data.
    """
    scores = {name: 0 for name in COMPONENTS}

    if is_limited_visibility_scan(scan):
        ports = scan.get("open_ports") or {}
        risky = ports.get("risky_open") or []
        for item in risky:
            scores["SMB / Open Ports"] += _severity_points(item.get("severity"), high=4, medium=3, low=1)
        if len(risky) >= 3:
            scores["SMB / Open Ports"] += 3
        elif len(risky) >= 2:
            scores["SMB / Open Ports"] += 1
        scores["SMB / Open Ports"] = _clamp(scores["SMB / Open Ports"])
        return scores

    av = scan.get("antivirus") or {}
    if not av.get("found"):
        scores["Antivirus"] += 5
    else:
        av_status = str(av.get("status") or "UNKNOWN").upper()
        if av_status == "DISABLED":
            scores["Antivirus"] += 4
        if av.get("realtime_protection") is False:
            scores["Antivirus"] += 3

    fw = scan.get("firewall") or {}
    for profile in ("Domain", "Private", "Public"):
        state = str((fw.get("profiles") or {}).get(profile, {}).get("state") or "").upper()
        if state == "OFF":
            scores["Firewall"] += 5

    ports = scan.get("open_ports") or {}
    risky = ports.get("risky_open") or []
    for item in risky:
        scores["SMB / Open Ports"] += _severity_points(item.get("severity"), high=3, medium=2, low=1)

    patches = scan.get("patches") or {}
    days = patches.get("days_since_last_patch")
    if isinstance(days, int) and days > 30:
        scores["Patching"] += 4
    elif isinstance(days, int) and days > 14:
        scores["Patching"] += 2

    total_patches = int(patches.get("total_patches") or 0)
    patch_warning = str(patches.get("patch_warning") or "").strip()
    if total_patches == 0:
        scores["Patching"] += 3
    elif patch_warning:
        scores["Patching"] += 2

    services = scan.get("services") or {}
    highlighted = services.get("highlighted") or []
    for item in highlighted:
        scores["Services"] += _severity_points(item.get("severity"), high=2, medium=1, low=1)

    risky_apps = scan.get("risky_apps")
    if not isinstance(risky_apps, list):
        risky_apps = filter_risky_apps(analyze_software_risk(scan.get("installed_apps") or []))

    high_risk_count = sum(1 for item in risky_apps if str(item.get("risk_level") or item.get("risk") or "").upper() == "HIGH")
    medium_risk_count = sum(
        1 for item in risky_apps if str(item.get("risk_level") or item.get("risk") or "").upper() == "MEDIUM"
    )
    scores["Third-party Software"] += (high_risk_count * 2) + medium_risk_count

    for k in scores:
        scores[k] = _clamp(scores[k])
    return scores


def compute_contributions(component_scores: Dict[str, int]) -> Dict[str, float]:
    total = sum(component_scores.values())
    if total <= 0:
        return {k: 0.0 for k in component_scores}
    return {k: (v / total) * 100.0 for k, v in component_scores.items()}


def summarize_risk_reason(scan: Dict[str, Any]) -> str:
    scores = compute_component_scores(scan)
    if sum(scores.values()) <= 0:
        if is_limited_visibility_scan(scan):
            return "Limited attacker-view scan found no exposed monitored services."
        return "System is secure. No risks detected."

    level = str(scan.get("risk_level") or "UNKNOWN").upper()
    if is_limited_visibility_scan(scan):
        notes = [str(item).strip() for item in scan.get("risk_notes") or [] if str(item).strip()]
        if notes:
            return f"Limited attacker-view risk is {level} due to: " + ", ".join(notes[:3])
        return f"Limited attacker-view risk is {level} based on exposed monitored services."
    vulns = scan.get("vulnerabilities") or []
    key_titles = [str(v.get("title") or "") for v in vulns if str(v.get("severity") or "").upper() in {"HIGH", "MEDIUM"}][:3]
    if not key_titles:
        return f"Risk level is {level}. No major findings were recorded."
    return f"Risk level is {level} mainly due to: " + ", ".join(key_titles) + "."


def top_risk_drivers(scan: Dict[str, Any], limit: int = 3) -> List[Tuple[str, int, float]]:
    """
    Returns top contributing components as tuples:
    (component_name, points, percent_of_total)
    """
    scores = compute_component_scores(scan)
    perc = compute_contributions(scores)
    ordered = sorted(scores.items(), key=lambda item: item[1], reverse=True)
    out: List[Tuple[str, int, float]] = []
    for name, points in ordered[:limit]:
        out.append((name, int(points), float(perc.get(name, 0.0))))
    return out


def risk_distribution(results: List[Dict[str, Any]]) -> Tuple[Dict[str, int], Dict[str, List[str]]]:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    names = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
    for r in results:
        lvl = str(r.get("risk_level") or "LOW").upper()
        if lvl not in counts:
            lvl = "LOW"
        counts[lvl] += 1
        names[lvl].append(str(r.get("hostname") or "Unknown"))
    return counts, names
