"""Risk scoring and software-inventory analysis.

Turns a raw scan record into component scores, weighted contributions and
plain-English explanations. Kept free of any UI or I/O so the CLI, the GUI
and the web API all score identically.
"""

from __future__ import annotations

from typing import Any

COMPONENTS = [
    "Firewall",
    "SMB / Open Ports",
    "Patching",
    "Antivirus",
    "Services",
    "Third-party Software",
    "Device Protection",
]

COMPONENT_COLORS = {
    "Firewall": "#E53935",
    "SMB / Open Ports": "#FB8C00",
    "Patching": "#FDD835",
    "Antivirus": "#1E88E5",
    "Services": "#8E24AA",
    "Third-party Software": "#26A69A",
    "Device Protection": "#7C83FD",
}


def is_limited_visibility_scan(scan: dict[str, Any] | None) -> bool:
    data = scan or {}
    return bool(data.get("limited_visibility")) or str(data.get("scan_mode") or "").strip().lower() == "unauthenticated"


def analyze_software_risk(apps: list[dict[str, Any]] | None) -> list[dict[str, str]]:
    """Describe inventory visibility; a name or version alone is not a vulnerability assessment."""
    analysis: list[dict[str, str]] = []
    for app in apps or []:
        name = str(app.get("name") or "").strip()
        if not name:
            continue
        version = str(app.get("version") or "Unknown").strip() or "Unknown"
        missing = version.upper() in {"N/A", "UNKNOWN", "NONE"}
        reason = ("Version not available; security status could not be verified" if missing
                  else "Inventory only; security status has not been verified against advisories")
        analysis.append({"name": name, "version": version, "risk_level": "UNKNOWN", "reason": reason})
    return analysis

def filter_risky_apps(analysis: list[dict[str, Any]] | None) -> list[dict[str, str]]:
    """
    Returns only MEDIUM/HIGH software findings for scoring, export, and JSON output.
    """
    risky_apps: list[dict[str, str]] = []
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


def compute_component_scores(scan: dict[str, Any]) -> dict[str, int]:
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
    av_status = str(av.get("status") or "UNKNOWN").upper()
    if not av.get("error"):
        if not av.get("found") and av_status == "NOT FOUND":
            scores["Antivirus"] += 5
        elif av.get("found"):
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

    # A HotFix inventory is partial and neither age nor count establishes patch compliance.

    services = scan.get("services") or {}
    highlighted = services.get("highlighted") or []
    for item in highlighted:
        scores["Services"] += _severity_points(item.get("severity"), high=2, medium=1, low=1)

    protection = scan.get("device_protection") or {}
    for name in ("secure_boot", "system_drive_encryption"):
        if str((protection.get(name) or {}).get("state") or "").lower() == "disabled":
            scores["Device Protection"] += 2

    # Historical risky_apps can contain stale heuristics; inventory alone cannot
    # establish whether installed software has a known vulnerability.

    for k in scores:
        scores[k] = _clamp(scores[k])
    return scores


def compute_contributions(component_scores: dict[str, int]) -> dict[str, float]:
    total = sum(component_scores.values())
    if total <= 0:
        return {k: 0.0 for k in component_scores}
    return {k: (v / total) * 100.0 for k, v in component_scores.items()}


def summarize_risk_reason(scan: dict[str, Any]) -> str:
    scores = compute_component_scores(scan)
    if sum(scores.values()) <= 0:
        if is_limited_visibility_scan(scan):
            return "Limited attacker-view scan found no exposed monitored services."
        return "No scored issues identified in the available evidence; some checks may be incomplete."

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


def top_risk_drivers(scan: dict[str, Any], limit: int = 3) -> list[tuple[str, int, float]]:
    """
    Returns top contributing components as tuples:
    (component_name, points, percent_of_total)
    """
    scores = compute_component_scores(scan)
    perc = compute_contributions(scores)
    ordered = sorted(scores.items(), key=lambda item: item[1], reverse=True)
    out: list[tuple[str, int, float]] = []
    for name, points in ordered[:limit]:
        out.append((name, int(points), float(perc.get(name, 0.0))))
    return out


def risk_distribution(results: list[dict[str, Any]]) -> tuple[dict[str, int], dict[str, list[str]]]:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    names = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
    for r in results:
        lvl = str(r.get("risk_level") or "LOW").upper()
        if lvl not in counts:
            lvl = "LOW"
        counts[lvl] += 1
        names[lvl].append(str(r.get("hostname") or "Unknown"))
    return counts, names
