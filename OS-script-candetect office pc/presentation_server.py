from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any, Dict, List

from flask import Flask, abort, jsonify, render_template

import dashboard_data
import scanner_module
import threat_analysis


app = Flask(__name__, template_folder="templates")


@app.after_request
def add_cors_headers(response: Any) -> Any:
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
    return response


def _load_results() -> List[Dict[str, Any]]:
    results = scanner_module.load_scan_results()
    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    results.sort(
        key=lambda item: (
            risk_order.get(str(item.get("risk_level") or "UNKNOWN").upper(), 4),
            str(item.get("hostname") or scanner_module.get_device_id(item)).lower(),
        )
    )
    return results


def _device_identifier(scan: Dict[str, Any]) -> str:
    return str(scanner_module.get_device_id(scan) or scan.get("target_ip") or scan.get("hostname") or "Unknown")


def _connection_status(scan: Dict[str, Any]) -> str:
    raw_status = str(scan.get("connection_status") or "Unknown").strip()
    lowered = raw_status.lower()
    if lowered in {"local scan", "online", "scanned", "connected"}:
        return "Online"
    if "offline" in lowered:
        return "Offline"
    if "failed" in lowered:
        return "Connection Failed"
    return raw_status or "Unknown"


def _device_summary(scan: Dict[str, Any]) -> Dict[str, Any]:
    enriched_scan = scanner_module.enrich_device_metadata(scan)
    system_info = enriched_scan.get("system_info") or {}
    device_id = _device_identifier(enriched_scan)
    ip_address = str(enriched_scan.get("target_ip") or system_info.get("ip_address") or device_id).strip() or device_id
    return {
        "device_id": device_id,
        "hostname": str(enriched_scan.get("hostname") or system_info.get("hostname") or device_id),
        "ip_address": ip_address,
        "risk_level": str(enriched_scan.get("risk_level") or "UNKNOWN").upper(),
        "risk_score": int(enriched_scan.get("risk_score") or 0),
        "status": _connection_status(enriched_scan),
        "last_scan_at": enriched_scan.get("last_scan_at"),
        "device_type": str(enriched_scan.get("device_type") or "Unknown"),
        "device_type_label": str(
            enriched_scan.get("device_type_label") or scanner_module.describe_device_type(enriched_scan.get("device_type"))
        ),
        "scan_supported": bool(enriched_scan.get("scan_supported", True)),
    }


def _build_component_cards(scan: Dict[str, Any]) -> List[Dict[str, Any]]:
    scores = dashboard_data.compute_component_scores(scan)
    contributions = dashboard_data.compute_contributions(scores)
    firewall_profiles = scan.get("firewall", {}).get("profiles", {}) or {}
    firewall_off = [name for name in ("Domain", "Private", "Public") if str((firewall_profiles.get(name) or {}).get("state") or "").upper() == "OFF"]
    risky_ports = scan.get("open_ports", {}).get("risky_open", []) or []
    highlighted_services = scan.get("services", {}).get("highlighted", []) or []
    risky_apps = scan.get("risky_apps")
    if not isinstance(risky_apps, list):
        risky_apps = dashboard_data.filter_risky_apps(dashboard_data.analyze_software_risk(scan.get("installed_apps") or []))
    patches = scan.get("patches") or {}
    antivirus = scan.get("antivirus") or {}

    def _card(name: str, details: str) -> Dict[str, Any]:
        score = int(scores.get(name, 0))
        return {
            "name": name,
            "score": score,
            "contribution": round(float(contributions.get(name, 0.0)), 1),
            "status": "Risk Detected" if score > 0 else "Secure",
            "details": details,
        }

    return [
        _card("Firewall", f"Profiles off: {', '.join(firewall_off) if firewall_off else 'None'}"),
        _card(
            "SMB / Open Ports",
            f"Risky ports: {', '.join(str(item.get('port')) for item in risky_ports[:6]) if risky_ports else 'None'}",
        ),
        _card(
            "Patching",
            f"Days since last patch: {patches.get('days_since_last_patch', 'Unknown')} | Warning: {patches.get('patch_warning') or 'None'}",
        ),
        _card(
            "Antivirus",
            f"Status: {antivirus.get('status', 'UNKNOWN')} | Real-time: {antivirus.get('realtime_protection')}",
        ),
        _card(
            "Services",
            f"Highlighted services: {', '.join(str(item.get('name') or '') for item in highlighted_services[:6]) or 'None'}",
        ),
        _card("Third-party Software", f"Risky applications: {len(risky_apps)}"),
    ]


def _build_live_applications(scan: Dict[str, Any]) -> tuple[List[Dict[str, Any]], str]:
    if str(scan.get("connection_status") or "").strip().lower() == "local scan":
        try:
            return scanner_module.fetch_local_processes(limit=25), "Live snapshot collected from the local machine."
        except Exception as exc:
            return [], f"Unable to fetch live applications for the local machine: {exc}"
    return [], "Live monitoring is available in the desktop GUI. Saved remote scan results do not include active process snapshots."


def _find_scan(device_id: str) -> Dict[str, Any] | None:
    target = str(device_id or "").strip().lower()
    for scan in _load_results():
        candidates = {
            _device_identifier(scan).lower(),
            str(scan.get("target_ip") or "").strip().lower(),
            str(scan.get("hostname") or "").strip().lower(),
        }
        if target in candidates:
            return scan
    return None


@app.route("/")
def home() -> str:
    return render_template("dashboard.html")


@app.route("/devices")
def devices() -> Any:
    summaries = [_device_summary(scan) for scan in _load_results()]
    return jsonify({"devices": summaries})


@app.route("/device/<path:device_id>/live-applications")
def device_live_applications(device_id: str) -> Any:
    scan = _find_scan(device_id)
    if scan is None:
        abort(404, description="Device not found.")

    live_apps, live_note = _build_live_applications(scan)
    return jsonify(
        {
            "device_id": _device_identifier(scan),
            "live_applications": live_apps,
            "live_applications_note": live_note,
            "fetched_at": datetime.now().astimezone().isoformat(),
        }
    )


@app.route("/device/<path:device_id>")
def device_details(device_id: str) -> Any:
    scan = _find_scan(device_id)
    if scan is None:
        abort(404, description="Device not found.")

    scores = dashboard_data.compute_component_scores(scan)
    contributions = dashboard_data.compute_contributions(scores)
    threats = threat_analysis.generate_threats(scan, max_threats=10)
    threat_breakdown = dict(Counter(str(item.get("category") or "Other") for item in threats))
    live_apps, live_note = _build_live_applications(scan)
    top_drivers = [
        {"component": name, "points": points, "contribution": round(percent, 1)}
        for name, points, percent in dashboard_data.top_risk_drivers(scan, limit=3)
    ]

    payload = {
        "summary": _device_summary(scan),
        "risk_summary": dashboard_data.summarize_risk_reason(scan),
        "component_scores": scores,
        "component_contributions": contributions,
        "security_components": _build_component_cards(scan),
        "top_drivers": top_drivers,
        "threats": threats,
        "threat_category_breakdown": threat_breakdown,
        "live_applications": live_apps,
        "live_applications_note": live_note,
        "scan": scan,
    }
    return jsonify(payload)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
