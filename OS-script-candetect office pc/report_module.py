"""
report_module.py

Generates a simple ISO-style Word report (report.docx) from scan results
using python-docx.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from docx import Document
from docx.enum.style import WD_STYLE_TYPE

import threat_analysis


def _ensure_list_style(document: Document, name: str = "Bullet List") -> None:
    """
    Ensures there is at least one bullet list style, for nicer bullets.
    Beginner-friendly: if anything fails, we just continue with defaults.
    """
    try:
        for style in document.styles:
            if style.type == WD_STYLE_TYPE.PARAGRAPH and "List" in style.name:
                return
    except Exception:
        return


def build_word_report(results: List[Dict[str, Any]], output_path: Path | str = "report.docx") -> Path:
    """
    Builds a Word report with sections:
    - Title Page
    - Executive Summary
    - Scope
    - Methodology
    - Findings
    - Risk Assessment
    - Recommendations
    """
    document = Document()
    _ensure_list_style(document)

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M")

    # Title page
    document.add_heading("Endpoint Security Assessment Report", level=0)
    document.add_paragraph(f"Generated: {now_str}")
    document.add_paragraph("Tool: Python Endpoint Security Scanner")
    document.add_page_break()

    # Executive Summary
    document.add_heading("Executive Summary", level=1)
    if not results:
        document.add_paragraph("No scan data was available at the time of report generation.")
    else:
        total = len(results)
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        for r in results:
            lvl = str(r.get("risk_level") or "UNKNOWN").upper()
            if lvl not in counts:
                lvl = "UNKNOWN"
            counts[lvl] += 1

        para = document.add_paragraph()
        para.add_run(
            f"This report summarizes the security posture of {total} system(s) "
            "based on local configuration and exposure checks."
        )

        bullet = document.add_paragraph(style="List Bullet")
        bullet.add_run(f"Critical risk systems: {counts['CRITICAL']}")
        bullet = document.add_paragraph(style="List Bullet")
        bullet.add_run(f"High risk systems: {counts['HIGH']}")
        bullet = document.add_paragraph(style="List Bullet")
        bullet.add_run(f"Medium risk systems: {counts['MEDIUM']}")
        bullet = document.add_paragraph(style="List Bullet")
        bullet.add_run(f"Low risk systems: {counts['LOW']}")

        document.add_paragraph(
            "Systems with high or critical risk should be reviewed and corrected as soon as possible."
        )

    # Scope
    document.add_heading("Scope", level=1)
    document.add_paragraph(
        "This assessment covers endpoint configuration and basic exposure checks on Windows systems. "
        "It focuses on antivirus status, patching, firewall configuration, open ports, and selected services."
    )

    # Methodology
    document.add_heading("Methodology", level=1)
    document.add_paragraph(
        "The tool performs local checks on each endpoint and assigns a risk score. "
        "It does not use vulnerability databases or CVE feeds; instead, it relies on "
        "system configuration signals that commonly indicate risk (for example, firewall "
        "disabled, exposed remote access ports, missing or outdated patches)."
    )

    # Findings
    document.add_heading("Findings", level=1)
    if not results:
        document.add_paragraph("No findings are available.")
    else:
        for r in results:
            hostname = r.get("hostname") or "Unknown"
            level = str(r.get("risk_level") or "UNKNOWN").upper()
            score = int(r.get("risk_score") or 0)

            document.add_heading(f"System: {hostname}", level=2)
            document.add_paragraph(f"Overall Risk Level: {level} (Score: {score})")

            vulns = r.get("vulnerabilities") or []
            if not vulns:
                document.add_paragraph("No specific vulnerabilities detected by local checks.")
                continue

            for v in vulns:
                title = v.get("title") or "Finding"
                sev = str(v.get("severity") or "INFO").upper()
                desc = v.get("description") or ""
                fix = v.get("fix") or ""

                p = document.add_paragraph(style="List Bullet")
                p.add_run(f"[{sev}] {title}").bold = True

                if desc:
                    document.add_paragraph(desc)
                if fix:
                    document.add_paragraph("Recommended action:", style="List Bullet")
                    document.add_paragraph(fix)

    # Risk Assessment
    document.add_heading("Risk Assessment", level=1)
    document.add_paragraph(
        "Risk levels (Low/Medium/High/Critical) are based on a numeric scoring "
        "model that adds points for missing antivirus, disabled protection, "
        "outdated patching, firewall settings, and exposed services."
    )

    # Threat Analysis (NIST aligned)
    document.add_heading("Threat Analysis", level=1)
    document.add_paragraph(
        "Endpoint Security Assessment Tool - Compliance: NIST SP 800-30 aligned risk scoring & NIST CSF 2.0 mapping"
    )
    if not results:
        document.add_paragraph("No scan data was available to generate threats.")
    else:
        for r in results:
            hostname = r.get("hostname") or "Unknown"
            document.add_heading(f"System: {hostname}", level=2)

            threats = []
            try:
                threats = threat_analysis.generate_threats(r, max_threats=10)
            except Exception:
                threats = []

            if not threats:
                document.add_paragraph("No threats were generated from the available local findings.")
                continue

            # Group by category for readability
            grouped: Dict[str, List[Dict[str, Any]]] = {}
            for t in threats:
                cat = str(t.get("category") or "Other")
                grouped.setdefault(cat, []).append(t)

            for cat, items in grouped.items():
                document.add_heading(cat, level=3)
                for t in items:
                    title = t.get("threat_title") or "Threat"
                    risk_level = str(t.get("risk_level") or "LOW").upper()
                    nist_func = t.get("nist_function") or "Protect"
                    desc = t.get("description") or ""
                    rec = t.get("recommendation") or ""

                    p = document.add_paragraph(style="List Bullet")
                    p.add_run(f"Threat: {title}").bold = True
                    document.add_paragraph(f"Risk: {risk_level} | NIST Function: {nist_func}")
                    if desc:
                        document.add_paragraph(f"Description: {desc}")
                    if rec:
                        document.add_paragraph(f"Recommendation: {rec}")

    # Recommendations
    document.add_heading("Recommendations", level=1)
    recs = [
        "Ensure Windows Firewall is enabled for all profiles unless a justified exception exists.",
        "Review and close unnecessary open ports, especially remote access and file-sharing services.",
        "Keep antivirus enabled with real-time protection and up-to-date signatures.",
        "Apply Windows Updates regularly and verify that patching is monitored.",
        "Disable or restrict remote administration services that are not strictly required.",
    ]
    for rtext in recs:
        document.add_paragraph(rtext, style="List Bullet")

    out_path = Path(output_path)
    document.save(str(out_path))
    return out_path


def build_threat_word_report(scan: Dict[str, Any], output_path: Path | str = "threat_report.docx") -> Path:
    """
    Builds a dedicated NIST-aligned threat analysis report for a single selected system.
    """
    document = Document()
    _ensure_list_style(document)

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M")
    hostname = str(scan.get("hostname") or "Unknown")
    risk_level = str(scan.get("risk_level") or "UNKNOWN").upper()
    risk_score = int(scan.get("risk_score") or 0)

    try:
        threats = threat_analysis.generate_threats(scan, max_threats=10)
    except Exception:
        threats = []

    severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    category_counts: Dict[str, int] = {}
    for threat in threats:
        level = str(threat.get("risk_level") or "LOW").upper()
        if level not in severity_counts:
            level = "LOW"
        severity_counts[level] += 1
        category = str(threat.get("category") or "Other")
        category_counts[category] = category_counts.get(category, 0) + 1

    document.add_heading("Endpoint Threat Analysis Report", level=0)
    document.add_paragraph(f"Generated: {now_str}")
    document.add_paragraph(f"System: {hostname}")
    document.add_paragraph("Compliance: NIST SP 800-30 aligned risk scoring & NIST CSF 2.0 mapping")
    document.add_page_break()

    document.add_heading("Executive Summary", level=1)
    document.add_paragraph(
        f"This report provides a focused threat analysis for {hostname}. "
        f"The current endpoint risk posture is {risk_level} with a score of {risk_score}. "
        "Threats in this report are derived from the scanner's endpoint findings and are presented as "
        "NIST-aligned scenarios with likelihood, impact, and response guidance."
    )
    document.add_paragraph(style="List Bullet").add_run(f"Total threats generated: {len(threats)}")
    document.add_paragraph(style="List Bullet").add_run(f"High severity threats: {severity_counts['HIGH']}")
    document.add_paragraph(style="List Bullet").add_run(f"Medium severity threats: {severity_counts['MEDIUM']}")
    document.add_paragraph(style="List Bullet").add_run(f"Low severity threats: {severity_counts['LOW']}")

    document.add_heading("NIST Alignment", level=1)
    document.add_paragraph(
        "This report follows the project's NIST-oriented threat model. Threat risk is estimated using a "
        "likelihood x impact approach aligned with NIST SP 800-30 concepts, while each threat is mapped to "
        "a NIST CSF 2.0 function to support governance, remediation planning, and audit discussions."
    )
    document.add_paragraph(style="List Bullet").add_run("Risk method: Likelihood x Impact scoring")
    document.add_paragraph(style="List Bullet").add_run("Threat presentation: Category, severity, description, recommendation")
    document.add_paragraph(style="List Bullet").add_run("Framework mapping: NIST CSF 2.0 function per threat")

    document.add_heading("Threat Summary", level=1)
    if not threats:
        document.add_paragraph("No threats were generated from the currently available endpoint findings.")
    else:
        document.add_paragraph(
            "The following categories produced threat scenarios during analysis. These categories are tied "
            "to observed local findings and are not based on external CVE enrichment."
        )
        for category, count in sorted(category_counts.items(), key=lambda item: item[0].lower()):
            document.add_paragraph(style="List Bullet").add_run(f"{category}: {count} threat(s)")

    document.add_heading("Threat Register", level=1)
    if not threats:
        document.add_paragraph("No threat entries are available for this system.")
    else:
        grouped: Dict[str, List[Dict[str, Any]]] = {}
        for threat in threats:
            category = str(threat.get("category") or "Other")
            grouped.setdefault(category, []).append(threat)

        for category, items in grouped.items():
            document.add_heading(category, level=2)
            for item in items:
                title = str(item.get("threat_title") or "Threat")
                level = str(item.get("risk_level") or "LOW").upper()
                likelihood = int(item.get("likelihood") or 0)
                impact = int(item.get("impact") or 0)
                score = int(item.get("score") or 0)
                nist_function = str(item.get("nist_function") or "Protect")
                description = str(item.get("description") or "")
                recommendation = str(item.get("recommendation") or "")

                entry = document.add_paragraph(style="List Bullet")
                entry.add_run(title).bold = True
                document.add_paragraph(
                    f"Risk Level: {level} | Likelihood: {likelihood} | Impact: {impact} | Score: {score} | NIST CSF Function: {nist_function}"
                )
                if description:
                    document.add_paragraph(f"Description: {description}")
                if recommendation:
                    document.add_paragraph(f"Recommendation: {recommendation}")

    document.add_heading("Recommended Actions", level=1)
    recommendations: List[str] = []
    for item in threats:
        recommendation = str(item.get("recommendation") or "").strip()
        if recommendation and recommendation not in recommendations:
            recommendations.append(recommendation)

    if recommendations:
        for recommendation in recommendations:
            document.add_paragraph(recommendation, style="List Bullet")
    else:
        document.add_paragraph("Continue standard hardening and monitoring controls for this endpoint.")

    out_path = Path(output_path)
    document.save(str(out_path))
    return out_path


if __name__ == "__main__":
    # Very small manual test when running this file directly.
    sample_results: List[Dict[str, Any]] = [
        {
            "hostname": "EXAMPLE-PC",
            "risk_score": 12,
            "risk_level": "HIGH",
            "vulnerabilities": [
                {
                    "title": "Windows Firewall OFF",
                    "severity": "HIGH",
                    "description": "Firewall disabled on Private profile.",
                    "fix": "Enable Windows Firewall for all profiles.",
                }
            ],
        }
    ]
    print(f"Writing example report to: {build_word_report(sample_results)}")
