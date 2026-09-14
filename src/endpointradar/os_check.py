"""Local Windows security posture checks.

Every function here uses only the standard library plus optional psutil, so
this module can be staged onto a remote host that has nothing installed.
"""

import ctypes
import platform
import re
import socket
import subprocess
import sys
from datetime import datetime, timezone


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


def _section(title: str) -> str:
    return f"\n{'=' * 78}\n{title}\n{'=' * 78}"


def _mark(level: str) -> str:
    """
    Visual markers for SOC-style reporting.
    """
    def can_print(s: str) -> bool:
        try:
            enc = sys.stdout.encoding or "utf-8"
            s.encode(enc, errors="strict")
            return True
        except Exception:
            return False

    level = (level or "").upper()
    if level in {"FAIL", "CRITICAL", "HIGH"}:
        return "❌" if can_print("❌") else "[X]"
    if level in {"WARN", "WARNING", "MEDIUM"}:
        return "⚠️" if can_print("⚠️") else "[!]"
    if level in {"OK", "PASS", "LOW"}:
        return "✅" if can_print("✅") else "[OK]"
    return "•"


def _risk_label(severity: str) -> str:
    """
    Clear risk labels for non-technical readers.
    """
    s = (severity or "").upper()
    if s == "HIGH":
        return "High Risk (Needs immediate action)"
    if s == "MEDIUM":
        return "Medium Risk (Should be fixed soon)"
    return "Low Risk (For awareness)"


def _overall_status_message(risk_level: str, score: int, top_reasons: list[str]) -> list[str]:
    """
    Creates a simple, manager-friendly overall summary.
    """
    lvl = (risk_level or "UNKNOWN").upper()
    lines: list[str] = []
    if lvl in {"CRITICAL", "HIGH"}:
        lines.append(f"{_mark('FAIL')} Overall Status: RISKY")
        lines.append("This device has security issues that could be exploited by attackers.")
    elif lvl == "MEDIUM":
        lines.append(f"{_mark('WARN')} Overall Status: NEEDS IMPROVEMENT")
        lines.append("This device is mostly OK, but some settings should be fixed soon to reduce risk.")
    else:
        lines.append(f"{_mark('OK')} Overall Status: GENERALLY SAFE")
        lines.append("No major high-risk issues were detected by these local checks.")

    lines.append(f"Risk Score: {score}  |  Risk Level: {lvl}")
    if top_reasons:
        lines.append("Main reasons:")
        for r in top_reasons[:5]:
            lines.append(f"  - {r}")
    lines.append("Note: Some results are based on automated system checks and may require manual verification.")
    return lines


def _safe_int(value: str | None) -> int | None:
    try:
        if value is None:
            return None
        return int(value)
    except Exception:
        return None


def _parse_hotfix_date(date_text: str) -> datetime | None:
    """
    Attempts to parse common InstalledOn formats from WMIC/Get-HotFix outputs.
    Returns a timezone-aware local datetime when possible.
    """
    if not date_text:
        return None
    s = str(date_text).strip()
    if not s:
        return None

    # Normalize common "00:00:00" time padding.
    s = re.sub(r"\s+00:00:00$", "", s)

    # Many environments outside the US use day-month-year. Prefer d-m-y first to reduce ambiguity.
    candidates = [
        "%d-%m-%Y",
        "%m-%d-%Y",
        "%m/%d/%Y",
        "%d/%m/%Y",
        "%Y-%m-%d",
        "%Y/%m/%d",
        "%d-%m-%y",
        "%m-%d-%y",
        "%m/%d/%y",
        "%d/%m/%y",
    ]
    for fmt in candidates:
        try:
            dt = datetime.strptime(s, fmt)
            return dt.replace(tzinfo=datetime.now().astimezone().tzinfo)
        except Exception:
            continue

    # Fallback: attempt to parse "03-03-2026 00:00:00" style.
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.now().astimezone().tzinfo)
        return dt
    except Exception:
        return None


def get_system_info() -> dict:
    info: dict = {}
    try:
        info["os_name"] = platform.system()
        info["os_version"] = platform.version()
        info["os_release"] = platform.release()
        info["platform"] = platform.platform()
    except Exception as e:
        info["os_error"] = str(e)

    try:
        hostname = socket.gethostname()
        info["hostname"] = hostname
        info["ip_address"] = socket.gethostbyname(hostname)
    except Exception as e:
        info["host_error"] = str(e)

    return info


def check_antivirus() -> dict:
    """
    Attempts to detect installed antivirus via Windows WMI (SecurityCenter2).
    Uses PowerShell/CIM first, falls back to WMIC where available.
    """
    result: dict = {
        "found": False,
        "products": [],
        "method": None,
        "error": None,
        # Real-world-ish validation signals (best effort):
        "status": "NOT FOUND",  # ENABLED / DISABLED / NOT FOUND / UNKNOWN
        "realtime_protection": None,  # True/False/None
        "details": [],
    }

    # Best signal for Microsoft Defender: Get-MpComputerStatus (works when Defender module is present).
    # This is optional; if it's not available, we continue with SecurityCenter2.
    mp_cmd = (
        "Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue | Out-Null; "
        "$s = Get-MpComputerStatus -ErrorAction SilentlyContinue; "
        "if ($null -ne $s) { "
        "  $avEnabled = $s.AntivirusEnabled; "
        "  $rtp = $s.RealTimeProtectionEnabled; "
        "  Write-Output (\"AntivirusEnabled={0}`nRealTimeProtectionEnabled={1}\" -f $avEnabled,$rtp) "
        "}"
    )
    code_mp, out_mp, _err_mp = _run_command(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", mp_cmd],
        timeout_s=20,
    )
    defender_av_enabled: bool | None = None
    defender_rtp: bool | None = None
    if code_mp == 0 and out_mp:
        for line in out_mp.splitlines():
            line = line.strip()
            if line.lower().startswith("antivirusenabled="):
                defender_av_enabled = line.split("=", 1)[1].strip().lower() == "true"
            if line.lower().startswith("realtimeprotectionenabled="):
                defender_rtp = line.split("=", 1)[1].strip().lower() == "true"

    # Preferred: PowerShell CIM query (WMI SecurityCenter2 namespace).
    ps_cmd = (
        "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct "
        "| Select-Object displayName,productState"
    )
    code, out, err = _run_command(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd],
        timeout_s=25,
    )
    if code == 0 and out:
        # We parse with a forgiving approach since table formatting can vary.
        lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
        # Skip header lines when table format is present.
        cleaned = [ln for ln in lines if ln.lower() not in {"displayname productstate"}]
        products: list[str] = []
        states: list[int] = []
        for ln in cleaned:
            # Common output looks like: "Windows Defender  397568"
            parts = re.split(r"\s{2,}", ln)
            if len(parts) >= 1:
                name = parts[0].strip()
                # Skip table separators like "-----"
                if name and name.lower() != "displayname" and not re.fullmatch(r"-{3,}", name):
                    products.append(name)
            if len(parts) >= 2:
                st = _safe_int(parts[1].strip())
                if st is not None:
                    states.append(st)

        if products:
            result.update({"found": True, "products": sorted(set(products)), "method": "PowerShell CIM (SecurityCenter2)"})

            # Decode SecurityCenter2 productState (best effort).
            # Many references treat productState as 3 bytes (0xAABBCC). The middle byte commonly indicates on/off.
            enabled_guess = None
            if states:
                enabled_flags = []
                for st in states:
                    hx = f"{st:06x}"
                    middle = int(hx[2:4], 16)
                    # Heuristic: 0x10/0x11 often indicates "on", 0x00 indicates "off".
                    if middle in (0x10, 0x11):
                        enabled_flags.append(True)
                    elif middle in (0x00, 0x01):
                        enabled_flags.append(False)
                if enabled_flags:
                    enabled_guess = any(enabled_flags)

            # Prefer Defender-specific status if we got it.
            if defender_av_enabled is not None:
                result["status"] = "ENABLED" if defender_av_enabled else "DISABLED"
            elif enabled_guess is True:
                result["status"] = "ENABLED"
            elif enabled_guess is False:
                result["status"] = "DISABLED"
            else:
                result["status"] = "UNKNOWN"

            if defender_rtp is not None:
                result["realtime_protection"] = defender_rtp
            result["details"].append("AV enabled/real-time status is best-effort; third-party AV reporting varies.")
            return result

    # Fallback: WMIC SecurityCenter2 (older Windows environments).
    wmic_cmd = r'wmic /namespace:\\root\SecurityCenter2 path AntiVirusProduct get displayName,productState /value'
    code, out, err2 = _run_command(["cmd", "/c", wmic_cmd], timeout_s=25)
    if code == 0 and out:
        products = []
        states = []
        for line in out.splitlines():
            line = line.strip()
            if not line or "=" not in line:
                continue
            k, v = line.split("=", 1)
            key = k.strip().lower()
            val = v.strip()
            if key == "displayname" and val:
                products.append(v.strip())
            if key == "productstate":
                st = _safe_int(val)
                if st is not None:
                    states.append(st)
        if products:
            result.update({"found": True, "products": sorted(set(products)), "method": "WMIC (SecurityCenter2)"})
            enabled_guess = None
            if states:
                enabled_flags = []
                for st in states:
                    hx = f"{st:06x}"
                    middle = int(hx[2:4], 16)
                    if middle in (0x10, 0x11):
                        enabled_flags.append(True)
                    elif middle in (0x00, 0x01):
                        enabled_flags.append(False)
                if enabled_flags:
                    enabled_guess = any(enabled_flags)

            if enabled_guess is True:
                result["status"] = "ENABLED"
            elif enabled_guess is False:
                result["status"] = "DISABLED"
            else:
                result["status"] = "UNKNOWN"
            return result

    combined_err = err or err2 or "No antivirus products detected (or access restricted)."
    result.update({"error": combined_err, "method": "PowerShell/WMIC", "status": "NOT FOUND"})
    return result


def check_patches() -> dict:
    """
    Lists installed Windows updates (HotFix IDs).
    Tries 'wmic qfe' first, then falls back to PowerShell 'Get-HotFix' on newer Windows.
    """
    result: dict = {
        "found": False,
        "hotfix_ids": [],
        "raw_table": [],
        "method": None,
        "error": None,
        # Advanced analysis fields:
        "total_patches": 0,
        "most_recent_patch_date": None,  # datetime
        "days_since_last_patch": None,  # int
        "patch_warning": None,
    }

    cmd = ["cmd", "/c", "wmic qfe get HotFixID,InstalledOn,Description /format:table"]
    code, out, err = _run_command(cmd, timeout_s=40)
    if code == 0 and out:
        result["method"] = "WMIC QFE"
        lines = [ln.rstrip() for ln in out.splitlines() if ln.strip()]
        result["raw_table"] = lines
        hotfixes = re.findall(r"\bKB\d{4,10}\b", out, flags=re.IGNORECASE)
        normalized = sorted({hf.upper() for hf in hotfixes})
        result["hotfix_ids"] = normalized
        result["found"] = len(normalized) > 0

    # Fallback for Windows 11 where WMIC may be missing.
    ps_cmd = (
        "Get-HotFix | Select-Object HotFixID,InstalledOn,Description "
        "| Format-Table -AutoSize"
    )
    code2, out2, err2 = _run_command(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd],
        timeout_s=40,
    )
    if (not result.get("raw_table")) and code2 == 0 and out2:
        result["method"] = "PowerShell Get-HotFix"
        lines = [ln.rstrip() for ln in out2.splitlines() if ln.strip()]
        result["raw_table"] = lines
        hotfixes = re.findall(r"\bKB\d{4,10}\b", out2, flags=re.IGNORECASE)
        normalized = sorted({hf.upper() for hf in hotfixes})
        result["hotfix_ids"] = normalized
        result["found"] = len(normalized) > 0

    if not result.get("raw_table"):
        result["error"] = (err or "") + (("\n" + err2) if err2 else "")
        if not result["error"].strip():
            result["error"] = "Failed to query installed updates using WMIC or PowerShell."
        result["method"] = "WMIC QFE / PowerShell Get-HotFix"
        return result

    # Advanced analysis of patch recency and patch counts.
    now = datetime.now(timezone.utc).astimezone()

    # Attempt to parse InstalledOn dates from the table lines.
    # We keep this flexible because WMIC / Get-HotFix output formatting differs by system locale.
    parsed_dates: list[datetime] = []
    for ln in result["raw_table"]:
        # Common pattern: "... 03-03-2026 ..." or "... 03/03/2026 ..."
        m = re.search(r"\b(\d{1,4}[/-]\d{1,2}[/-]\d{1,4})\b", ln)
        if not m:
            continue
        dt = _parse_hotfix_date(m.group(1))
        if dt is not None:
            parsed_dates.append(dt)

    result["total_patches"] = len(result.get("hotfix_ids") or [])
    if parsed_dates:
        most_recent = max(parsed_dates)
        result["most_recent_patch_date"] = most_recent
        result["days_since_last_patch"] = max(0, int((now - most_recent).days))

    # Warnings/heuristics (simple, transparent).
    patch_warnings: list[str] = []
    if result["total_patches"] == 0:
        patch_warnings.append("No patches were detected via HotFix listing; update visibility may be limited.")
    elif result["total_patches"] < 15:
        patch_warnings.append("Unusually low number of HotFix entries; the system may be missing updates.")

    if result["days_since_last_patch"] is None:
        patch_warnings.append("Could not determine most recent patch date from output.")
    elif result["days_since_last_patch"] > 30:
        patch_warnings.append("No updates detected in the last 30 days.")

    # If we have multiple warnings, we aggregate them into a single summary string.
    result["patch_warning"] = "; ".join(patch_warnings) if patch_warnings else None
    return result


def os_security_validation(system_info: dict) -> dict:
    """
    Compares the OS build against a simple expected secure baseline.
    This is a heuristic (not authoritative EOL validation).
    """
    os_name = (system_info.get("os_name") or "").lower()
    os_release = str(system_info.get("os_release") or "")
    os_version = str(system_info.get("os_version") or "")

    findings: list[str] = []
    baseline_ok = True
    baseline = "Unknown"

    if "windows" not in os_name:
        return {
            "baseline_ok": False,
            "baseline": "Windows-only baseline",
            "build": None,
            "findings": ["Non-Windows OS detected; Windows baseline checks not applicable."],
        }

    build = _safe_int(os_version.split(".")[-1]) if os_version else None
    rel = _safe_int(re.findall(r"\d+", os_release)[0]) if re.findall(r"\d+", os_release) else None

    # Conservative baselines to avoid false "outdated" on modern systems.
    # Windows 10: baseline build ~19045, Windows 11: baseline build ~22621.
    if rel == 10:
        baseline = "Windows 10 baseline build >= 19045"
        if build is None or build < 19045:
            baseline_ok = False
            findings.append("OS build is below the expected Windows 10 secure baseline.")
    elif rel == 11:
        baseline = "Windows 11 baseline build >= 22621"
        if build is None:
            baseline_ok = False
            findings.append("Could not determine Windows build number.")
        elif build < 22621:
            baseline_ok = False
            findings.append("OS build is below the expected Windows 11 secure baseline.")
    elif rel is None:
        baseline_ok = False
        findings.append("Unknown Windows release; unable to validate baseline.")
    else:
        baseline_ok = False
        findings.append("Unsupported/unknown Windows release detected.")

    return {"baseline_ok": baseline_ok, "baseline": baseline, "build": build, "findings": findings}


def vulnerability_check(system_info: dict, av_info: dict, patches_info: dict) -> dict:
    """
    Practical assessment: numeric scoring + local misconfiguration findings.
    Returns: numeric score, level (LOW/MEDIUM/HIGH/CRITICAL), warnings, and vulnerabilities.
    """
    warnings: list[str] = []
    vulnerabilities: list[dict] = []  # {severity, title, details, points, meaning, why, fix}

    score = 0

    def add_finding(
        severity: str,
        title: str,
        details: str,
        points: int,
        meaning: str,
        why: str,
        fix: str,
    ) -> None:
        nonlocal score
        vulnerabilities.append(
            {
                "severity": severity.upper(),
                "title": title,
                "details": details,
                "points": int(points),
                "meaning": meaning,
                "why": why,
                "fix": fix,
            }
        )
        score += int(points)

    # Collect local checks
    fw = check_firewall_status()
    ports = detect_open_ports()
    services = check_running_services()

    # 1) Firewall OFF → +5 (HIGH)
    if fw.get("error"):
        warnings.append("Unable to determine firewall status.")
    else:
        off_profiles = []
        for prof, data in (fw.get("profiles") or {}).items():
            if str((data or {}).get("state", "")).upper() == "OFF":
                off_profiles.append(prof)
        if off_profiles:
            add_finding(
                "HIGH",
                "Windows Firewall OFF",
                f"Firewall is OFF for profile(s): {', '.join(off_profiles)}.",
                5,
                "Your computer’s built-in network protection is turned off for at least one network type.",
                "A firewall blocks unwanted network traffic. If it’s off, attackers and malware can reach your device more easily.",
                "Turn on Windows Firewall for all profiles (Control Panel → Windows Defender Firewall, or Windows Security → Firewall & network protection).",
            )

    # 2) Open risky port → +3 each
    if ports.get("error"):
        warnings.append("Unable to enumerate listening ports.")
    else:
        for item in ports.get("risky_open", []) or []:
            p = item.get("port")
            sev = item.get("severity") or "MEDIUM"
            reason = item.get("reason") or "Risky port open."
            plain = ""
            fix = ""
            if p == 445:
                plain = "Port 445 is used for Windows file sharing (SMB). If it’s open, attackers can sometimes use it to spread malware across the network."
                fix = "If file sharing is not needed, disable SMB/file sharing. If needed, restrict it to trusted networks, block it on Public networks, and keep Windows fully updated."
            elif p == 3389:
                plain = "Port 3389 is used for Remote Desktop (RDP). If it’s open, attackers may try to guess passwords or exploit remote access."
                fix = "If you don’t need Remote Desktop, turn it off. If you do, restrict access (VPN, allow-list), enable MFA/NLA, and use strong passwords."
            elif p == 21:
                plain = "Port 21 is used for FTP. FTP often sends usernames/passwords without encryption."
                fix = "Disable FTP if unused. Prefer SFTP/FTPS. If required, restrict access and use strong credentials."
            elif p == 22:
                plain = "Port 22 is used for SSH (remote administration). Exposed SSH increases your remote attack surface."
                fix = "Disable SSH if unused. If required, restrict access, use key-based login, and block password login where possible."
            else:
                plain = "A network service is listening on a port that can increase exposure."
                fix = "Close/disable services you don’t need and restrict access using firewall rules."
            add_finding(
                "HIGH" if str(sev).upper() == "HIGH" else "MEDIUM",
                f"Risky port listening: {p}",
                reason,
                3,
                plain,
                "Open ports are like open doors on the network. Attackers scan for them to find targets.",
                fix,
            )

    # 3) Running services (highlight)
    if services.get("error"):
        warnings.append("Unable to enumerate running services.")
    else:
        for svc in services.get("highlighted", []) or []:
            name = svc.get("name")
            sev = svc.get("severity") or "MEDIUM"
            reason = svc.get("reason") or ""
            # Services are context signals; score lightly unless combined with exposed port.
            points = 2 if str(sev).upper() == "HIGH" else 1
            meaning = ""
            fix = ""
            if name == "LanmanServer":
                meaning = "The SMB file-sharing server is running on this device."
                fix = "If you don’t need file sharing, disable it. If needed, restrict sharing, disable SMBv1, and ensure firewall rules limit exposure."
            elif name == "TermService":
                meaning = "Remote Desktop Services is running."
                fix = "Disable Remote Desktop if not required. If required, restrict access (VPN/allow-list) and enable Network Level Authentication."
            elif name == "SSHD":
                meaning = "An SSH server is running (remote administration)."
                fix = "Disable SSH if unused. If needed, restrict access and use key-based authentication."
            elif name == "LanmanWorkstation":
                meaning = "The SMB client component is running (normal for many systems)."
                fix = "No action needed unless you are hardening SMB across the environment."
            else:
                meaning = "A service is running that can increase remote access or network exposure."
                fix = "Disable services you don’t need and restrict network access."
            add_finding(
                "MEDIUM" if str(sev).upper() != "HIGH" else "HIGH",
                f"Potentially risky service running: {name}",
                reason,
                points,
                meaning,
                "Unneeded services increase attack surface. If attackers find a weakness, a running service gives them something to target.",
                fix,
            )

    # 4) Patch-based vulnerability logic
    # - Outdated patches (>30 days) → +4
    # - Low patch count → warning (no extra points unless extremely low/zero)
    if not av_info.get("found"):
        warnings.append("No antivirus detected.")
        add_finding(
            "HIGH",
            "Antivirus not found",
            "No antivirus product detected via SecurityCenter2.",
            5,
            "No active antivirus product was detected on this system.",
            "Without antivirus, malware is more likely to run undetected and spread.",
            "Install a reputable antivirus product and confirm real-time protection is enabled.",
        )
    else:
        av_status = (av_info.get("status") or "UNKNOWN").upper()
        if av_status == "DISABLED":
            warnings.append("Antivirus appears disabled.")
            add_finding(
                "HIGH",
                "Antivirus disabled",
                "Antivirus is installed but appears disabled.",
                5,
                "Antivirus exists but is not currently active.",
                "Disabled antivirus removes a major protection layer against malware and malicious files.",
                "Enable antivirus immediately and verify policy/settings are not disabling it.",
            )
        elif av_status in {"UNKNOWN"}:
            warnings.append("Unable to confirm antivirus enabled status (best effort).")

        rtp = av_info.get("realtime_protection")
        if rtp is False:
            warnings.append("Real-time protection appears disabled.")
            add_finding(
                "MEDIUM",
                "Real-time protection disabled",
                "Real-time protection is OFF (best effort).",
                3,
                "The antivirus may not be scanning files continuously as they are opened or downloaded.",
                "Threats can execute before scheduled scans run, increasing compromise risk.",
                "Turn on real-time protection in your antivirus settings and validate policy enforcement.",
            )

    days_since = patches_info.get("days_since_last_patch")
    if days_since is None:
        warnings.append("Patch recency unknown.")
    elif days_since > 30:
        warnings.append("No updates detected in the last 30 days.")
        add_finding(
            "HIGH",
            "Outdated patching",
            f"Most recent patch appears {days_since} days old (> 30 days). System may be vulnerable due to outdated patching.",
            4,
            "Your computer may be missing recent security fixes.",
            "Attackers often use known bugs that have already been patched. If you are behind on updates, you are easier to exploit.",
            "Run Windows Update and install the latest updates. Consider enabling automatic updates.",
        )

    total_patches = int(patches_info.get("total_patches") or 0)
    if total_patches == 0:
        warnings.append("No patches detected by hotfix inventory.")
        add_finding(
            "HIGH",
            "Patch inventory empty",
            "No HotFix entries detected. System may be missing updates or inventory visibility is restricted.",
            4,
            "The system could not confirm installed updates.",
            "If updates can’t be verified, you may be missing important security patches without realizing it.",
            "Open Windows Update and confirm the device is up to date. If this is a managed device, verify update reporting with IT.",
        )
    elif total_patches < 15:
        score += 2
        warnings.append("Unusually low patch count.")
        # Keep as warning-level vulnerability signal
        add_finding(
            "MEDIUM",
            "Unusually low patch count",
            "Low HotFix count may indicate missing cumulative updates (or limited visibility).",
            1,
            "This device has fewer recorded updates than expected.",
            "A low patch count can mean the system is missing updates, or that update inventory is incomplete.",
            "Run Windows Update and verify patching. If inventory is managed by IT, confirm reporting is working.",
        )

    os_val = os_security_validation(system_info)
    if not os_val.get("baseline_ok"):
        findings = os_val.get("findings") or []
        for f in findings:
            warnings.append(f)
        add_finding(
            "HIGH",
            "OS baseline not met",
            "Detected OS build is below expected secure baseline or unsupported/unknown version.",
            5,
            "Your Windows version/build may be outdated or not supported.",
            "Older or unsupported versions may not receive critical security updates and are easier to compromise.",
            "Update Windows to a supported version/build and install the latest cumulative updates.",
        )

    # Admin context (INFO; no points)
    admin = check_admin_privileges()
    if admin.get("is_admin") is True:
        vulnerabilities.append(
            {
                "severity": "INFO",
                "title": "Script running as Administrator",
                "details": "Admin execution increases potential impact if the process is compromised.",
                "points": 0,
                "meaning": "This scan is running with full system privileges.",
                "why": "If malware or an attacker controls an admin-level process, they can make deeper system changes.",
                "fix": "Run tools as admin only when needed. For normal use, prefer running as a standard user.",
            }
        )
    elif admin.get("error"):
        warnings.append("Unable to determine admin privilege status.")

    # Map numeric score to level.
    if score >= 16:
        level = "CRITICAL"
    elif score >= 10:
        level = "HIGH"
    elif score >= 5:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "risk_score": score,
        "risk_level": level,
        "warnings": warnings,
        "vulnerabilities": vulnerabilities,
        "os_validation": os_val,
        "firewall": fw,
        "open_ports": ports,
        "services": services,
    }


def cve_api_placeholder() -> None:
    """
    Placeholder for future CVE API integration.
    Example future workflow:
      - Collect OS build + installed KBs
      - Query a CVE feed/API to map missing KBs/builds to known CVEs
      - Enrich report with CVE IDs, CVSS, and remediation guidance
    """
    return None


def check_admin_privileges() -> dict:
    """
    Checks whether the script is running with elevated (Administrator) privileges.
    Admin execution is not a vulnerability itself, but it increases impact if compromised.
    """
    try:
        is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
        return {"is_admin": is_admin, "error": None}
    except Exception as e:
        return {"is_admin": None, "error": str(e)}


def check_firewall_status() -> dict:
    """
    Checks Windows Firewall status using:
      netsh advfirewall show allprofiles
    Flags if any profile is OFF (Domain/Private/Public).
    """
    result: dict = {"profiles": {}, "any_off": False, "method": "netsh advfirewall", "error": None, "raw": None}
    code, out, err = _run_command(["cmd", "/c", "netsh advfirewall show allprofiles"], timeout_s=20)
    if code != 0 or not out:
        result["error"] = err or "Failed to query firewall status."
        return result

    result["raw"] = out

    current_profile = None
    for ln in out.splitlines():
        line = ln.strip()
        if not line:
            continue

        m = re.search(r"^(Domain|Private|Public)\s+Profile\s+Settings", line, flags=re.IGNORECASE)
        if m:
            current_profile = m.group(1).capitalize()
            result["profiles"].setdefault(current_profile, {"state": "UNKNOWN"})
            continue

        if current_profile:
            m2 = re.search(r"^State\s+(\w+)", line, flags=re.IGNORECASE)
            if m2:
                state = m2.group(1).upper()
                result["profiles"][current_profile]["state"] = state

    # Evaluate OFF profiles
    any_off = False
    for data in result["profiles"].values():
        if str(data.get("state", "")).upper() == "OFF":
            any_off = True
    result["any_off"] = any_off
    return result


def detect_open_ports() -> dict:
    """
    Lists listening ports and flags risky ports.

    Preferred: psutil (if installed) for accurate local listening sockets.
    Fallback: netstat -ano parsing if psutil is unavailable.
    """
    risky_ports = {
        3389: "RDP exposed can enable remote access/brute-force attempts.",
        445: "SMB exposed can increase risk of lateral movement and wormable exploits.",
        21: "FTP is often plaintext; exposed FTP can leak credentials/data.",
        22: "SSH exposed increases remote attack surface (verify hardening).",
    }

    result: dict = {
        "method": None,
        "listening_ports": [],  # sorted unique ints
        "risky_open": [],  # list of dicts: {port, severity, reason}
        "error": None,
    }

    ports: set[int] = set()

    # Attempt psutil first.
    try:
        import psutil  # type: ignore

        result["method"] = "psutil.net_connections()"
        for c in psutil.net_connections(kind="inet"):
            try:
                if getattr(c, "status", "").upper() != "LISTEN":
                    continue
                laddr = getattr(c, "laddr", None)
                if not laddr:
                    continue
                port = getattr(laddr, "port", None)
                if isinstance(port, int):
                    ports.add(port)
            except Exception:
                continue
    except Exception:
        # Fallback: netstat
        code, out, err = _run_command(["cmd", "/c", "netstat -ano -p tcp"], timeout_s=25)
        if code != 0 or not out:
            result["error"] = err or "Failed to enumerate open ports (psutil missing and netstat failed)."
            result["method"] = "psutil/netstat"
            return result

        result["method"] = "netstat -ano"
        for ln in out.splitlines():
            line = ln.strip()
            if not line.upper().startswith("TCP"):
                continue
            # Example: TCP  0.0.0.0:135  0.0.0.0:0  LISTENING  1234
            parts = re.split(r"\s+", line)
            if len(parts) < 4:
                continue
            local = parts[1]
            state = parts[3].upper() if len(parts) >= 4 else ""
            if state not in {"LISTENING", "LISTEN"}:
                continue
            m = re.search(r":(\d+)$", local)
            if not m:
                continue
            p = _safe_int(m.group(1))
            if p is not None:
                ports.add(p)

    result["listening_ports"] = sorted(ports)

    for p, reason in risky_ports.items():
        if p in ports:
            # Default severity: Medium; RDP/SMB generally treated higher.
            severity = "HIGH" if p in (3389, 445) else "MEDIUM"
            result["risky_open"].append({"port": p, "severity": severity, "reason": reason})

    return result


def check_running_services() -> dict:
    """
    Lists running Windows services and highlights commonly risky exposure services.

    Preferred: psutil.win_service_iter() (requires psutil).
    Fallback: PowerShell Get-Service.
    """
    highlights = {
        "TermService": "Remote Desktop Services (RDP). If running, ensure it is required and restricted.",
        "LanmanServer": "SMB Server service. If running, ensure SMB is needed and hardened.",
        "LanmanWorkstation": "SMB client service. Typically normal; note for SMB exposure context.",
        "SSHD": "OpenSSH server. If running, ensure hardened configuration and strong auth.",
    }

    result: dict = {"method": None, "running": [], "highlighted": [], "error": None}

    # psutil approach
    try:
        import psutil  # type: ignore

        result["method"] = "psutil.win_service_iter()"
        running = []
        for svc in psutil.win_service_iter():
            try:
                info = svc.as_dict()
                if str(info.get("status", "")).lower() == "running":
                    name = str(info.get("name") or "")
                    display = str(info.get("display_name") or name)
                    running.append({"name": name, "display_name": display})
            except Exception:
                continue
        result["running"] = running
    except Exception:
        # PowerShell fallback
        ps_cmd = "Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object -ExpandProperty Name"
        code, out, err = _run_command(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd],
            timeout_s=30,
        )
        if code != 0 or not out:
            result["error"] = err or "Failed to enumerate services."
            result["method"] = "psutil/PowerShell"
            return result
        result["method"] = "PowerShell Get-Service"
        names = [ln.strip() for ln in out.splitlines() if ln.strip()]
        result["running"] = [{"name": n, "display_name": n} for n in names]

    running_names = {svc["name"] for svc in result.get("running", []) if svc.get("name")}
    highlighted = []
    for name, why in highlights.items():
        if name in running_names:
            highlighted.append({"name": name, "severity": "MEDIUM" if name not in {"TermService", "LanmanServer"} else "HIGH", "reason": why})
    result["highlighted"] = highlighted
    return result


def build_text_report() -> str:
    """Run every local check and render the full plain-text posture report."""
    timestamp = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    report_lines: list[str] = []

    report_lines.append("WINDOWS ENDPOINT SECURITY SCAN REPORT")
    report_lines.append(f"Timestamp: {timestamp}")

    # High-level summary for non-technical readers
    # (We compute this after assessment, but print it near the top.)

    report_lines.append(_section("1) SYSTEM INFORMATION"))
    sysinfo = get_system_info()
    report_lines.append(f"Hostname   : {sysinfo.get('hostname', 'N/A')}")
    report_lines.append(f"IP Address : {sysinfo.get('ip_address', 'N/A')}")
    report_lines.append(f"OS Name    : {sysinfo.get('os_name', 'N/A')}")
    report_lines.append(f"OS Release : {sysinfo.get('os_release', 'N/A')}")
    report_lines.append(f"OS Version : {sysinfo.get('os_version', 'N/A')}")
    report_lines.append(f"Platform   : {sysinfo.get('platform', 'N/A')}")
    if sysinfo.get("os_error") or sysinfo.get("host_error"):
        report_lines.append(f"Info Errors: {sysinfo.get('os_error') or sysinfo.get('host_error')}")

    report_lines.append(_section("2) ANTIVIRUS (WMI / SecurityCenter2)"))
    av = check_antivirus()
    report_lines.append(f"Detection Method: {av.get('method', 'N/A')}")
    report_lines.append(f"Status          : {av.get('status', 'UNKNOWN')}")
    if av.get("realtime_protection") is True:
        report_lines.append("Real-Time Prot. : ENABLED")
    elif av.get("realtime_protection") is False:
        report_lines.append("Real-Time Prot. : DISABLED")
    else:
        report_lines.append("Real-Time Prot. : UNKNOWN")

    if av.get("found"):
        report_lines.append("Detected AV Products:")
        for name in av.get("products", []):
            report_lines.append(f"  - {name}")
    else:
        report_lines.append(f"{_mark('FAIL')} Antivirus: NOT FOUND")
        if av.get("error"):
            report_lines.append(f"Details: {av.get('error')}")
    for d in av.get("details", []):
        report_lines.append(f"Note: {d}")

    report_lines.append(_section("3) PATCH / UPDATE CHECK (HOTFIXES)"))
    patches = check_patches()
    report_lines.append(f"Detection Method: {patches.get('method', 'N/A')}")
    report_lines.append(f"Total Patches   : {patches.get('total_patches', 0)}")
    if patches.get("most_recent_patch_date"):
        dt = patches["most_recent_patch_date"]
        report_lines.append(f"Last Patch Date : {dt.strftime('%Y-%m-%d')}")
    else:
        report_lines.append("Last Patch Date : Unknown")
    if patches.get("days_since_last_patch") is not None:
        report_lines.append(f"Patch Recency   : {patches['days_since_last_patch']} days ago")
    else:
        report_lines.append("Patch Recency   : Unknown")

    if patches.get("patch_warning"):
        report_lines.append(f"{_mark('WARN')} Patch Warnings : {patches['patch_warning']}")
    if patches.get("raw_table"):
        report_lines.append("Installed Updates (summary table):")
        report_lines.extend([f"  {ln}" for ln in patches["raw_table"][:60]])
        if len(patches["raw_table"]) > 60:
            report_lines.append("  ... (truncated) ...")
    else:
        report_lines.append(f"{_mark('FAIL')} Installed Updates: Not available")
        if patches.get("error"):
            report_lines.append(f"Details: {patches.get('error')}")

    report_lines.append(_section("4) OS SECURITY VALIDATION"))
    os_val = os_security_validation(sysinfo)
    report_lines.append(f"Baseline        : {os_val.get('baseline', 'N/A')}")
    if os_val.get("build") is not None:
        report_lines.append(f"Detected Build  : {os_val.get('build')}")
    report_lines.append(f"Baseline Status : {'PASS' if os_val.get('baseline_ok') else 'FAIL'}")
    for f in os_val.get("findings", []):
        report_lines.append(f"{_mark('WARN')} {f}")

    report_lines.append(_section("5) RISK SCORING + VULNERABILITY ASSESSMENT"))
    assessment = vulnerability_check(sysinfo, av, patches)
    report_lines.append(f"Risk Score (0+) : {assessment['risk_score']}")
    report_lines.append(f"Risk Level      : {assessment['risk_level']}")

    if assessment.get("warnings"):
        report_lines.append("Warnings / Findings:")
        for w in assessment["warnings"]:
            sev = "WARN"
            if "disabled" in w.lower() or "not found" in w.lower() or "below" in w.lower():
                sev = "FAIL"
            report_lines.append(f"  {_mark(sev)} {w}")
    else:
        report_lines.append(f"{_mark('OK')} Warnings: None")

    report_lines.append(_section("6) FIREWALL STATUS (NETSH)"))
    fw = assessment.get("firewall") or {}
    if fw.get("error"):
        report_lines.append(f"{_mark('FAIL')} Firewall Status: Unknown")
        report_lines.append(f"Details: {fw.get('error')}")
    else:
        profiles = fw.get("profiles") or {}
        for prof in ["Domain", "Private", "Public"]:
            st = (profiles.get(prof) or {}).get("state", "UNKNOWN")
            sev = "OK" if str(st).upper() == "ON" else ("FAIL" if str(st).upper() == "OFF" else "WARN")
            report_lines.append(f"  {prof:<7} : {st} {_mark(sev)}")

    report_lines.append(_section("7) OPEN PORTS / EXPOSURE (LISTENING)"))
    ports = assessment.get("open_ports") or {}
    report_lines.append(f"Detection Method: {ports.get('method', 'N/A')}")
    if ports.get("error"):
        report_lines.append(f"{_mark('FAIL')} Listening Ports: Unknown")
        report_lines.append(f"Details: {ports.get('error')}")
    else:
        listening = ports.get("listening_ports") or []
        report_lines.append(f"Total Listening Ports: {len(listening)}")
        risky = ports.get("risky_open") or []
        if risky:
            report_lines.append("Risky Listening Ports:")
            for r in risky:
                sev = str(r.get("severity") or "MEDIUM").upper()
                report_lines.append(f"  {_mark(sev)} Port {r.get('port')}: {r.get('reason')}")
        else:
            report_lines.append(f"{_mark('OK')} No risky ports detected from the monitored list.")

    report_lines.append(_section("8) RUNNING SERVICES (HIGHLIGHTS)"))
    services = assessment.get("services") or {}
    report_lines.append(f"Detection Method: {services.get('method', 'N/A')}")
    if services.get("error"):
        report_lines.append(f"{_mark('FAIL')} Services: Unknown")
        report_lines.append(f"Details: {services.get('error')}")
    else:
        highlighted = services.get("highlighted") or []
        if highlighted:
            report_lines.append("Highlighted Services:")
            for s in highlighted:
                sev = str(s.get("severity") or "MEDIUM").upper()
                report_lines.append(f"  {_mark(sev)} {s.get('name')}: {s.get('reason')}")
        else:
            report_lines.append(f"{_mark('OK')} No highlighted risky services detected.")

    report_lines.append(_section("9) POTENTIAL VULNERABILITIES DETECTED"))
    vulns = assessment.get("vulnerabilities") or []
    if vulns:
        # Print in severity order: HIGH, MEDIUM, INFO
        order = {"HIGH": 0, "MEDIUM": 1, "INFO": 2}
        vulns_sorted = sorted(vulns, key=lambda x: order.get(str(x.get("severity", "")).upper(), 99))
        top_reasons = [str(v.get("title") or "") for v in vulns_sorted if str(v.get("severity", "")).upper() in {"HIGH", "MEDIUM"}]

        # Overall status near the bottom (and manager-friendly)
        report_lines.insert(2, _section("OVERALL SECURITY STATUS"))
        report_lines[3:3] = _overall_status_message(
            assessment.get("risk_level", "UNKNOWN"),
            int(assessment.get("risk_score") or 0),
            top_reasons,
        )

        for v in vulns_sorted:
            sev = str(v.get("severity") or "INFO").upper()
            pts = int(v.get("points") or 0)
            title = str(v.get("title") or "Finding")
            details = str(v.get("details") or "")
            report_lines.append(f"  {_mark(sev)} [{_risk_label(sev)}] (+{pts}) {title}")
            if details:
                report_lines.append(f"      - {details}")
            meaning = str(v.get("meaning") or "").strip()
            why = str(v.get("why") or "").strip()
            fix = str(v.get("fix") or "").strip()
            if meaning:
                report_lines.append("      What this means:")
                report_lines.append(f"        - {meaning}")
            if why:
                report_lines.append("      Why it matters:")
                report_lines.append(f"        - {why}")
            if fix:
                report_lines.append("      What you should do:")
                report_lines.append(f"        - {fix}")
            report_lines.append("")
    else:
        report_lines.append(f"{_mark('OK')} No potential vulnerabilities detected by local checks.")

    report_lines.append(_section("10) RECOMMENDATIONS (GENERAL)"))
    report_lines.append("  - Ensure Windows Update is enabled and fully patched.")
    report_lines.append("  - Ensure reputable antivirus is installed and up to date.")
    report_lines.append("  - Review local admin accounts and strong password policy.")
    report_lines.append("  - Enable firewall and disk encryption where possible.")
    report_lines.append("")
    report_lines.append("Friendly note: This report is generated from local system checks. Some items (especially third-party antivirus status and patch visibility) may require manual verification.")

    return "\n".join(report_lines) + "\n"


def main() -> None:
    """Print the posture report and save a copy to report.txt."""
    report = build_text_report()
    # Make console output robust on Windows terminals with legacy codepages.
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    print(report)

    try:
        with open("report.txt", "w", encoding="utf-8") as f:
            f.write(report)
        print("Report saved to: report.txt")
    except Exception as e:
        print(f"Failed to save report.txt: {e}")


if __name__ == "__main__":
    main()
