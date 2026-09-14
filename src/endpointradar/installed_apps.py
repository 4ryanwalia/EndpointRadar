"""
Installed applications inventory (registry-based).

This is separate from the existing third-party software heuristics used for risk scoring.
"""

from __future__ import annotations

from typing import Any


def _safe_str(value: Any) -> str:
    if value is None:
        return ""
    try:
        s = str(value)
    except Exception:
        return ""
    return s.strip()


def _iter_apps_from_uninstall_path(root: Any, uninstall_key_path: str) -> list[dict[str, str]]:
    """
    Enumerates installed apps from a single uninstall registry path.
    """
    try:
        import winreg  # Windows-only
    except Exception:
        return []

    apps: list[dict[str, str]] = []
    try:
        base = winreg.OpenKey(root, uninstall_key_path)
    except Exception:
        return []

    try:
        subkey_count, _value_count, _last_modified = winreg.QueryInfoKey(base)
    except Exception:
        subkey_count = 0

    for i in range(subkey_count):
        try:
            subkey_name = winreg.EnumKey(base, i)
        except Exception:
            continue

        try:
            subkey = winreg.OpenKey(base, subkey_name)
        except Exception:
            continue

        try:
            display_name, _ = winreg.QueryValueEx(subkey, "DisplayName")
        except Exception:
            continue

        name = _safe_str(display_name)
        if not name:
            continue

        try:
            display_version, _ = winreg.QueryValueEx(subkey, "DisplayVersion")
            version = _safe_str(display_version) or "N/A"
        except Exception:
            version = "N/A"

        apps.append({"name": name, "version": version})

        try:
            winreg.CloseKey(subkey)
        except Exception:
            pass

    try:
        winreg.CloseKey(base)
    except Exception:
        pass

    return apps


def get_installed_apps() -> list[dict[str, str]]:
    """
    Collects installed applications from uninstall registry keys using Python (winreg).

    Iterates both:
    - SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall
    - SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall

    Returns a list of:
      {"name": "...", "version": "..."}
    """
    try:
        import winreg  # Windows-only
    except Exception:
        return []

    uninstall_paths: list[tuple[int, str]] = [
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        ),
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        ),
    ]

    all_apps: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for root, key_path in uninstall_paths:
        apps = _iter_apps_from_uninstall_path(root, key_path)
        for app in apps:
            key = (app["name"].lower(), app["version"])
            if key in seen:
                continue
            seen.add(key)
            all_apps.append(app)

    # Sort for consistent UI/exports.
    all_apps.sort(key=lambda a: a.get("name", "").lower())
    return all_apps

