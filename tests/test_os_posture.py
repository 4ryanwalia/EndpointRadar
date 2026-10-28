"""Evidence-limited Windows posture checks; runs without Windows commands."""

import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("os_posture_test_module", Path(__file__).resolve().parents[1] / "src/endpointradar/os_check.py")
os_check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(os_check)


class PostureChecks(unittest.TestCase):
    def test_device_protection_is_strict_about_unknown_results(self):
        with patch.object(os_check, "_run_command", side_effect=[(0, "False", ""), (0, "Unknown", "")]):
            results = os_check.check_device_protection()
        self.assertEqual(results["secure_boot"]["state"], "disabled")
        self.assertEqual(results["system_drive_encryption"]["state"], "unknown")
        with patch.object(os_check, "_run_command", side_effect=[(1, "True", "error"), (0, "True", "")]):
            results = os_check.check_device_protection()
        self.assertEqual(results["secure_boot"]["state"], "unknown")
        self.assertEqual(results["system_drive_encryption"]["state"], "enabled")

    def test_passive_defender_does_not_override_third_party_antivirus(self):
        responses = [(0, "AntivirusEnabled=False\nRealTimeProtectionEnabled=False", ""),
                     (0, "Third Party AV  397568\nWindows Defender  397568", "")]
        with patch.object(os_check, "_run_command", side_effect=responses):
            result = os_check.check_antivirus()
        self.assertTrue(result["found"])
        self.assertIsNone(result["realtime_protection"])
        self.assertNotEqual(result["status"], "DISABLED")

    def test_antivirus_query_failure_is_unknown(self):
        with patch.object(os_check, "_run_command", return_value=(1, "", "access denied")):
            result = os_check.check_antivirus()
        self.assertFalse(result["found"])
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertTrue(result["error"])

    def test_low_hotfix_count_and_unknown_av_do_not_add_risk(self):
        mocks = (
            patch.object(os_check, "check_firewall_status", return_value={"profiles": {}}),
            patch.object(os_check, "detect_open_ports", return_value={"risky_open": []}),
            patch.object(os_check, "check_running_services", return_value={"highlighted": []}),
            patch.object(os_check, "check_device_protection", return_value={"secure_boot": {"state": "unknown"}, "system_drive_encryption": {"state": "unknown"}}),
            patch.object(os_check, "os_security_validation", return_value={"baseline_ok": True}),
            patch.object(os_check, "check_admin_privileges", return_value={"is_admin": False}),
        )
        from contextlib import ExitStack
        with ExitStack() as stack:
            for item in mocks:
                stack.enter_context(item)
            assessment = os_check.vulnerability_check({}, {"found": False, "status": "UNKNOWN", "error": "access denied"}, {"total_patches": 1, "days_since_last_patch": 60})
        self.assertEqual(assessment["risk_score"], 0)
        self.assertEqual([v["title"] for v in assessment["vulnerabilities"]], ["Review update status"])
        self.assertTrue(any("antivirus" in warning.lower() for warning in assessment["warnings"]))

    def test_disabled_protection_adds_only_confirmed_risk(self):
        with patch.object(os_check, "check_firewall_status", return_value={"profiles": {}}), \
             patch.object(os_check, "detect_open_ports", return_value={"risky_open": []}), \
             patch.object(os_check, "check_running_services", return_value={"highlighted": []}), \
             patch.object(os_check, "check_device_protection", return_value={"secure_boot": {"state": "disabled"}, "system_drive_encryption": {"state": "unknown"}}), \
             patch.object(os_check, "os_security_validation", return_value={"baseline_ok": True}), \
             patch.object(os_check, "check_admin_privileges", return_value={"is_admin": False}):
            assessment = os_check.vulnerability_check({}, {"found": True, "status": "ENABLED"}, {"total_patches": 1, "days_since_last_patch": 4})
        self.assertEqual(assessment["risk_score"], 2)
        self.assertEqual([v["title"] for v in assessment["vulnerabilities"]], ["Secure Boot is disabled"])


if __name__ == "__main__":
    unittest.main()
