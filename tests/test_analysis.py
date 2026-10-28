"""Tests for the scoring and threat-analysis engine.

These run on every platform: they work from the checked-in sample scan rather
than touching the host, so CI on Linux exercises the same code paths Windows
users get after a real scan.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from endpointradar import risk, threats
from endpointradar.cli import build_parser, main

SAMPLE = Path(__file__).resolve().parents[1] / "examples" / "sample-scan.json"


@pytest.fixture(scope="module")
def scan() -> dict:
    return json.loads(SAMPLE.read_text(encoding="utf-8"))[0]


# --------------------------------------------------------------------------
# Sample fixture
# --------------------------------------------------------------------------

def test_sample_scan_has_the_documented_shape(scan: dict) -> None:
    for key in ("hostname", "risk_score", "risk_level", "vulnerabilities", "antivirus", "firewall"):
        assert key in scan, f"sample scan is missing {key}"
    assert isinstance(scan["vulnerabilities"], list)


def test_sample_scan_is_anonymised() -> None:
    blob = SAMPLE.read_text(encoding="utf-8")
    for leak in ("192.168.1.", "DESKTOP-QK99KTV", "C:\\Users\\"):
        assert leak not in blob, f"sample scan leaks {leak!r}"


# --------------------------------------------------------------------------
# Risk scoring
# --------------------------------------------------------------------------

def test_component_scores_are_bounded(scan: dict) -> None:
    scores = risk.compute_component_scores(scan)
    assert scores, "expected at least one component"
    assert all(0 <= v <= 100 for v in scores.values()), scores


def test_contributions_sum_to_one_hundred(scan: dict) -> None:
    scores = risk.compute_component_scores(scan)
    total = sum(risk.compute_contributions(scores).values())
    assert total == pytest.approx(100.0, abs=0.01)


def test_contributions_handle_a_clean_machine() -> None:
    """A host with nothing wrong must not divide by zero."""
    contributions = risk.compute_contributions({"Firewall": 0, "Antivirus": 0})
    assert set(contributions.values()) == {0.0}


def test_top_risk_drivers_are_ordered(scan: dict) -> None:
    drivers = risk.top_risk_drivers(scan, limit=3)
    points = [points for _name, points, _pct in drivers]
    assert points == sorted(points, reverse=True)


def test_risk_distribution_counts_every_level() -> None:
    counts, names = risk.risk_distribution(
        [{"hostname": "a", "risk_level": "HIGH"}, {"hostname": "b", "risk_level": "LOW"}]
    )
    assert counts["HIGH"] == 1 and counts["LOW"] == 1
    assert names["HIGH"] == ["a"]


def test_unknown_risk_level_falls_back_to_low() -> None:
    counts, _ = risk.risk_distribution([{"hostname": "x", "risk_level": "BOGUS"}])
    assert counts["LOW"] == 1


def test_inventory_does_not_claim_software_risk_without_advisories() -> None:
    apps = [
        {"name": "Google Chrome", "version": "50.0.1"},
        {"name": "Java", "version": "99"},
        {"name": "Folder Tool", "version": "Unknown"},
    ]
    analysis = risk.analyze_software_risk(apps)
    assert [item["risk_level"] for item in analysis] == ["UNKNOWN"] * 3
    assert "not been verified" in analysis[0]["reason"]
    assert "not available" in analysis[2]["reason"]
    assert risk.filter_risky_apps(analysis) == []


def test_incomplete_inventory_does_not_add_risk_or_generate_threats() -> None:
    scan = {
        "antivirus": {"found": False, "status": "UNKNOWN", "error": "unavailable"},
        "patches": {"days_since_last_patch": 400, "total_patches": 0, "patch_warning": "unavailable"},
        "risky_apps": [{"name": "Java", "risk_level": "HIGH"}],
    }
    scores = risk.compute_component_scores(scan)
    assert scores["Antivirus"] == scores["Patching"] == scores["Third-party Software"] == 0
    assert not {"Antivirus", "OS / Patching", "Third-party Software"}.intersection(
        threat["category"] for threat in threats.generate_threats(scan)
    )
    assert "secure" not in risk.summarize_risk_reason(scan).lower()


def test_device_protection_scores_only_known_disabled_states() -> None:
    scan = {"device_protection": {"secure_boot": {"state": "disabled"}, "system_drive_encryption": {"state": "unknown"}}}
    assert risk.compute_component_scores(scan)["Device Protection"] == 2
    scan["device_protection"]["system_drive_encryption"]["state"] = "disabled"
    assert risk.compute_component_scores(scan)["Device Protection"] == 4
    assert risk.compute_component_scores({})["Device Protection"] == 0


# --------------------------------------------------------------------------
# Threat analysis
# --------------------------------------------------------------------------

def test_threats_respect_the_cap(scan: dict) -> None:
    assert len(threats.generate_threats(scan, max_threats=3)) <= 3


def test_every_threat_is_fully_populated(scan: dict) -> None:
    generated = threats.generate_threats(scan, max_threats=10)
    assert generated, "sample scan should raise at least one threat"
    for threat in generated:
        assert threat["risk_level"] in {"LOW", "MEDIUM", "HIGH"}
        assert threat["nist_function"] in {"Identify", "Protect", "Detect", "Respond", "Recover", "Govern"}
        assert threat["score"] == threat["likelihood"] * threat["impact"]
        assert 1 <= threat["likelihood"] <= 5
        assert 1 <= threat["impact"] <= 5
        assert threat["recommendation"].strip()


def test_threat_generation_is_deterministic(scan: dict) -> None:
    assert threats.generate_threats(scan) == threats.generate_threats(scan)


def test_empty_scan_does_not_crash_the_analysers() -> None:
    assert isinstance(threats.generate_threats({}), list)
    assert isinstance(risk.compute_component_scores({}), dict)


# --------------------------------------------------------------------------
# CLI plumbing
# --------------------------------------------------------------------------

def test_parser_exposes_every_documented_command() -> None:
    parser = build_parser()
    actions = [a for a in parser._actions if hasattr(a, "choices") and a.choices]
    commands = set()
    for action in actions:
        commands |= set(action.choices or {})
    for expected in ("scan", "discover", "sweep", "remote", "threats", "report", "show", "dashboard", "serve"):
        assert expected in commands


@pytest.mark.parametrize("order", [["-q", "show"], ["show", "-q"]])
def test_quiet_flag_works_on_both_sides_of_the_subcommand(order: list[str]) -> None:
    args = build_parser().parse_args([*order, "-i", str(SAMPLE)])
    assert args.quiet is True


def test_show_renders_the_sample(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["show", "-i", str(SAMPLE), "--no-color"])
    out = capsys.readouterr().out
    assert code == 0
    assert "WIN-DEMO-01" in out


def test_fail_on_threshold_sets_exit_code(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["show", "-i", str(SAMPLE), "--no-color", "--fail-on", "medium"]) == 2
    capsys.readouterr()
    assert main(["show", "-i", str(SAMPLE), "--no-color", "--fail-on", "critical"]) == 0


def test_threats_json_output_is_valid_json(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["threats", "-i", str(SAMPLE), "-f", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert isinstance(payload, list)


def test_missing_input_file_exits_cleanly(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["show", "-i", "does-not-exist.json", "--no-color"]) == 1
    assert "not found" in capsys.readouterr().err.lower()


def test_no_command_prints_help(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 0
    assert "usage: endpointradar" in capsys.readouterr().out
