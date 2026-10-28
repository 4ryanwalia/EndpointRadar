"""Local dashboard security and saved-scan API checks."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("flask")
from endpointradar import server  # noqa: E402


def test_saved_findings_are_available_without_cross_origin_access(monkeypatch: pytest.MonkeyPatch) -> None:
    sample_path = Path(__file__).resolve().parents[1] / "examples" / "sample-scan.json"
    scan = json.loads(sample_path.read_text(encoding="utf-8"))[0]
    monkeypatch.setattr(server, "_load_results", lambda: [scan])
    monkeypatch.setattr(server, "_build_live_applications", lambda _scan: ([], "Test"))
    client = server.app.test_client()

    response = client.get("/device/10.0.0.51", headers={"Origin": "https://untrusted.example"})
    assert response.status_code == 200
    assert response.get_json()["scan"]["vulnerabilities"] == scan["vulnerabilities"]
    assert "Access-Control-Allow-Origin" not in response.headers


def test_zero_component_score_does_not_claim_security() -> None:
    scan = {"limited_visibility": True}
    assert all(card["status"] == "No risk scored" for card in server._build_component_cards(scan))
