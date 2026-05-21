from __future__ import annotations

from app.features import is_behavior_eligible


def test_excluded_reasons_for_control_plane():
    doc = {"session": {"flow_based": True, "excluded_from_behavior": True, "category": "control_plane", "noise_reasons": ["control_plane"]}}
    eligible, reasons = is_behavior_eligible(doc)
    assert eligible is False
    assert "session_excluded_from_behavior" in reasons
    assert "control_plane" in reasons


def test_flow_based_required():
    doc = {"session": {"flow_based": False}}
    eligible, reasons = is_behavior_eligible(doc)
    assert eligible is False
    assert "not_flow_based" in reasons


def test_unspecified_and_multicast_are_not_ml_eligible():
    doc = {
        "session": {"flow_based": True},
        "source": {"ip": "0.0.0.0"},
        "destination": {"ip": "224.0.0.22", "port": 0},
        "network": {"protocol": "unknown"},
    }
    eligible, reasons = is_behavior_eligible(doc)
    assert eligible is False
    assert "source_unspecified" in reasons
    assert "destination_multicast" in reasons
