"""Checks the captured OSSEC JSON alert against the key set documented in SPEC 5.3."""
import json
import os

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FIXTURE = os.path.join(REPO, "tests", "fixtures", "ossec_alert.json")

TOP_LEVEL_KEYS = {
    "rule", "action", "srcip", "srcport", "srcuser", "dstip", "dstport",
    "dstuser", "location", "full_log", "file",
}
RULE_KEYS = {"level", "comment", "sidid", "cve", "info"}


def load_alert():
    with open(FIXTURE) as handle:
        lines = [line for line in handle.read().splitlines() if line.strip()]
    assert len(lines) == 1, "fixture holds exactly one alert line"
    return json.loads(lines[0])


def test_fixture_is_one_json_object():
    assert isinstance(load_alert(), dict)


def test_top_level_keys_are_documented():
    alert = load_alert()
    assert set(alert) <= TOP_LEVEL_KEYS, set(alert) - TOP_LEVEL_KEYS


def test_rule_keys_are_documented():
    rule = load_alert()["rule"]
    assert set(rule) <= RULE_KEYS, set(rule) - RULE_KEYS


def test_alert_is_the_brute_force_rule_from_the_lab_ip():
    alert = load_alert()
    assert alert["rule"]["sidid"] == 100020
    assert alert["rule"]["level"] == 12
    assert alert["srcip"] == "172.48.0.20"
    assert "Failed password for root" in alert["full_log"]
