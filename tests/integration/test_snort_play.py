"""The snort play applied twice to the ids_sensors group (the target
container in the lab), then checked with testinfra
(run with --hosts=ansible://targets --sudo)."""
import pytest

from conftest import run_playbook

SNORT_VERSION = "2.9.11.1"


@pytest.fixture(scope="module")
def recaps(lab_target):
    first = run_playbook("snort")
    second = run_playbook("snort")
    return first, second


def test_first_run_has_no_failures(recaps):
    first, _ = recaps
    assert first["target"]["failed"] == 0
    assert first["target"]["unreachable"] == 0


def test_second_run_changes_nothing(recaps):
    _, second = recaps
    assert second["target"]["failed"] == 0
    assert second["target"]["changed"] == 0


def test_snort_version(recaps, host):
    out = host.run("/usr/local/bin/snort -V 2>&1")
    assert out.rc == 0, out.stdout + out.stderr
    assert "Version {} ".format(SNORT_VERSION) in out.stdout


def test_snort_config_validates(recaps, host):
    out = host.run("/usr/local/bin/snort -T -q -c /etc/snort/snort.conf")
    assert out.rc == 0, out.stdout + out.stderr


def test_local_rules_deployed(recaps, host):
    rules = host.file("/etc/snort/rules/local.rules")
    assert rules.is_file
    assert "sid:1000004" in rules.content_string


def test_systemd_unit_rendered(recaps, host):
    unit = host.file("/etc/systemd/system/snort.service")
    assert unit.is_file
    assert "-c /etc/snort/snort.conf" in unit.content_string
    assert "-i eth0" in unit.content_string
