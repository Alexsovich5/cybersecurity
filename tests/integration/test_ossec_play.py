"""The ossec play applied twice to every host (the target container in the
lab), then checked with testinfra
(run with --hosts=ansible://targets --sudo)."""
import pytest

from conftest import run_playbook

OSSEC_VERSION = "2.9.4"


@pytest.fixture(scope="module")
def recaps(lab_target):
    first = run_playbook("ossec")
    second = run_playbook("ossec")
    return first, second


def test_first_run_has_no_failures(recaps):
    first, _ = recaps
    assert first["target"]["failed"] == 0
    assert first["target"]["unreachable"] == 0


def test_second_run_changes_nothing(recaps):
    _, second = recaps
    assert second["target"]["failed"] == 0
    assert second["target"]["changed"] == 0


def test_init_conf_reports_version(recaps, host):
    init_conf = host.file("/etc/ossec-init.conf")
    assert init_conf.is_file
    assert 'VERSION="v{}"'.format(OSSEC_VERSION) in init_conf.content_string


def test_json_alert_output_enabled(recaps, host):
    conf = host.file("/var/ossec/etc/ossec.conf")
    assert conf.is_file
    assert "<jsonout_output>yes</jsonout_output>" in conf.content_string


def test_local_rules_deployed(recaps, host):
    rules = host.file("/var/ossec/rules/local_rules.xml")
    assert rules.is_file
    assert 'id="100020"' in rules.content_string


def test_rules_compile(recaps, host):
    out = host.run("/var/ossec/bin/ossec-logtest -t")
    assert out.rc == 0, out.stdout + out.stderr
