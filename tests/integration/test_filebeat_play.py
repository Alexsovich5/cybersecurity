"""The filebeat play applied twice to every host (the target container in
the lab), then checked with testinfra
(run with --hosts=ansible://targets --sudo)."""
import pytest

from conftest import run_playbook

ELASTIC_VERSION = "6.3.2"
CONFIG = "/etc/filebeat/filebeat.yml"


@pytest.fixture(scope="module")
def recaps(lab_target):
    first = run_playbook("filebeat")
    second = run_playbook("filebeat")
    return first, second


def test_first_run_has_no_failures(recaps):
    first, _ = recaps
    assert first["target"]["failed"] == 0
    assert first["target"]["unreachable"] == 0


def test_second_run_changes_nothing(recaps):
    _, second = recaps
    assert second["target"]["failed"] == 0
    assert second["target"]["changed"] == 0


def test_filebeat_package_version(recaps, host):
    package = host.package("filebeat")
    assert package.is_installed
    assert package.version == ELASTIC_VERSION


def test_filebeat_config_validates(recaps, host):
    out = host.run(
        "/usr/share/filebeat/bin/filebeat test config -c {} "
        "-path.home /usr/share/filebeat".format(CONFIG))
    assert out.rc == 0, out.stdout + out.stderr


def test_filebeat_config_mode(recaps, host):
    config = host.file(CONFIG)
    assert config.is_file
    assert config.mode == 0o600


def test_filebeat_config_is_the_shared_one(recaps, host):
    config = host.file(CONFIG)
    assert "log_type: ossec" in config.content_string
    assert "${LOGSTASH_HOST:" in config.content_string


def test_logstash_host_passed_to_the_service(recaps, host):
    dropin = host.file("/etc/systemd/system/filebeat.service.d/logstash.conf")
    assert dropin.is_file
    assert "LOGSTASH_HOST=logstash:5044" in dropin.content_string
