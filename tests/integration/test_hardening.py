"""The hardening play applied twice to the target container, then checked
with testinfra (run with --hosts=ansible://targets --sudo)."""
import os

import pytest
import yaml

from conftest import ANSIBLE_DIR, run_playbook


def hardening_packages():
    with open(os.path.join(ANSIBLE_DIR, "group_vars", "all.yml")) as handle:
        return yaml.safe_load(handle)["hardening_packages"]


@pytest.fixture(scope="module")
def recaps(lab_target):
    first = run_playbook("hardening")
    second = run_playbook("hardening")
    return first, second


def test_first_run_has_no_failures(recaps):
    first, _ = recaps
    assert first["target"]["failed"] == 0
    assert first["target"]["unreachable"] == 0


def test_first_run_applies_changes_to_fresh_target(recaps):
    # make test-ansible recreates the target container before this suite.
    first, _ = recaps
    assert first["target"]["changed"] > 0


def test_second_run_changes_nothing(recaps):
    _, second = recaps
    assert second["target"]["failed"] == 0
    assert second["target"]["changed"] == 0


def test_sshd_effective_settings(recaps, host):
    out = host.run("/usr/sbin/sshd -T")
    assert out.rc == 0, out.stderr
    settings = set(out.stdout.splitlines())
    assert "permitrootlogin no" in settings
    assert "passwordauthentication no" in settings
    assert "maxauthtries 3" in settings


@pytest.mark.parametrize("nvr", hardening_packages())
def test_pinned_package_installed(recaps, host, nvr):
    out = host.run("rpm -q %s", nvr)
    assert out.rc == 0, out.stdout + out.stderr


def test_sysctl_drop_in(recaps, host):
    conf = host.file("/etc/sysctl.d/99-hardening.conf")
    assert conf.is_file
    assert "net.ipv4.tcp_syncookies = 1" in conf.content_string.splitlines()


def test_firewalld_drop_zone(recaps, host):
    zone = host.file("/etc/firewalld/zones/drop.xml")
    assert zone.is_file
    assert '<service name="ssh"/>' in zone.content_string
    conf = host.file("/etc/firewalld/firewalld.conf")
    assert "DefaultZone=drop" in conf.content_string.splitlines()


def test_shadow_mode(recaps, host):
    assert host.file("/etc/shadow").mode == 0o000
