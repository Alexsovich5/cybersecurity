"""respond_block_ip.yml against the lab target, fed directly and by correlate.py.

firewalld is not running in the target container, so the playbook takes
its firewall-offline-cmd path and the rich rules land in the permanent
drop zone file, which is read back over SSH.
"""
import datetime
import json
import os
import subprocess
import sys
import time
import uuid

import pytest

from conftest import ANSIBLE_DIR, REPO, parse_recap

PLAYBOOK = os.path.join(ANSIBLE_DIR, "respond_block_ip.yml")
DROP_ZONE = "/etc/firewalld/zones/drop.xml"
CORRELATE = os.path.join(REPO, "tools", "correlate.py")
TRAFFIC = os.path.join(REPO, "tools", "traffic.py")
FIXTURES = os.path.join(REPO, "tests", "fixtures")

ES_URL = os.environ.get("ES_URL", "http://elasticsearch:9200")
OSSEC_INPUT = os.environ.get("OSSEC_INPUT", "/lab/ossec-input/secure")
SNORT_HOST = os.environ.get("SNORT_HOST", "snort")

DOC_IP = "203.0.113.9"
LAB_SRC = "172.48.0.20"
CORRELATE_TIMEOUT = 120


def run(cmd):
    proc = subprocess.run(cmd, cwd=REPO, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          universal_newlines=True)
    print(proc.stdout)
    return proc


def play(*extra):
    return run(["ansible-playbook", PLAYBOOK] + list(extra))


def block(ips, state="present"):
    proc = play("-e", json.dumps({"block_ips": ips, "block_state": state}))
    assert proc.returncode == 0, proc.stdout
    return parse_recap(proc.stdout)["target"]


def drop_zone():
    proc = run(["ansible", "target", "-b", "-m", "command", "-a", "cat " + DROP_ZONE])
    if proc.returncode != 0 and "No such file" in proc.stdout:
        return ""
    assert proc.returncode == 0, proc.stdout
    return proc.stdout


def rule_present(ip):
    return 'source address="{}"'.format(ip) in drop_zone()


def test_playbook_passes_ansible_lint_without_exceptions():
    with open(PLAYBOOK) as handle:
        assert "skip_ansible_lint" not in handle.read()
    proc = run(["ansible-lint", PLAYBOOK])
    assert proc.returncode == 0, proc.stdout


def test_block_adds_drop_rule_and_is_idempotent(lab_target):
    first = block([DOC_IP])
    assert first["failed"] == 0
    assert first["changed"] >= 1
    zone = drop_zone()
    assert 'source address="{}"'.format(DOC_IP) in zone
    assert "<drop/>" in zone

    second = block([DOC_IP])
    assert second["failed"] == 0
    assert second["changed"] == 0


def test_block_state_absent_removes_rule(lab_target):
    block([DOC_IP])
    assert rule_present(DOC_IP)
    removed = block([DOC_IP], state="absent")
    assert removed["changed"] >= 1
    assert not rule_present(DOC_IP)
    again = block([DOC_IP], state="absent")
    assert again["changed"] == 0


def test_invalid_ip_fails_at_the_assert(lab_target):
    proc = play("-e", json.dumps({"block_ips": ["not-an-ip"]}))
    assert proc.returncode != 0
    assert "Validate block list" in proc.stdout
    assert "not-an-ip" in proc.stdout
    assert parse_recap(proc.stdout)["target"]["changed"] == 0


def test_empty_block_list_fails_at_the_assert(lab_target):
    proc = play("-e", json.dumps({"block_ips": []}))
    assert proc.returncode != 0
    assert "Validate block list" in proc.stdout


@pytest.mark.parametrize("entry", [
    "0.0.0.0/0",        # every IPv4 source, including the management host
    "203.0.113.0/24",   # a network instead of one host
    "::/0",
    "127.0.0.1",        # loopback
    "::1",
    "0.0.0.0",          # unspecified
    "224.0.0.1",        # multicast
    "255.255.255.255",  # broadcast
])
def test_unsafe_entries_are_refused_before_any_change(lab_target, entry):
    proc = play("-e", json.dumps({"block_ips": [DOC_IP, entry]}))
    assert proc.returncode != 0
    assert "Validate block list entries" in proc.stdout
    assert entry in proc.stdout
    assert parse_recap(proc.stdout)["target"]["changed"] == 0
    assert not rule_present(entry)
    assert not rule_present(DOC_IP)


def test_never_block_list_protects_management_addresses(lab_target):
    proc = play("-e", json.dumps({"block_ips": [DOC_IP],
                                  "respond_never_block": ["203.0.113.0/28"]}))
    assert proc.returncode != 0
    assert "Validate block list entries" in proc.stdout
    assert parse_recap(proc.stdout)["target"]["changed"] == 0
    assert not rule_present(DOC_IP)


def correlated_ips():
    # stdout only: correlate.py writes warnings (such as an index with no
    # events yet) to stderr, and the blocklist must stay valid JSON.
    proc = subprocess.run([sys.executable, CORRELATE, "--es", ES_URL, "--since", "15m",
                           "--format", "ansible"], cwd=REPO, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, universal_newlines=True)
    print(proc.stdout, proc.stderr)
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


def syslog_now():
    now = datetime.datetime.utcnow()
    return "{:%b} {:>2} {:%H:%M:%S}".format(now, now.day, now)


def inject_lab_events():
    """Live Snort traffic plus the auth fixture restamped to the current time.

    Logstash dates OSSEC alerts from the syslog prefix of the log line, so
    the fixture's fixed timestamps would fall outside correlate.py's range.
    """
    proc = run([sys.executable, TRAFFIC, "send", SNORT_HOST, "--only", "ssh_burst"])
    assert proc.returncode == 0, proc.stdout
    marker = "r" + uuid.uuid4().hex[:12]
    with open(os.path.join(FIXTURES, "secure_auth_failures.log")) as handle:
        lines = [line.rstrip("\n") for line in handle if line.strip()]
    with open(OSSEC_INPUT, "a") as handle:
        for line in lines:
            handle.write("{}{} {}\n".format(syslog_now(), line[15:], marker))


@pytest.fixture
def blocklist(tmpdir):
    """correlate.py's Ansible vars once they include the lab source IP."""
    output = correlated_ips()
    if LAB_SRC not in json.loads(output)["block_ips"]:
        inject_lab_events()
        deadline = time.time() + CORRELATE_TIMEOUT
        while LAB_SRC not in json.loads(output)["block_ips"]:
            assert time.time() < deadline, "correlate.py never reported " + LAB_SRC
            time.sleep(5)
            output = correlated_ips()
    path = tmpdir.join("blocklist.json")
    path.write(output)
    yield str(path)
    play("-e", "@" + str(path), "-e", "block_state=absent")


def test_correlated_ips_are_blocked_on_target(lab_target, blocklist):
    proc = play("-e", "@" + blocklist)
    assert proc.returncode == 0, proc.stdout
    assert parse_recap(proc.stdout)["target"]["failed"] == 0
    assert rule_present(LAB_SRC)

    again = play("-e", "@" + blocklist)
    assert parse_recap(again.stdout)["target"]["changed"] == 0
