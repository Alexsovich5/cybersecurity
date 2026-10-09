"""Helpers for the integration suites that drive the lab containers."""
import os
import re
import socket
import subprocess
import time

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ANSIBLE_DIR = os.path.join(REPO, "ansible")
SITE_PLAYBOOK = os.path.join(ANSIBLE_DIR, "hardening.yml")
LAB_KEY = "/lab/keys/id_rsa"
LAB_INVENTORY = os.path.join(ANSIBLE_DIR, "inventory", "docker.ini")

RECAP_LINE = re.compile(r"^(?P<host>\S+)\s*:\s*(?P<counts>(?:\w+=\d+\s*)+)$")


def wait_for_ssh(host="target", port=22, key=LAB_KEY, timeout=120):
    """Wait until the lab key exists and HOST answers with an SSH banner."""
    deadline = time.time() + timeout
    last_error = None
    while time.time() < deadline:
        if os.path.exists(key):
            try:
                with socket.create_connection((host, port), timeout=5) as conn:
                    if conn.recv(64).startswith(b"SSH-"):
                        return
            except OSError as exc:
                last_error = exc
        time.sleep(2)
    raise RuntimeError(
        "no SSH on {}:{} with key {} after {}s ({})".format(
            host, port, key, timeout, last_error))


def parse_recap(output):
    """Return {host: {counter: int}} from the PLAY RECAP of OUTPUT."""
    recap = {}
    in_recap = False
    for line in output.splitlines():
        if line.startswith("PLAY RECAP"):
            in_recap = True
            continue
        if not in_recap:
            continue
        match = RECAP_LINE.match(line.strip())
        if not match:
            continue
        counts = {}
        for pair in match.group("counts").split():
            name, value = pair.split("=")
            counts[name] = int(value)
        recap[match.group("host")] = counts
    if not recap:
        raise AssertionError("no PLAY RECAP in output:\n" + output)
    return recap


def run_playbook(tags, playbook=SITE_PLAYBOOK, extra_args=()):
    """Run PLAYBOOK limited to TAGS and return its parsed PLAY RECAP."""
    if isinstance(tags, str):
        tags = [tags]
    cmd = ["ansible-playbook", playbook, "--tags", ",".join(tags)]
    cmd.extend(extra_args)
    proc = subprocess.run(
        cmd, cwd=REPO, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        universal_newlines=True)
    print(proc.stdout)
    return parse_recap(proc.stdout)


def pytest_configure(config):
    # testinfra's Ansible backend does not read the inventory from
    # ansible.cfg, so --hosts=ansible://GROUP resolves against the lab
    # inventory unless --ansible-inventory is given.
    if getattr(config.option, "ansible_inventory", None) is None:
        config.option.ansible_inventory = LAB_INVENTORY


@pytest.fixture(scope="session")
def lab_target():
    wait_for_ssh()
    return "target"
