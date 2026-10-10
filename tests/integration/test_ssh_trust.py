"""Ansible verifies the target's SSH host key against the exported known_hosts.

The target writes its host public keys to /lab/keys/known_hosts at start,
and the lab inventory makes ssh use only that file with strict checking.
A forged or empty known_hosts must stop the connection before login.
"""
import os
import subprocess

from conftest import REPO

KNOWN_HOSTS = "/lab/keys/known_hosts"


def ping(extra_ssh_args=None):
    cmd = ["ansible", "target", "-m", "ping", "-o"]
    env = dict(os.environ)
    if extra_ssh_args is not None:
        cmd.extend(["-e", "ansible_ssh_common_args='{}'".format(extra_ssh_args)])
        # A fresh connection: no reuse of a ControlPersist master that was
        # opened with the real known_hosts.
        env["ANSIBLE_SSH_ARGS"] = "-o ControlMaster=no"
    proc = subprocess.run(cmd, cwd=REPO, env=env, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, universal_newlines=True)
    print(proc.stdout)
    return proc


def forged_known_hosts(tmpdir):
    """A known_hosts that names the target with a freshly generated key."""
    key = str(tmpdir.join("forged"))
    subprocess.check_call(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key])
    with open(key + ".pub") as handle:
        keytype, blob = handle.read().split()[:2]
    path = tmpdir.join("known_hosts")
    with open(KNOWN_HOSTS) as handle:
        names = set(line.split()[0] for line in handle if line.strip())
    path.write("".join("{} {} {}\n".format(name, keytype, blob) for name in sorted(names)))
    return str(path)


def test_exported_known_hosts_names_the_target(lab_target):
    with open(KNOWN_HOSTS) as handle:
        entries = [line.split() for line in handle if line.strip()]
    assert entries
    for names, keytype, _ in entries:
        assert "target" in names.split(",")
        assert keytype.startswith(("ssh-", "ecdsa-"))


def test_ping_succeeds_with_the_exported_host_keys(lab_target):
    proc = ping()
    assert proc.returncode == 0, proc.stdout
    assert "SUCCESS" in proc.stdout


def test_empty_known_hosts_refuses_the_target(lab_target, tmpdir):
    empty = tmpdir.join("empty_known_hosts")
    empty.write("")
    proc = ping("-o UserKnownHostsFile={} -o StrictHostKeyChecking=yes".format(empty))
    assert proc.returncode != 0
    assert "UNREACHABLE" in proc.stdout
    assert "Host key verification failed" in proc.stdout


def test_changed_host_key_refuses_the_target(lab_target, tmpdir):
    forged = forged_known_hosts(tmpdir)
    with open(forged) as handle:
        assert handle.read().strip(), "forged known_hosts is empty"
    proc = ping("-o UserKnownHostsFile={} -o StrictHostKeyChecking=yes "
                "-o HostKeyAlgorithms=ssh-ed25519".format(forged))
    assert proc.returncode != 0
    assert "UNREACHABLE" in proc.stdout
    assert "Host key verification failed" in proc.stdout or \
        "REMOTE HOST IDENTIFICATION HAS CHANGED" in proc.stdout
