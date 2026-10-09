"""Checks that the test image carries exactly the pinned tool versions."""
import os
import re
import subprocess

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
REQUIREMENTS = os.path.join(REPO, "requirements-dev.txt")
PIN = re.compile(r"^[A-Za-z0-9_.-]+==[0-9][^ ]*$")


def requirement_lines():
    with open(REQUIREMENTS) as handle:
        lines = [line.strip() for line in handle]
    return [line for line in lines if line and not line.startswith("#")]


def test_requirements_file_is_not_empty():
    assert len(requirement_lines()) > 0


def test_every_requirement_is_an_exact_pin():
    loose = [line for line in requirement_lines() if not PIN.match(line)]
    assert loose == []


def test_ansible_version():
    import ansible

    assert ansible.__version__ == "2.4.6.0"


def test_pytest_version():
    import pytest

    assert pytest.__version__ == "3.5.1"


def test_testinfra_imports():
    import testinfra

    assert hasattr(testinfra, "get_host")


def test_shellcheck_version():
    output = subprocess.check_output(["shellcheck", "--version"]).decode()
    assert "0.5.0" in output
