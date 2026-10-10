"""Checks the syslog framing and UDP sending of tools/pfsense_sim.py."""
import datetime
import os
import socket
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "tools"))

import pfsense_sim  # noqa: E402

FIXTURE = os.path.join(REPO, "tests", "fixtures", "pfsense_filterlog.log")
NOW = datetime.datetime(2018, 8, 3, 9, 5, 7)


def fixture_lines():
    with open(FIXTURE) as handle:
        return [line.rstrip("\n") for line in handle if line.strip()]


def body(line):
    """Everything from the program name on, as bytes."""
    data = line.encode("utf-8") if isinstance(line, str) else line
    return data[data.index(b"filterlog:"):]


def test_fixture_holds_three_ipv4_lines_and_one_ipv6_line():
    versions = [body(line).split(b",")[8] for line in fixture_lines()]
    assert versions == [b"4", b"4", b"4", b"6"]


def test_frame_starts_with_local0_info_priority():
    for line in fixture_lines():
        assert pfsense_sim.frame(line, NOW).startswith(b"<134>")


def test_frame_adds_priority_when_missing():
    line = "Jul 20 14:03:11 filterlog: 5,,,1000000103,em0,match,block,in,4"
    assert pfsense_sim.frame(line, NOW) == b"<134>Aug  3 09:05:07 filterlog: 5,,,1000000103,em0,match,block,in,4"


def test_frame_rewrites_timestamp_to_now():
    line = fixture_lines()[0]
    framed = pfsense_sim.frame(line, NOW)
    assert framed.startswith(b"<134>Aug  3 09:05:07 filterlog: ")
    assert b"Jul 20 14:03:11" not in framed
    two_digit_day = pfsense_sim.frame(line, datetime.datetime(2018, 8, 21, 23, 59, 1))
    assert two_digit_day.startswith(b"<134>Aug 21 23:59:01 filterlog: ")


def test_frame_keeps_csv_body_byte_for_byte():
    for line in fixture_lines():
        assert body(pfsense_sim.frame(line, NOW)) == body(line)


def test_frame_rejects_line_without_timestamp():
    with pytest.raises(ValueError):
        pfsense_sim.frame("filterlog: 5,,,1000000103", NOW)


def test_main_sends_each_line_as_one_datagram(tmpdir):
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.bind(("127.0.0.1", 0))
    receiver.settimeout(5)
    port = receiver.getsockname()[1]
    source = tmpdir.join("filterlog.log")
    source.write("\n".join(fixture_lines()[:2]) + "\n\n")
    try:
        sent = pfsense_sim.main(["--host", "127.0.0.1", "--port", str(port),
                                 "--file", str(source), "--rate", "0"])
        got = [receiver.recv(4096) for _ in range(2)]
    finally:
        receiver.close()
    assert sent == 2
    assert [body(datagram) for datagram in got] == [body(line) for line in fixture_lines()[:2]]
    assert all(datagram.startswith(b"<134>") for datagram in got)
    assert all(not datagram.endswith(b"\n") for datagram in got)
