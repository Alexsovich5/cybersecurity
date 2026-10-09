"""Checks the pcaps written by tools/traffic.py against the local Snort rules."""
import os
import sys

import pytest
from scapy.all import DNS, ICMP, IP, TCP, UDP, Raw, rdpcap

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "tools"))

import traffic  # noqa: E402

EXPECTED_FILES = [
    "lab_probe.pcap",
    "telnet_syn.pcap",
    "xmas_scan.pcap",
    "ssh_burst.pcap",
    "benign.pcap",
]


def flags_of(packet):
    return str(packet[TCP].flags)


@pytest.fixture
def pcaps(tmpdir):
    traffic.main(["write", str(tmpdir)])
    return tmpdir


def read(directory, name):
    return list(rdpcap(str(directory.join(name))))


def test_write_creates_every_pcap(pcaps):
    names = sorted(os.listdir(str(pcaps)))
    assert names == sorted(EXPECTED_FILES)


def test_pcaps_use_lab_source_ip(pcaps):
    for name in EXPECTED_FILES:
        packets = read(pcaps, name)
        outbound = [p for p in packets if p[IP].dst != "172.48.0.20"]
        assert outbound, name
        assert all(p[IP].src == "172.48.0.20" for p in outbound), name


def test_source_ip_can_be_overridden(tmpdir):
    traffic.main(["write", str(tmpdir), "--src", "10.9.8.7"])
    packets = read(tmpdir, "telnet_syn.pcap")
    assert packets[0][IP].src == "10.9.8.7"


def test_lab_probe_is_icmp_echo_with_payload(pcaps):
    packets = read(pcaps, "lab_probe.pcap")
    assert len(packets) == 1
    packet = packets[0]
    assert packet[ICMP].type == 8
    assert b"LAB-PROBE" in bytes(packet[Raw].load)


def test_telnet_syn_is_a_single_syn_to_port_23(pcaps):
    packets = read(pcaps, "telnet_syn.pcap")
    assert len(packets) == 1
    assert packets[0][TCP].dport == 23
    assert flags_of(packets[0]) == "S"


def test_xmas_scan_sets_fin_psh_urg(pcaps):
    packets = read(pcaps, "xmas_scan.pcap")
    assert len(packets) == 1
    assert flags_of(packets[0]) == "FPU"
    assert packets[0][TCP].dport not in (22, 23)


def test_ssh_burst_has_six_syns_to_port_22(pcaps):
    packets = read(pcaps, "ssh_burst.pcap")
    assert len(packets) == 6
    for packet in packets:
        assert packet[TCP].dport == 22
        assert flags_of(packet) == "S"
    assert len(set(p[IP].src for p in packets)) == 1


def test_benign_has_tls_handshake_and_dns_query(pcaps):
    packets = read(pcaps, "benign.pcap")
    tcp = [p for p in packets if TCP in p]
    assert [flags_of(p) for p in tcp] == ["S", "SA", "A"]
    assert tcp[0][TCP].dport == 443
    assert tcp[1][TCP].sport == 443
    dns = [p for p in packets if DNS in p]
    assert len(dns) == 1
    assert dns[0][UDP].dport == 53
    assert dns[0][DNS].qr == 0


def test_benign_never_touches_ssh_or_telnet(pcaps):
    for packet in read(pcaps, "benign.pcap"):
        layer = packet[TCP] if TCP in packet else packet[UDP]
        assert layer.dport not in (22, 23)


def test_benign_has_no_xmas_or_probe(pcaps):
    for packet in read(pcaps, "benign.pcap"):
        if TCP in packet:
            assert flags_of(packet) != "FPU"
        assert ICMP not in packet


def test_only_selects_one_packet_set():
    names = [name for name, _ in traffic.select("ssh_burst")]
    assert names == ["ssh_burst"]


def test_only_rejects_unknown_name():
    with pytest.raises(SystemExit):
        traffic.main(["send", "127.0.0.1", "--only", "nope"])


def test_send_uses_live_packets(monkeypatch):
    sent = []
    monkeypatch.setattr(traffic, "send", lambda packets, verbose=0: sent.extend(packets))
    traffic.main(["send", "172.48.0.10", "--only", "telnet_syn"])
    assert len(sent) == 1
    assert sent[0][IP].dst == "172.48.0.10"
    assert sent[0][TCP].dport == 23
