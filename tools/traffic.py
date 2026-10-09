#!/usr/bin/env python
"""Write or send packets that match the local Snort rules, plus benign traffic.

  traffic.py write DIR [--src IP] [--dst IP]
  traffic.py send HOST [--only NAME]

Pcap names and the rule each one is built for:

  lab_probe   ICMP echo request carrying "LAB-PROBE"      SID 1000001
  telnet_syn  TCP SYN to port 23                          SID 1000002
  xmas_scan   TCP FIN+PSH+URG                             SID 1000003
  ssh_burst   6 TCP SYNs to port 22 from one source       SID 1000004
  benign      TCP handshake to 443 and a DNS query        no alert

Live sending is meant for the isolated compose network only.
"""
import argparse
import os
import socket
import sys
import time

from scapy.all import DNS, DNSQR, ICMP, IP, TCP, UDP, Raw, conf, send, wrpcap

DEFAULT_SRC = "172.48.0.20"
DEFAULT_DST = "172.48.0.10"
SSH_BURST_SIZE = 6
CLIENT_PORT = 40000


def lab_probe(src, dst):
    return [IP(src=src, dst=dst) / ICMP(type=8, id=0x4c41, seq=1) / Raw(load=b"LAB-PROBE")]


def telnet_syn(src, dst):
    return [IP(src=src, dst=dst) / TCP(sport=CLIENT_PORT, dport=23, flags="S", seq=1000)]


def xmas_scan(src, dst):
    return [IP(src=src, dst=dst) / TCP(sport=CLIENT_PORT + 1, dport=80, flags="FPU", seq=2000)]


def ssh_burst(src, dst):
    return [
        IP(src=src, dst=dst) / TCP(sport=CLIENT_PORT + 10 + i, dport=22, flags="S", seq=3000 + i)
        for i in range(SSH_BURST_SIZE)
    ]


def benign(src, dst):
    sport = CLIENT_PORT + 443
    return [
        IP(src=src, dst=dst) / TCP(sport=sport, dport=443, flags="S", seq=5000),
        IP(src=dst, dst=src) / TCP(sport=443, dport=sport, flags="SA", seq=9000, ack=5001),
        IP(src=src, dst=dst) / TCP(sport=sport, dport=443, flags="A", seq=5001, ack=9001),
        IP(src=src, dst=dst) / UDP(sport=CLIENT_PORT + 53, dport=53)
        / DNS(id=0x1234, rd=1, qd=DNSQR(qname="example.com", qtype="A")),
    ]


BUILDERS = [
    ("lab_probe", lab_probe),
    ("telnet_syn", telnet_syn),
    ("xmas_scan", xmas_scan),
    ("ssh_burst", ssh_burst),
    ("benign", benign),
]


def select(only=None):
    """Return the (name, builder) pairs to use, all of them when only is None."""
    if only is None:
        return list(BUILDERS)
    chosen = [pair for pair in BUILDERS if pair[0] == only]
    if not chosen:
        raise ValueError("unknown packet set: %s" % only)
    return chosen


def stamp(packets, start):
    """Give packets increasing capture times, 100 ms apart."""
    for index, packet in enumerate(packets):
        packet.time = start + index * 0.1
    return packets


def write(directory, src, dst):
    if not os.path.isdir(directory):
        os.makedirs(directory)
    start = time.time()
    paths = []
    for name, builder in BUILDERS:
        path = os.path.join(directory, name + ".pcap")
        wrpcap(path, stamp(builder(src, dst), start))
        paths.append(path)
    return paths


def send_live(host, only=None):
    dst = socket.gethostbyname(host)
    src = conf.route.route(dst)[1]
    for name, builder in select(only):
        packets = builder(src, dst)
        send(packets, verbose=0)
        print("sent %s: %d packet(s) to %s" % (name, len(packets), dst))


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Lab Snort traffic generator")
    commands = parser.add_subparsers(dest="command")
    commands.required = True

    write_cmd = commands.add_parser("write", help="write pcaps into DIR")
    write_cmd.add_argument("directory", metavar="DIR")
    write_cmd.add_argument("--src", default=DEFAULT_SRC)
    write_cmd.add_argument("--dst", default=DEFAULT_DST)

    send_cmd = commands.add_parser("send", help="send packets to HOST")
    send_cmd.add_argument("host", metavar="HOST")
    send_cmd.add_argument("--only", choices=[name for name, _ in BUILDERS])
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.command == "write":
        for path in write(args.directory, args.src, args.dst):
            print(path)
    else:
        send_live(args.host, args.only)
    return 0


if __name__ == "__main__":
    sys.exit(main())
