#!/usr/bin/env python
"""Send recorded pfSense filterlog lines to a syslog receiver over UDP.

  pfsense_sim.py --host HOST [--port 5140] [--file FILE] [--rate N]

Each line of FILE is an RFC 3164 message such as

  <134>Jul 20 14:03:11 filterlog: 5,,,1000000103,em0,match,block,in,4,...

The timestamp is replaced with the current local time so the event lands
in today's index, and the rest of the line is sent unchanged, one line per
datagram. --rate is lines per second; 0 sends without pausing.
"""
import argparse
import datetime
import os
import re
import socket
import sys
import time

DEFAULT_PORT = 5140
DEFAULT_PRI = "<134>"  # facility local0, severity info, as pfSense sends it
DEFAULT_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "tests", "fixtures", "pfsense_filterlog.log")

MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
          "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

LINE = re.compile(r"^(<\d{1,3}>)?[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2} (.*)$")


def syslog_time(now):
    """Format NOW as an RFC 3164 timestamp, e.g. 'Aug  3 09:05:07'."""
    return "{} {:>2} {:02d}:{:02d}:{:02d}".format(
        MONTHS[now.month - 1], now.day, now.hour, now.minute, now.second)


def frame(line, now):
    """Return LINE as a syslog datagram with its timestamp set to NOW."""
    match = LINE.match(line.rstrip("\r\n"))
    if match is None:
        raise ValueError("not an RFC 3164 line: {!r}".format(line))
    pri = match.group(1) or DEFAULT_PRI
    return "{}{} {}".format(pri, syslog_time(now), match.group(2)).encode("utf-8")


def read_lines(path):
    with open(path) as handle:
        return [line.rstrip("\r\n") for line in handle if line.strip()]


def parse_args(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", required=True, help="syslog receiver (Logstash udp input)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--file", default=DEFAULT_FILE, help="filterlog lines to send")
    parser.add_argument("--rate", type=float, default=1.0,
                        help="lines per second, 0 for no pause")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    lines = read_lines(args.file)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for number, line in enumerate(lines):
            if number and args.rate > 0:
                time.sleep(1.0 / args.rate)
            sock.sendto(frame(line, datetime.datetime.now()), (args.host, args.port))
    finally:
        sock.close()
    return len(lines)


if __name__ == "__main__":
    print("sent {} lines".format(main()))
