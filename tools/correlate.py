#!/usr/bin/env python
"""Report source IPs that both Snort and OSSEC alerted on.

  correlate.py [--es http://elasticsearch:9200] [--since 15m] [--window 900]
               [--min-events 2] [--format table|json|ansible] [--fail-on-match]

Events from the last --since are read from security-snort-* and
security-ossec-*. An IP matches when at least one Snort event and one
OSSEC event from it lie within --window seconds of each other and it has
at least --min-events events in total. A warning goes to stderr when either
index returns no events, so a broken pipeline is not mistaken for a quiet
network.

Exit status: 0 ok, 3 matches found with --fail-on-match, 1 on an
Elasticsearch or usage error.
"""
import argparse
import datetime
import json
import logging
import re
import sys

try:
    from elasticsearch import Elasticsearch, helpers
    from elasticsearch.exceptions import ElasticsearchException
except ImportError:  # the library functions work without the client
    Elasticsearch = None
    helpers = None

    class ElasticsearchException(Exception):
        pass

SNORT_INDEX = "security-snort-*"
OSSEC_INDEX = "security-ossec-*"
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_MATCH = 3

SINCE = re.compile(r"^(\d+)([smhd])$")
SINCE_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}

TIMESTAMP = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})?$")


def parse_since(text):
    """Turn '30s', '15m', '2h' or '1d' into a timedelta."""
    match = SINCE.match(text or "")
    if not match:
        raise ValueError("invalid duration {!r}: expected a number followed by s, m, h or d"
                         .format(text))
    return datetime.timedelta(**{SINCE_UNITS[match.group(2)]: int(match.group(1))})


def parse_timestamp(text):
    """Parse an ISO 8601 timestamp into a naive UTC datetime."""
    match = TIMESTAMP.match(text)
    if not match:
        raise ValueError("invalid timestamp {!r}".format(text))
    year, month, day, hour, minute, second = (int(g) for g in match.groups()[:6])
    fraction = match.group(7) or "0"
    micro = int((fraction + "000000")[:6])
    value = datetime.datetime(year, month, day, hour, minute, second, micro)
    zone = match.group(8)
    if zone and zone != "Z":
        sign = -1 if zone[0] == "-" else 1
        digits = zone[1:].replace(":", "")
        offset = datetime.timedelta(hours=int(digits[:2]), minutes=int(digits[2:]))
        value -= sign * offset
    return value


def format_timestamp(value):
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def _by_ip(events):
    grouped = {}
    for event in events:
        ip = event.get("src_ip")
        if not ip:
            continue
        grouped.setdefault(ip, []).append((parse_timestamp(event["@timestamp"]), event))
    return grouped


def _within_window(snort_times, ossec_times, window):
    """True when some Snort time and some OSSEC time are WINDOW apart or less."""
    snort_times = sorted(snort_times)
    ossec_times = sorted(ossec_times)
    i = j = 0
    while i < len(snort_times) and j < len(ossec_times):
        if abs((snort_times[i] - ossec_times[j]).total_seconds()) <= window:
            return True
        if snort_times[i] < ossec_times[j]:
            i += 1
        else:
            j += 1
    return False


def _values(events, field):
    return sorted(set(int(e[field]) for _, e in events if e.get(field) is not None))


def correlate(snort_events, ossec_events, window_seconds, min_events):
    """Return one summary per source IP seen by both sensors within the window."""
    snort_by_ip = _by_ip(snort_events)
    ossec_by_ip = _by_ip(ossec_events)
    results = []
    for ip in set(snort_by_ip) & set(ossec_by_ip):
        snort_hits = snort_by_ip[ip]
        ossec_hits = ossec_by_ip[ip]
        if len(snort_hits) + len(ossec_hits) < min_events:
            continue
        if not _within_window([t for t, _ in snort_hits], [t for t, _ in ossec_hits],
                              window_seconds):
            continue
        times = [t for t, _ in snort_hits + ossec_hits]
        priorities = _values(snort_hits, "priority")
        levels = _values(ossec_hits, "alert_level")
        results.append({
            "src_ip": ip,
            "snort_count": len(snort_hits),
            "ossec_count": len(ossec_hits),
            "first_seen": format_timestamp(min(times)),
            "last_seen": format_timestamp(max(times)),
            "sids": _values(snort_hits, "sid"),
            "rule_ids": _values(ossec_hits, "rule_id"),
            "min_priority": priorities[0] if priorities else None,
            "max_level": levels[-1] if levels else None,
        })

    def order(result):
        priority = result["min_priority"]
        level = result["max_level"]
        return (priority is None, priority or 0, -(level or 0), result["src_ip"])

    return sorted(results, key=order)


def fetch_events(es, index_pattern, since, until):
    """Return the _source of every event with a src_ip stamped in [SINCE, UNTIL]."""
    query = {
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": format_timestamp(since),
                                              "lte": format_timestamp(until)}}},
                    {"exists": {"field": "src_ip"}},
                ]
            }
        }
    }
    return [hit["_source"] for hit in helpers.scan(
        es, query=query, index=index_pattern, ignore_unavailable=True)]


def format_table(results):
    if not results:
        return "No correlated source IPs."
    header = ("SRC_IP", "SNORT", "OSSEC", "PRIO", "LEVEL", "FIRST_SEEN", "LAST_SEEN",
              "SIDS", "RULE_IDS")
    rows = [header]
    for r in results:
        rows.append((
            r["src_ip"], str(r["snort_count"]), str(r["ossec_count"]),
            "-" if r["min_priority"] is None else str(r["min_priority"]),
            "-" if r["max_level"] is None else str(r["max_level"]),
            r["first_seen"], r["last_seen"],
            ",".join(str(s) for s in r["sids"]) or "-",
            ",".join(str(s) for s in r["rule_ids"]) or "-",
        ))
    widths = [max(len(row[i]) for row in rows) for i in range(len(header))]
    return "\n".join("  ".join(cell.ljust(w) for cell, w in zip(row, widths)).rstrip()
                     for row in rows)


def format_json(results):
    return json.dumps(results, indent=2, sort_keys=True)


def format_ansible(results):
    return json.dumps({"block_ips": [r["src_ip"] for r in results]})


FORMATTERS = {"table": format_table, "json": format_json, "ansible": format_ansible}


class UsageError(Exception):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise UsageError(message)


def non_negative_int(text):
    value = int(text)
    if value < 0:
        raise argparse.ArgumentTypeError("must be 0 or more: {}".format(text))
    return value


def positive_int(text):
    value = int(text)
    if value < 1:
        raise argparse.ArgumentTypeError("must be 1 or more: {}".format(text))
    return value


def build_parser():
    parser = _Parser(description="Report source IPs seen by both Snort and OSSEC.")
    parser.add_argument("--es", default="http://elasticsearch:9200",
                        help="Elasticsearch URL (default: %(default)s)")
    parser.add_argument("--since", default="15m",
                        help="how far back to look: 30s, 15m, 2h, 1d (default: %(default)s)")
    parser.add_argument("--window", type=non_negative_int, default=900,
                        help="max seconds between a Snort and an OSSEC event (default: %(default)s)")
    parser.add_argument("--min-events", type=positive_int, default=2,
                        help="min total events per IP (default: %(default)s)")
    parser.add_argument("--format", choices=sorted(FORMATTERS), default="table")
    parser.add_argument("--fail-on-match", action="store_true",
                        help="exit 3 when any IP matches")
    return parser


def main(argv=None):
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        since = parse_since(args.since)
    except (UsageError, ValueError) as exc:
        parser.print_usage(sys.stderr)
        sys.stderr.write("correlate.py: error: {}\n".format(exc))
        return EXIT_ERROR

    # The client logs every failed request with a traceback; the one-line
    # error below is enough.
    logging.getLogger("elasticsearch").addHandler(logging.NullHandler())
    logging.getLogger("elasticsearch").propagate = False

    until = datetime.datetime.utcnow()
    start = until - since
    es = Elasticsearch([args.es]) if Elasticsearch is not None else None
    try:
        snort_events = fetch_events(es, SNORT_INDEX, start, until)
        ossec_events = fetch_events(es, OSSEC_INDEX, start, until)
    except ElasticsearchException as exc:
        sys.stderr.write("correlate.py: Elasticsearch query failed: {}\n".format(exc))
        return EXIT_ERROR

    for name, events, index in (("Snort", snort_events, SNORT_INDEX),
                                ("OSSEC", ossec_events, OSSEC_INDEX)):
        if not events:
            sys.stderr.write("correlate.py: warning: no {} events with a src_ip in {} "
                             "over the last {}\n".format(name, index, args.since))

    results = correlate(snort_events, ossec_events, args.window, args.min_events)
    print(FORMATTERS[args.format](results))
    if results and args.fail_on_match:
        return EXIT_MATCH
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
