"""correlate.py against a running Elasticsearch with synthetic indexed events.

Documents go straight into security-snort-test and security-ossec-test, so
they pick up the security-* template and are found by the same index
patterns as the live lab data. Each run uses its own 10.201.x.0/24 block
so live lab events and earlier runs never affect the assertions.
"""
import datetime
import json
import os
import random
import sys
import time

import pytest
import requests

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "tools"))

import correlate  # noqa: E402

ES_URL = os.environ.get("ES_URL", "http://elasticsearch:9200")
SNORT_INDEX = "security-snort-test"
OSSEC_INDEX = "security-ossec-test"
HEALTH_TIMEOUT = 180

BLOCK = "10.201.{}".format(random.randint(0, 255))
BOTH = BLOCK + ".1"         # Snort and OSSEC two minutes apart
SNORT_ONLY = BLOCK + ".2"   # Snort only
FAR_APART = BLOCK + ".3"    # Snort and OSSEC 45 minutes apart
URGENT = BLOCK + ".4"       # Snort priority 1 and OSSEC one minute apart


def wait_for_es(timeout=HEALTH_TIMEOUT):
    deadline = time.time() + timeout
    last_error = None
    while time.time() < deadline:
        try:
            resp = requests.get(ES_URL + "/_cluster/health",
                                params={"wait_for_status": "yellow", "timeout": "5s"},
                                timeout=10)
            if resp.status_code == 200 and resp.json()["status"] in ("yellow", "green"):
                return
            last_error = resp.text
        except requests.RequestException as exc:
            last_error = exc
        time.sleep(2)
    raise RuntimeError("Elasticsearch not healthy after {}s ({})".format(timeout, last_error))


def ago(minutes):
    stamp = datetime.datetime.utcnow() - datetime.timedelta(minutes=minutes)
    return stamp.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def snort_doc(ip, minutes, sid, priority):
    return {"@timestamp": ago(minutes), "log_type": "snort", "src_ip": ip,
            "dst_ip": "172.48.0.10", "sid": sid, "gid": 1, "rev": 1, "priority": priority,
            "alert_msg": "synthetic"}


def ossec_doc(ip, minutes, rule_id, level):
    return {"@timestamp": ago(minutes), "log_type": "ossec", "src_ip": ip,
            "rule_id": rule_id, "alert_level": level, "alert_description": "synthetic"}


DOCS = [
    (SNORT_INDEX, snort_doc(BOTH, 10, 1000004, 2)),
    (SNORT_INDEX, snort_doc(BOTH, 9, 1000002, 2)),
    (OSSEC_INDEX, ossec_doc(BOTH, 8, 100020, 12)),
    (SNORT_INDEX, snort_doc(SNORT_ONLY, 10, 1000002, 2)),
    (SNORT_INDEX, snort_doc(SNORT_ONLY, 9, 1000002, 2)),
    (SNORT_INDEX, snort_doc(FAR_APART, 50, 1000002, 2)),
    (OSSEC_INDEX, ossec_doc(FAR_APART, 5, 100020, 12)),
    (SNORT_INDEX, snort_doc(URGENT, 4, 1000001, 1)),
    (OSSEC_INDEX, ossec_doc(URGENT, 3, 5716, 5)),
]


@pytest.fixture(scope="module")
def indexed():
    wait_for_es()
    lines = []
    for index, doc in DOCS:
        lines.append(json.dumps({"index": {"_index": index, "_type": "doc"}}))
        lines.append(json.dumps(doc))
    resp = requests.post(ES_URL + "/_bulk", params={"refresh": "true"},
                         data="\n".join(lines) + "\n",
                         headers={"Content-Type": "application/x-ndjson"}, timeout=30)
    resp.raise_for_status()
    body = resp.json()
    assert not body["errors"], body
    yield
    requests.delete("{}/{},{}".format(ES_URL, SNORT_INDEX, OSSEC_INDEX), timeout=30)


def run(capsys, *args):
    code = correlate.main(["--es", ES_URL, "--since", "1h"] + list(args))
    return code, capsys.readouterr()


def ours(ips):
    return [ip for ip in ips if ip.startswith(BLOCK + ".")]


def test_json_reports_ips_seen_by_both_sensors_within_window(indexed, capsys):
    code, out = run(capsys, "--format", "json")
    assert code == 0, out.err
    results = [r for r in json.loads(out.out) if r["src_ip"].startswith(BLOCK + ".")]
    assert [r["src_ip"] for r in results] == [URGENT, BOTH]

    urgent, both = results
    assert urgent["min_priority"] == 1
    assert urgent["sids"] == [1000001]
    assert urgent["rule_ids"] == [5716]

    assert both["snort_count"] == 2
    assert both["ossec_count"] == 1
    assert both["sids"] == [1000002, 1000004]
    assert both["rule_ids"] == [100020]
    assert both["max_level"] == 12
    assert both["first_seen"] < both["last_seen"]


def test_min_events_three_drops_the_single_pair(indexed, capsys):
    code, out = run(capsys, "--format", "json", "--min-events", "3")
    assert code == 0, out.err
    assert ours(r["src_ip"] for r in json.loads(out.out)) == [BOTH]


def test_wider_window_picks_up_the_distant_pair(indexed, capsys):
    code, out = run(capsys, "--format", "json", "--window", "3600")
    assert code == 0, out.err
    assert ours(r["src_ip"] for r in json.loads(out.out)) == [URGENT, BOTH, FAR_APART]


def test_short_since_excludes_older_events(indexed, capsys):
    code, out = run(capsys, "--format", "json", "--since", "6m")
    assert code == 0, out.err
    assert ours(r["src_ip"] for r in json.loads(out.out)) == [URGENT]


def test_ansible_format_with_fail_on_match(indexed, capsys):
    code, out = run(capsys, "--format", "ansible", "--fail-on-match")
    assert code == 3
    block_ips = json.loads(out.out)["block_ips"]
    assert ours(block_ips) == [URGENT, BOTH]


def test_unreachable_elasticsearch_exits_1(capsys):
    code = correlate.main(["--es", "http://127.0.0.1:1", "--format", "json"])
    assert code == 1
    assert "Elasticsearch" in capsys.readouterr().err
