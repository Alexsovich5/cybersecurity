"""Filebeat -> Logstash -> Elasticsearch: fixture alerts become parsed documents.

The fixture appends every Snort fast-alert line and the OSSEC JSON alert to
the files Filebeat watches, each tagged with a marker that is unique to this
run, then looks the resulting documents up in Elasticsearch by that marker.
"""
import json
import os
import time
import uuid

import pytest
import requests

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FIXTURES = os.path.join(REPO, "tests", "fixtures")

ES_URL = os.environ.get("ES_URL", "http://elasticsearch:9200")
SNORT_ALERT = os.environ.get("SNORT_ALERT", "/lab/logs/snort/alert")
OSSEC_ALERTS = os.environ.get("OSSEC_ALERTS", "/lab/logs/ossec/alerts.json")

HEALTH_TIMEOUT = 120
DOC_TIMEOUT = 60


def wait_for_es(timeout=HEALTH_TIMEOUT):
    deadline = time.time() + timeout
    last_error = None
    while time.time() < deadline:
        try:
            resp = requests.get(
                ES_URL + "/_cluster/health",
                params={"wait_for_status": "yellow", "timeout": "5s"},
                timeout=10)
            if resp.status_code == 200 and resp.json()["status"] in ("yellow", "green"):
                return
            last_error = resp.text
        except requests.RequestException as exc:
            last_error = exc
        time.sleep(2)
    raise RuntimeError("Elasticsearch not healthy after {}s ({})".format(timeout, last_error))


def search(index, marker):
    """Return the _source of every document in INDEX whose message holds MARKER."""
    resp = requests.post(
        "{}/{}/_search".format(ES_URL, index),
        params={"ignore_unavailable": "true", "allow_no_indices": "true"},
        json={"size": 50, "query": {"match_phrase": {"message": marker}}},
        timeout=10)
    resp.raise_for_status()
    return [hit["_source"] for hit in resp.json()["hits"]["hits"]]


def wait_for_docs(index, marker, timeout=DOC_TIMEOUT):
    """Poll until at least one document for MARKER exists, then let late duplicates land."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        requests.post("{}/{}/_refresh".format(ES_URL, index),
                      params={"ignore_unavailable": "true", "allow_no_indices": "true"},
                      timeout=10)
        docs = search(index, marker)
        if docs:
            time.sleep(3)
            requests.post("{}/{}/_refresh".format(ES_URL, index),
                          params={"ignore_unavailable": "true", "allow_no_indices": "true"},
                          timeout=10)
            return search(index, marker)
        time.sleep(2)
    raise AssertionError("no document in {} for marker {} after {}s".format(index, marker, timeout))


def snort_lines():
    with open(os.path.join(FIXTURES, "snort_alert.fast")) as handle:
        return [line.rstrip("\n") for line in handle if line.strip()]


def ossec_alert():
    with open(os.path.join(FIXTURES, "ossec_alert.json")) as handle:
        return json.loads(handle.read().strip())


def append(path, lines):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a") as handle:
        for line in lines:
            handle.write(line + "\n")


@pytest.fixture(scope="module")
def shipped():
    """Inject the fixture lines and return {key: (index, marker, docs)}."""
    wait_for_es()
    run = uuid.uuid4().hex[:12]

    injected = {}
    snort_out = []
    for number, line in enumerate(snort_lines(), 1):
        marker = "m{}s{}".format(run, number)
        # The marker becomes the last word of the alert message, so the
        # line keeps the exact fast-alert layout the grok expects.
        tagged = line.replace(" [**] [Classification:", " " + marker + " [**] [Classification:", 1)
        assert tagged != line, "unexpected fast alert layout: " + line
        snort_out.append(tagged)
        injected["snort{}".format(number)] = ("security-snort-*", marker)

    alert = ossec_alert()
    marker = "m{}o1".format(run)
    alert["full_log"] = "{} {}".format(alert["full_log"], marker)
    injected["ossec1"] = ("security-ossec-*", marker)

    append(SNORT_ALERT, snort_out)
    append(OSSEC_ALERTS, [json.dumps(alert, separators=(",", ":"))])

    return {key: (index, marker, wait_for_docs(index, marker))
            for key, (index, marker) in injected.items()}


def docs_of(shipped, prefix):
    return [doc for key, (_, _, docs) in sorted(shipped.items()) if key.startswith(prefix)
            for doc in docs]


def test_snort_telnet_alert_is_parsed(shipped):
    docs = [doc for doc in docs_of(shipped, "snort") if doc.get("sid") == 1000002]
    assert len(docs) == 1, docs
    doc = docs[0]
    assert doc["log_type"] == "snort"
    assert doc["gid"] == 1
    assert doc["rev"] == 1
    assert doc["priority"] == 1
    assert doc["src_ip"] == "172.48.0.20"
    assert doc["dst_ip"] == "172.48.0.10"
    assert doc["src_port"] == 40000
    assert doc["dst_port"] == 23
    assert doc["proto"] == "TCP"
    assert doc["classification"] == "Attempted Administrator Privilege Gain"
    assert doc["alert_msg"].startswith("LAB telnet connection attempt")


def test_every_snort_sid_and_priority_arrives(shipped):
    got = sorted((doc["sid"], doc["priority"]) for doc in docs_of(shipped, "snort"))
    assert got == [(1000001, 3), (1000002, 1), (1000003, 2), (1000004, 1)]


def test_ossec_alert_fields_are_mapped(shipped):
    docs = docs_of(shipped, "ossec")
    assert len(docs) == 1, docs
    doc = docs[0]
    assert doc["log_type"] == "ossec"
    assert doc["rule_id"] == 100020
    assert doc["alert_level"] == 12
    assert doc["src_ip"] == "172.48.0.20"
    assert doc["alert_description"].startswith("SSH authentication failures")
    assert doc["message"].startswith("Jul 20 14:03:10 target sshd[2211]: Failed password")
    assert "json" not in doc
    assert "_ossec_time_fallback" not in doc.get("tags", [])
    assert doc["@timestamp"][5:10] == "07-20"


def test_each_line_gives_exactly_one_clean_document(shipped):
    for key, (index, marker, docs) in sorted(shipped.items()):
        assert len(docs) == 1, "{} ({}) produced {} documents".format(key, marker, len(docs))
        doc = docs[0]
        assert "_grokparsefailure" not in doc.get("tags", []), (key, doc)
        assert doc.get("hostname"), (key, doc)
        assert "host" not in doc, (key, doc)


def test_public_source_gets_geoip(shipped):
    docs = [doc for doc in docs_of(shipped, "snort") if doc.get("src_ip") == "8.8.8.8"]
    assert len(docs) == 1, docs
    assert docs[0]["geoip"]["country_code2"] == "US"
