"""Live lab: sniffed traffic and injected auth logs reach Elasticsearch.

The tests container (172.48.0.20) sends packets at the snort sensor
(172.48.0.10), which sniffs its own interface on the lab bridge, and
appends sshd failures to the file the ossec container watches. No alert
file is written by hand: every document comes from Snort or OSSEC.
"""
import datetime
import os
import subprocess
import sys
import time
import uuid

import pytest
import requests

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FIXTURES = os.path.join(REPO, "tests", "fixtures")
TRAFFIC = os.path.join(REPO, "tools", "traffic.py")

ES_URL = os.environ.get("ES_URL", "http://elasticsearch:9200")
OSSEC_INPUT = os.environ.get("OSSEC_INPUT", "/lab/ossec-input/secure")
SNORT_HOST = os.environ.get("SNORT_HOST", "snort")

LAB_SRC = "172.48.0.20"
SENSOR_IP = "172.48.0.10"
HEALTH_TIMEOUT = 180
# Logstash start-up on a loaded host can take several minutes.
DOC_TIMEOUT = 60
LOGSTASH_TIMEOUT = 300


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


def wait_for_template(name="security", timeout=LOGSTASH_TIMEOUT):
    """Logstash installs the template once its pipeline has started."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if requests.get("{}/_template/{}".format(ES_URL, name), timeout=10).status_code == 200:
                return
        except requests.RequestException:
            pass
        time.sleep(2)
    raise RuntimeError("index template {} not installed after {}s".format(name, timeout))


def query(index, must):
    requests.post("{}/{}/_refresh".format(ES_URL, index),
                  params={"ignore_unavailable": "true", "allow_no_indices": "true"},
                  timeout=10)
    resp = requests.post(
        "{}/{}/_search".format(ES_URL, index),
        params={"ignore_unavailable": "true", "allow_no_indices": "true"},
        json={"size": 50, "query": {"bool": {"filter": must}}},
        timeout=10)
    resp.raise_for_status()
    return [hit["_source"] for hit in resp.json()["hits"]["hits"]]


def wait_for(index, must, timeout=DOC_TIMEOUT):
    deadline = time.time() + timeout
    while time.time() < deadline:
        docs = query(index, must)
        if docs:
            return docs
        time.sleep(2)
    raise AssertionError("no document in {} matching {} after {}s".format(index, must, timeout))


def since(start):
    """Range filter for documents stamped at or after START (epoch seconds).

    Snort stamps alerts with the sensor clock, which is the host clock;
    the slack covers the second-resolution parse and clock reads.
    """
    stamp = datetime.datetime.utcfromtimestamp(start - 5).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {"range": {"@timestamp": {"gte": stamp}}}


def send(only):
    proc = subprocess.run([sys.executable, TRAFFIC, "send", SNORT_HOST, "--only", only],
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          universal_newlines=True)
    print(proc.stdout)
    assert proc.returncode == 0, proc.stdout


@pytest.fixture(scope="module")
def lab():
    wait_for_es()
    wait_for_template()


def test_live_telnet_syn_is_sniffed_and_indexed(lab):
    start = time.time()
    send("telnet_syn")
    docs = wait_for("security-snort-*", [{"term": {"sid": 1000002}}, since(start)])
    doc = docs[0]
    assert doc["src_ip"] == LAB_SRC
    assert doc["dst_ip"] == SENSOR_IP
    assert doc["dst_port"] == 23
    assert doc["log_type"] == "snort"


def test_live_ssh_burst_is_sniffed_and_indexed(lab):
    start = time.time()
    send("ssh_burst")
    docs = wait_for("security-snort-*", [{"term": {"sid": 1000004}}, since(start)])
    assert docs[0]["src_ip"] == LAB_SRC
    assert docs[0]["dst_ip"] == SENSOR_IP


def test_injected_auth_failures_raise_ossec_brute_force_alert(lab):
    marker = "m" + uuid.uuid4().hex[:12]
    with open(os.path.join(FIXTURES, "secure_auth_failures.log")) as handle:
        lines = [line.rstrip("\n") for line in handle if line.strip()]
    assert sum("Failed password" in line for line in lines) == 10
    # The marker is a trailing word, which the sshd decoder ignores; it
    # ends up in full_log and so in the indexed message.
    with open(OSSEC_INPUT, "a") as handle:
        for line in lines:
            handle.write("{} {}\n".format(line, marker))
    docs = wait_for("security-ossec-*", [{"term": {"rule_id": 100020}},
                                         {"match_phrase": {"message": marker}}])
    doc = docs[0]
    assert doc["src_ip"] == LAB_SRC
    assert doc["alert_level"] == 12
    assert doc["log_type"] == "ossec"
