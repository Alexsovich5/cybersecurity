"""Filebeat -> Logstash -> Elasticsearch: fixture alerts become parsed documents.

The fixture appends every Snort fast-alert line, the OSSEC JSON alert, the
sshd lines of the secure log and the auditd lines to the files Filebeat
watches, and sends the pfSense filterlog lines to the Logstash UDP syslog
input. Each line carries a marker that is unique to this run; the tests look
the resulting documents up in Elasticsearch by that marker and read the
alert mails Logstash sent to MailHog.
"""
import datetime
import json
import os
import socket
import sys
import time
import uuid

import pytest
import requests

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FIXTURES = os.path.join(REPO, "tests", "fixtures")

ES_URL = os.environ.get("ES_URL", "http://elasticsearch:9200")
SNORT_ALERT = os.environ.get("SNORT_ALERT", "/lab/logs/snort/alert")
OSSEC_ALERTS = os.environ.get("OSSEC_ALERTS", "/lab/logs/ossec/alerts.json")
SECURE_LOG = os.environ.get("SECURE_LOG", "/lab/logs/system/secure")
AUDIT_LOG = os.environ.get("AUDIT_LOG", "/lab/logs/system/audit/audit.log")
TEMPLATE = os.path.join(REPO, "elk", "es-template.json")
MAILHOG_URL = os.environ.get("MAILHOG_URL", "http://mailhog:8025")
LOGSTASH_HOST = os.environ.get("PFSENSE_HOST", "logstash")
PFSENSE_HOST = LOGSTASH_HOST
PFSENSE_PORT = int(os.environ.get("PFSENSE_PORT", "5140"))

sys.path.insert(0, os.path.join(REPO, "tools"))
import pfsense_sim  # noqa: E402

HEALTH_TIMEOUT = 120
DOC_TIMEOUT = 60
# JRuby start-up on a loaded Docker host can take several minutes.
LOGSTASH_TIMEOUT = 300


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


def wait_for_template(name="security", timeout=HEALTH_TIMEOUT):
    """Wait until Logstash has installed the index template NAME."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if requests.get("{}/_template/{}".format(ES_URL, name), timeout=10).status_code == 200:
            return
        time.sleep(2)
    raise RuntimeError("index template {} not installed after {}s".format(name, timeout))


def wait_for_logstash(timeout=LOGSTASH_TIMEOUT):
    """Wait until the Logstash pipeline listens for Beats on 5044.

    The template may survive from an earlier run in the ES volume, so its
    presence alone does not show that a freshly started Logstash is ready.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            socket.create_connection((LOGSTASH_HOST, 5044), timeout=5).close()
            return
        except OSError:
            time.sleep(2)
    raise RuntimeError("Logstash beats input not listening after {}s".format(timeout))


def drop_untyped_indices():
    """Delete security-* indices created before the template existed.

    A template only applies to indices created after it, so an index left
    in the lab volume by an earlier pipeline version keeps src_ip as text.
    The fixture lines are re-injected each run, so nothing is lost.
    """
    resp = requests.get(ES_URL + "/security-*/_mapping/field/src_ip", timeout=10)
    if resp.status_code == 404:
        # No security-* index exists yet (a fresh lab volume).
        return
    resp.raise_for_status()
    for name, body in resp.json().items():
        specs = [spec["mapping"]["src_ip"]["type"]
                 for mapping in body["mappings"].values()
                 for spec in mapping.values()]
        if any(kind != "ip" for kind in specs):
            requests.delete("{}/{}".format(ES_URL, name), timeout=30).raise_for_status()


def search(index, marker):
    """Return the _source of every document in INDEX whose message holds MARKER."""
    return [hit["_source"] for hit in search_hits(index, marker)]


def search_hits(index, marker):
    """Return every hit in INDEX whose message holds MARKER."""
    resp = requests.post(
        "{}/{}/_search".format(ES_URL, index),
        params={"ignore_unavailable": "true", "allow_no_indices": "true"},
        json={"size": 50, "query": {"match_phrase": {"message": marker}}},
        timeout=10)
    resp.raise_for_status()
    return resp.json()["hits"]["hits"]


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


def plain_lines(name):
    with open(os.path.join(FIXTURES, name)) as handle:
        return [line.rstrip("\n") for line in handle if line.strip()]


def clear_mail():
    requests.delete(MAILHOG_URL + "/api/v1/messages", timeout=10).raise_for_status()


def mail_subjects():
    resp = requests.get(MAILHOG_URL + "/api/v2/messages", params={"limit": 250}, timeout=10)
    resp.raise_for_status()
    return [subject
            for item in resp.json()["items"]
            for subject in item["Content"]["Headers"].get("Subject", [])]


def send_pfsense(lines):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for line in lines:
            sock.sendto(pfsense_sim.frame(line, datetime.datetime.now()),
                        (PFSENSE_HOST, PFSENSE_PORT))
    finally:
        sock.close()


def append(path, lines):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a") as handle:
        for line in lines:
            handle.write(line + "\n")


@pytest.fixture(scope="module")
def shipped():
    """Inject the fixture lines and return {key: (index, marker, docs)}."""
    wait_for_es()
    wait_for_logstash()
    wait_for_template()
    drop_untyped_indices()
    clear_mail()
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

    # Secure and audit lines take the marker as a trailing word: the syslog
    # and auditd parsers ignore text after the fields they extract.
    secure_out = []
    for number, line in enumerate(plain_lines("secure_auth_failures.log"), 1):
        marker = "m{}x{}".format(run, number)
        secure_out.append("{} {}".format(line, marker))
        injected["secure{}".format(number)] = ("security-secure-*", marker)

    audit_out = []
    for number, line in enumerate(plain_lines("audit.log"), 1):
        marker = "m{}a{}".format(run, number)
        audit_out.append("{} {}".format(line, marker))
        injected["audit{}".format(number)] = ("security-audit-*", marker)

    append(SNORT_ALERT, snort_out)
    append(OSSEC_ALERTS, [json.dumps(alert, separators=(",", ":"))])
    append(SECURE_LOG, secure_out)
    append(AUDIT_LOG, audit_out)

    found = {key: (index, marker, wait_for_docs(index, marker))
             for key, (index, marker) in injected.items()}

    # The UDP lines are sent once the Beats events are indexed, so the
    # Logstash inputs are known to be running and no datagram is lost.
    # The marker is a trailing word after the last CSV column.
    pfsense = {}
    pfsense_out = []
    for number, line in enumerate(plain_lines("pfsense_filterlog.log"), 1):
        marker = "m{}p{}".format(run, number)
        pfsense_out.append("{} {}".format(line, marker))
        pfsense["pfsense{}".format(number)] = ("security-pfsense-*", marker)
    send_pfsense(pfsense_out)
    found.update((key, (index, marker, wait_for_docs(index, marker)))
                 for key, (index, marker) in pfsense.items())
    return found


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


def test_secure_failed_password_gives_src_ip(shipped):
    docs = docs_of(shipped, "secure")
    assert len(docs) == len(plain_lines("secure_auth_failures.log")), docs
    failed = [doc for doc in docs if "Failed password" in doc["message"]]
    assert len(failed) == 10, failed
    for doc in failed:
        assert doc["log_type"] == "secure"
        assert doc["src_ip"] == "172.48.0.20"
        assert doc["program"] == "sshd"
        assert doc["logsource"] == "target"
    assert {doc["src_port"] for doc in failed} == {40012, 40014, 40022, 40026}
    other = [doc for doc in docs if "Failed password" not in doc["message"]]
    assert all("src_ip" not in doc for doc in other), other
    assert {doc["@timestamp"][5:10] for doc in docs} == {"07-20"}


def test_audit_records_are_split_into_fields(shipped):
    docs = docs_of(shipped, "audit")
    assert len(docs) == len(plain_lines("audit.log")), docs
    by_type = {doc["type"]: doc for doc in docs}
    assert {"SYSCALL", "USER_LOGIN"} <= set(by_type), sorted(by_type)
    assert all(doc["log_type"] == "audit" for doc in docs)
    syscall = by_type["SYSCALL"]
    assert syscall["audit"]["syscall"] == "59"
    assert syscall["audit"]["exe"] == "/usr/bin/passwd"
    assert syscall["audit"]["key"] == "identity"
    login = by_type["USER_LOGIN"]
    assert login["audit"]["addr"] == "172.48.0.20"
    assert login["audit"]["res"] == "failed"
    assert login["@timestamp"].startswith("2018-07-20T14:03:14")


def field_types(index, fields):
    """Return {index_name: {field: type}} from the field mapping API."""
    resp = requests.get("{}/{}/_mapping/field/{}".format(ES_URL, index, ",".join(fields)),
                        timeout=10)
    resp.raise_for_status()
    out = {}
    for name, body in resp.json().items():
        types = {}
        for mapping in body["mappings"].values():
            for field, spec in mapping.items():
                leaf = field.rsplit(".", 1)[-1]
                types[field] = spec["mapping"][leaf]["type"]
        out[name] = types
    return out


def test_template_types_the_indexed_fields(shipped):
    written = set()
    for key, (index, marker, _) in shipped.items():
        written.update(hit["_index"] for hit in search_hits(index, marker))
    assert any(name.startswith("security-secure-") for name in written), written
    fields = ["src_ip", "hostname", "beat.hostname"]
    for name, types in field_types(",".join(sorted(written)), fields).items():
        assert types.get("src_ip", "ip") == "ip", (name, types)
        assert types["hostname"] == "keyword", (name, types)
        assert types["beat.hostname"] == "keyword", (name, types)
    for name in written:
        if name.startswith(("security-secure-", "security-snort-")):
            assert field_types(name, ["src_ip"])[name]["src_ip"] == "ip", name


def test_installed_template_has_no_host_mapping(shipped):
    resp = requests.get(ES_URL + "/_template/security", timeout=10)
    assert resp.status_code == 200, resp.text
    installed = resp.json()["security"]
    assert installed["index_patterns"] == ["security-*"]
    assert installed["order"] == 1
    properties = installed["mappings"]["doc"]["properties"]
    assert "host" not in properties
    assert properties["src_ip"]["type"] == "ip"
    assert properties["dst_ip"]["type"] == "ip"
    assert properties["hostname"]["type"] == "keyword"
    assert properties["geoip"]["properties"]["location"]["type"] == "geo_point"
    assert properties["priority"]["type"] == "integer"
    assert properties["alert_level"]["type"] == "integer"
    with open(TEMPLATE) as handle:
        assert "host" not in json.load(handle)["mappings"]["doc"]["properties"]


def test_pfsense_block_to_ssh_is_parsed(shipped):
    docs = [doc for doc in docs_of(shipped, "pfsense")
            if doc.get("fw_action") == "block" and doc.get("dst_port") == 22]
    assert len(docs) == 1, docs_of(shipped, "pfsense")
    doc = docs[0]
    assert doc["log_type"] == "pfsense"
    assert doc["fw_rule"] == "5"
    assert doc["fw_interface"] == "em0"
    assert doc["fw_reason"] == "match"
    assert doc["fw_direction"] == "in"
    assert doc["proto"] == "tcp"
    assert doc["src_ip"] == "8.8.8.8"
    assert doc["dst_ip"] == "172.48.0.10"
    assert doc["src_port"] == 51234
    assert doc.get("hostname")
    assert doc["geoip"]["country_code2"] == "US"
    assert "_pfsense_unparsed" not in doc.get("tags", [])


def test_pfsense_ipv4_tcp_and_udp_lines_are_parsed(shipped):
    parsed = [doc for doc in docs_of(shipped, "pfsense")
              if "_pfsense_unparsed" not in doc.get("tags", [])]
    got = sorted((doc["fw_action"], doc["proto"], doc["dst_port"]) for doc in parsed)
    assert got == [("block", "tcp", 22), ("block", "tcp", 23), ("pass", "udp", 40053)]


def test_pfsense_ipv6_line_is_tagged_unparsed(shipped):
    docs = shipped["pfsense4"][2]
    assert len(docs) == 1, docs
    doc = docs[0]
    assert doc["log_type"] == "pfsense"
    assert "_pfsense_unparsed" in doc.get("tags", [])
    assert "src_ip" not in doc
    assert "fw_action" not in doc
    assert doc.get("hostname")


def wait_for_subject(text, timeout=DOC_TIMEOUT):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if any(text in subject for subject in mail_subjects()):
            time.sleep(3)
            return mail_subjects()
        time.sleep(2)
    raise AssertionError("no mail with subject containing {!r} after {}s ({})".format(
        text, timeout, mail_subjects()))


def test_priority_one_snort_alert_is_mailed_once(shipped):
    marker = shipped["snort2"][1]
    subjects = wait_for_subject(marker)
    # Only this run's marker is counted: a recreated Filebeat may re-ship
    # alerts appended by earlier runs after the mailbox was cleared.
    expected = "High Priority Snort Alert: LAB telnet connection attempt " + marker
    assert [s for s in subjects if marker in s] == [expected], subjects


def test_priority_three_snort_alert_is_not_mailed(shipped):
    subjects = wait_for_subject(shipped["snort2"][1])
    assert not [s for s in subjects if shipped["snort1"][1] in s], subjects
    # Priority 2 and 1 alerts from the same run are mailed too.
    assert any(shipped["snort3"][1] in s for s in subjects), subjects
