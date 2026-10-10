"""Checks the matching rules, ordering and output formats of tools/correlate.py."""
import datetime
import json
import os
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "tools"))

import correlate  # noqa: E402

T0 = datetime.datetime(2018, 8, 3, 9, 0, 0)


def stamp(offset):
    """ISO timestamp OFFSET seconds after T0, as Elasticsearch returns it."""
    return (T0 + datetime.timedelta(seconds=offset)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def snort(ip, offset, sid=1000002, priority=2):
    return {"@timestamp": stamp(offset), "src_ip": ip, "sid": sid, "priority": priority}


def ossec(ip, offset, rule_id=100020, level=12):
    return {"@timestamp": stamp(offset), "src_ip": ip, "rule_id": rule_id, "alert_level": level}


def ips(results):
    return [r["src_ip"] for r in results]


def test_snort_and_ossec_899_seconds_apart_match_with_900_window():
    results = correlate.correlate([snort("10.0.0.1", 0)], [ossec("10.0.0.1", 899)], 900, 2)
    assert ips(results) == ["10.0.0.1"]


def test_snort_and_ossec_901_seconds_apart_do_not_match_with_900_window():
    results = correlate.correlate([snort("10.0.0.1", 0)], [ossec("10.0.0.1", 901)], 900, 2)
    assert results == []


def test_window_applies_in_both_directions():
    results = correlate.correlate([snort("10.0.0.1", 899)], [ossec("10.0.0.1", 0)], 900, 2)
    assert ips(results) == ["10.0.0.1"]


def test_one_close_pair_is_enough_among_distant_events():
    results = correlate.correlate(
        [snort("10.0.0.1", 0), snort("10.0.0.1", 5000)],
        [ossec("10.0.0.1", 2000), ossec("10.0.0.1", 5100)], 900, 2)
    assert ips(results) == ["10.0.0.1"]
    assert results[0]["snort_count"] == 2
    assert results[0]["ossec_count"] == 2


def test_ip_seen_only_by_snort_is_excluded():
    results = correlate.correlate(
        [snort("10.0.0.1", 0), snort("10.0.0.2", 0)], [ossec("10.0.0.2", 10)], 900, 2)
    assert ips(results) == ["10.0.0.2"]


def test_ip_seen_only_by_ossec_is_excluded():
    results = correlate.correlate([], [ossec("10.0.0.3", 0), ossec("10.0.0.3", 1)], 900, 1)
    assert results == []


def test_min_events_three_excludes_a_single_pair():
    pair = ([snort("10.0.0.1", 0)], [ossec("10.0.0.1", 10)])
    assert correlate.correlate(pair[0], pair[1], 900, 3) == []
    assert ips(correlate.correlate(pair[0], pair[1], 900, 2)) == ["10.0.0.1"]


def test_min_events_three_keeps_two_plus_one():
    results = correlate.correlate(
        [snort("10.0.0.1", 0), snort("10.0.0.1", 5)], [ossec("10.0.0.1", 10)], 900, 3)
    assert ips(results) == ["10.0.0.1"]


def test_priority_one_sorts_before_priority_three():
    results = correlate.correlate(
        [snort("10.0.0.9", 0, priority=3), snort("10.0.0.5", 0, priority=1)],
        [ossec("10.0.0.9", 1), ossec("10.0.0.5", 1)], 900, 2)
    assert ips(results) == ["10.0.0.5", "10.0.0.9"]
    assert [r["min_priority"] for r in results] == [1, 3]


def test_equal_priority_sorts_by_level_descending_then_ip():
    results = correlate.correlate(
        [snort("10.0.0.3", 0), snort("10.0.0.1", 0), snort("10.0.0.2", 0)],
        [ossec("10.0.0.3", 1, level=5), ossec("10.0.0.1", 1, level=5),
         ossec("10.0.0.2", 1, level=12)], 900, 2)
    assert ips(results) == ["10.0.0.2", "10.0.0.1", "10.0.0.3"]


def test_sids_and_rule_ids_are_deduplicated_and_sorted():
    results = correlate.correlate(
        [snort("10.0.0.1", 0, sid=1000004), snort("10.0.0.1", 1, sid=1000002),
         snort("10.0.0.1", 2, sid=1000004)],
        [ossec("10.0.0.1", 3, rule_id=100020), ossec("10.0.0.1", 4, rule_id=5716),
         ossec("10.0.0.1", 5, rule_id=100020)], 900, 2)
    assert results[0]["sids"] == [1000002, 1000004]
    assert results[0]["rule_ids"] == [5716, 100020]


def test_result_fields():
    results = correlate.correlate(
        [snort("10.0.0.1", 30, priority=2), snort("10.0.0.1", 60, priority=1)],
        [ossec("10.0.0.1", 0, level=10), ossec("10.0.0.1", 90, level=12)], 900, 2)
    result = results[0]
    assert set(result) == {"src_ip", "snort_count", "ossec_count", "first_seen", "last_seen",
                           "sids", "rule_ids", "min_priority", "max_level"}
    assert result["snort_count"] == 2
    assert result["ossec_count"] == 2
    assert result["first_seen"] == "2018-08-03T09:00:00Z"
    assert result["last_seen"] == "2018-08-03T09:01:30Z"
    assert result["min_priority"] == 1
    assert result["max_level"] == 12


def test_parse_timestamp_accepts_offsets_and_fractions():
    expected = datetime.datetime(2018, 8, 3, 9, 0, 0)
    assert correlate.parse_timestamp("2018-08-03T09:00:00Z") == expected
    assert correlate.parse_timestamp("2018-08-03T09:00:00.123Z") == expected.replace(
        microsecond=123000)
    assert correlate.parse_timestamp("2018-08-03T11:00:00+02:00") == expected


@pytest.mark.parametrize("text,expected", [
    ("30s", datetime.timedelta(seconds=30)),
    ("15m", datetime.timedelta(minutes=15)),
    ("2h", datetime.timedelta(hours=2)),
    ("1d", datetime.timedelta(days=1)),
])
def test_parse_since(text, expected):
    assert correlate.parse_since(text) == expected


@pytest.mark.parametrize("text", ["15x", "", "m", "-5m", "1.5h", "15 m"])
def test_parse_since_rejects_bad_input(text):
    with pytest.raises(ValueError):
        correlate.parse_since(text)


def sample_results():
    return correlate.correlate(
        [snort("10.0.0.5", 0, priority=1), snort("10.0.0.9", 0, priority=3)],
        [ossec("10.0.0.5", 1), ossec("10.0.0.9", 1)], 900, 2)


def test_format_ansible_lists_block_ips_in_result_order():
    assert json.loads(correlate.format_ansible(sample_results())) == {
        "block_ips": ["10.0.0.5", "10.0.0.9"]}
    assert json.loads(correlate.format_ansible([])) == {"block_ips": []}


def test_format_json_round_trips_results():
    results = sample_results()
    assert json.loads(correlate.format_json(results)) == results


def test_format_table_has_header_and_one_row_per_ip():
    lines = correlate.format_table(sample_results()).splitlines()
    assert lines[0].split()[0] == "SRC_IP"
    assert [line.split()[0] for line in lines[1:]] == ["10.0.0.5", "10.0.0.9"]


def test_format_table_reports_no_matches():
    assert "no correlated" in correlate.format_table([]).lower()


class FakeFetch(object):
    def __init__(self, snort_events, ossec_events):
        self.events = {"security-snort-*": snort_events, "security-ossec-*": ossec_events}
        self.calls = []

    def __call__(self, es, index_pattern, since, until):
        self.calls.append((index_pattern, since, until))
        return self.events[index_pattern]


def run_main(monkeypatch, capsys, fetch, argv):
    monkeypatch.setattr(correlate, "fetch_events", fetch)
    code = correlate.main(argv)
    return code, capsys.readouterr()


def test_fail_on_match_exits_3_when_ips_match(monkeypatch, capsys):
    fetch = FakeFetch([snort("10.0.0.1", 0)], [ossec("10.0.0.1", 10)])
    code, out = run_main(monkeypatch, capsys, fetch,
                         ["--format", "ansible", "--fail-on-match"])
    assert code == 3
    assert json.loads(out.out) == {"block_ips": ["10.0.0.1"]}


def test_fail_on_match_exits_0_without_matches(monkeypatch, capsys):
    fetch = FakeFetch([snort("10.0.0.1", 0)], [])
    code, out = run_main(monkeypatch, capsys, fetch, ["--fail-on-match"])
    assert code == 0


def test_matches_without_fail_on_match_exit_0(monkeypatch, capsys):
    fetch = FakeFetch([snort("10.0.0.1", 0)], [ossec("10.0.0.1", 10)])
    code, out = run_main(monkeypatch, capsys, fetch, ["--format", "json"])
    assert code == 0
    assert ips(json.loads(out.out)) == ["10.0.0.1"]


def test_main_queries_both_indices_over_the_since_range(monkeypatch, capsys):
    fetch = FakeFetch([], [])
    run_main(monkeypatch, capsys, fetch, ["--since", "2h"])
    assert sorted(call[0] for call in fetch.calls) == ["security-ossec-*", "security-snort-*"]
    for _, since, until in fetch.calls:
        assert until - since == datetime.timedelta(hours=2)


def test_main_passes_window_and_min_events(monkeypatch, capsys):
    fetch = FakeFetch([snort("10.0.0.1", 0)], [ossec("10.0.0.1", 100)])
    code, out = run_main(monkeypatch, capsys, fetch,
                         ["--window", "60", "--format", "ansible"])
    assert json.loads(out.out) == {"block_ips": []}
    code, out = run_main(monkeypatch, capsys, fetch,
                         ["--min-events", "3", "--format", "ansible"])
    assert json.loads(out.out) == {"block_ips": []}


def test_bad_since_is_a_usage_error(monkeypatch, capsys):
    code, out = run_main(monkeypatch, capsys, FakeFetch([], []), ["--since", "15x"])
    assert code == 1
    assert "15x" in out.err


def test_unknown_format_is_a_usage_error(monkeypatch, capsys):
    code, out = run_main(monkeypatch, capsys, FakeFetch([], []), ["--format", "xml"])
    assert code == 1


def test_elasticsearch_failure_exits_1(monkeypatch, capsys):
    def broken(es, index_pattern, since, until):
        raise correlate.ElasticsearchException("connection refused")
    code, out = run_main(monkeypatch, capsys, broken, [])
    assert code == 1
    assert "connection refused" in out.err
