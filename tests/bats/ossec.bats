#!/usr/bin/env bats
# Checks the OSSEC image: local rules through ossec-logtest, and JSON alerts
# written by the running daemons for lines appended to the lab input file.

FIXTURE=/src/tests/fixtures/secure_auth_failures.log
OSSEC=/var/ossec
ALERTS="$OSSEC/logs/alerts/alerts.json"
LAB_INPUT=/var/log/lab/secure
SRC_IP=172.48.0.20

# Runs one ossec-logtest session over stdin and prints its output.
logtest() {
  "$OSSEC/bin/ossec-logtest" -v 2>&1
}

fixture_line() {
  grep -m1 -- "$1" "$FIXTURE"
}

@test "OSSEC 2.9.4 is installed in local mode" {
  grep -q '^VERSION="v2.9.4"' /etc/ossec-init.conf
  grep -q '^TYPE="local"' /etc/ossec-init.conf
}

@test "installed ossec.conf turns on JSON output and reads the lab input" {
  grep -q '<jsonout_output>yes</jsonout_output>' "$OSSEC/etc/ossec.conf"
  grep -q "<location>$LAB_INPUT</location>" "$OSSEC/etc/ossec.conf"
  grep -q 'id="100020"' "$OSSEC/rules/local_rules.xml"
}

@test "failed root password maps to rule 5716" {
  output=$(fixture_line 'Failed password' | logtest)
  [[ "$output" == *"Rule id: '5716'"* ]]
}

@test "refused root login maps to local rule 100010" {
  output=$(fixture_line 'ROOT LOGIN REFUSED' | logtest)
  [[ "$output" == *"Rule id: '100010'"* ]]
  [[ "$output" == *"Level: '10'"* ]]
}

@test "accepted public key matches rule 5715" {
  output=$(fixture_line 'Accepted publickey' | logtest)
  # 5715 matches; the reported rule is its stock child 10100 (first time
  # user logged in), because this user has not been seen before.
  [[ "$output" == *"*Rule 5715 matched."* ]]
  [[ "$output" == *"Rule id: '10100'"* ]]
}

@test "ten failures in one session escalate to rule 100020 after the first" {
  output=$(grep 'Failed password' "$FIXTURE" | logtest)
  # Each event's report starts with the pre-decoding phase banner.
  first=$(awk '/\*\*Phase 1:/{n++} n==1' <<<"$output")
  later=$(awk '/\*\*Phase 1:/{n++} n>1' <<<"$output")
  [ -n "$first" ]
  [[ "$first" != *"Rule id: '100020'"* ]]
  [[ "$later" == *"Rule id: '100020'"* ]]
  [[ "$later" == *"Level: '12'"* ]]
}

@test "running daemons write a 100020 JSON alert for the lab input within 30s" {
  mkdir -p /var/log/lab
  touch "$LAB_INPUT"
  "$OSSEC/bin/ossec-control" start
  # The alerts directory is a volume, so only lines written by this run count.
  before=0
  [ -f "$ALERTS" ] && before=$(wc -l < "$ALERTS")
  # logcollector opens monitored files at the end; give it time to attach.
  sleep 5
  cat "$FIXTURE" >> "$LAB_INPUT"

  found=""
  for _ in $(seq 1 30); do
    if [ -f "$ALERTS" ]; then
      found=$(tail -n +"$((before + 1))" "$ALERTS" | grep '"sidid":100020' | head -1)
      [ -n "$found" ] && break
    fi
    sleep 1
  done
  "$OSSEC/bin/ossec-control" stop >/dev/null 2>&1 || true

  [ -n "$found" ]
  run python -c '
import json, sys
alert = json.loads(sys.argv[1])
assert alert["rule"]["sidid"] == 100020, alert
assert alert["srcip"] == sys.argv[2], alert
print(json.dumps(alert, sort_keys=True))
' "$found" "$SRC_IP"
  echo "$output"
  [ "$status" -eq 0 ]
}
