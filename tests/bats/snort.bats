#!/usr/bin/env bats
# Checks the Snort sensor image: version, install marker, configuration test
# and the local rules against the pcaps written by tools/traffic.py.

PCAPS="${PCAP_DIR:-/lab/pcaps}"
CONF=/etc/snort/snort.conf

setup() {
  LOGDIR="$BATS_TMPDIR/snort-log"
  rm -rf "$LOGDIR"
  mkdir -p "$LOGDIR"
}

teardown() {
  rm -rf "$LOGDIR"
}

# Prints the alerts Snort raises for one pcap, one console line per alert.
alerts_for() {
  snort -r "$PCAPS/$1.pcap" -c "$CONF" -l "$LOGDIR" -A console -q -k none
}

# Prints the distinct SIDs found in console alert output.
sids_in() {
  grep -o '\[[0-9]*:[0-9]*:[0-9]*\]' <<<"$1" | cut -d: -f2 | sort -u | tr '\n' ' '
}

@test "snort -V reports 2.9.11.1" {
  run bash -c 'snort -V 2>&1'
  [ "$status" -eq 0 ]
  [[ "$output" == *"Version 2.9.11.1"* ]]
}

@test "install marker for 2.9.11.1 exists" {
  [ -f /etc/snort/.installed-2.9.11.1 ]
}

@test "local rules are installed with SIDs 1000001-1000004" {
  for sid in 1000001 1000002 1000003 1000004; do
    grep -q "sid:$sid;" /etc/snort/rules/local.rules || { echo "missing sid $sid"; return 1; }
  done
}

@test "snort -T accepts snort.conf" {
  run snort -T -c "$CONF" -l "$LOGDIR" -q
  [ "$status" -eq 0 ]
}

@test "lab_probe.pcap fires only SID 1000001" {
  run alerts_for lab_probe
  [ "$status" -eq 0 ]
  [ "$(sids_in "$output")" = "1000001 " ]
  [[ "$output" == *"LAB ICMP probe"*"[Priority: 3]"* ]]
}

@test "telnet_syn.pcap fires only SID 1000002" {
  run alerts_for telnet_syn
  [ "$status" -eq 0 ]
  [ "$(sids_in "$output")" = "1000002 " ]
  [[ "$output" == *"LAB telnet connection attempt"*"[Priority: 1]"*"172.48.0.20:40000 -> 172.48.0.10:23"* ]]
}

@test "xmas_scan.pcap fires only SID 1000003" {
  run alerts_for xmas_scan
  [ "$status" -eq 0 ]
  [ "$(sids_in "$output")" = "1000003 " ]
  [[ "$output" == *"LAB nmap XMAS scan"*"[Priority: 2]"* ]]
}

@test "ssh_burst.pcap fires SID 1000004 only after the fifth SYN" {
  run alerts_for ssh_burst
  [ "$status" -eq 0 ]
  [ "$(sids_in "$output")" = "1000004 " ]
  count=$(grep -c '\[1:1000004:' <<<"$output")
  [ "$count" -ge 1 ]
  [ "$count" -lt 6 ]
}

@test "benign.pcap produces no alerts" {
  run alerts_for benign
  [ "$status" -eq 0 ]
  [ -z "$output" ]
}
