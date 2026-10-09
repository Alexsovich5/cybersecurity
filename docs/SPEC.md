# cybersecurity — Specification

Rebuild target: a working, self-contained **Linux hardening + IDS/HIDS + centralized security logging lab**
on the stack that was mainstream between March and August 2018: Ansible 2.4, Snort 2.9, OSSEC 2.9, Elastic Stack 6.3, Bash, CentOS 7.
The whole thing runs in Docker. Nothing in it touches a real network perimeter or a real mail server.

Scope source: the original README (commit `3b68ab9`), used only for its technical concept, features and stack.
The original README's employer/role/date claims, status badge and incident-reduction metric are not carried over.

---

## 1. Problem

Hardening a small fleet of CentOS 7 servers by hand is slow and inconsistent. Network and host intrusion signals
end up in separate places: Snort alerts in one file on the sensor, OSSEC alerts in another on each host, firewall
logs on the firewall. This project does four things:

1. Applies a repeatable, idempotent hardening baseline (Bash script, driven by Ansible) to CentOS 7 hosts.
2. Deploys a Snort 2.9 network IDS sensor and an OSSEC 2.9 host IDS with a small set of local rules.
3. Ships Snort, OSSEC, firewall (pfSense filterlog), auth and audit logs through Filebeat and Logstash into
   Elasticsearch, with GeoIP enrichment and an email alert for high-priority Snort events.
4. Correlates source IPs seen by both Snort and OSSEC, and feeds them into an Ansible playbook that blocks those IPs
   with firewalld.

## 2. In scope

| # | Feature | Where |
|---|---------|-------|
| F1 | **Idempotent Linux hardening script** for CentOS 7: SSH daemon options, password aging policy, firewalld default-drop zone allowing only ssh/https, disabling unneeded services, file permissions, auditd watch rules, kernel sysctls, fail2ban sshd jail. Supports `--check` (report only), `--root DIR` (operate on an alternate filesystem root, used by tests), `--skip-services`, `--skip-packages`. Prints `CHANGED:` only when something is modified. | `scripts/harden_linux.sh` |
| F2 | **Ansible hardening play**: installs the baseline security packages at the exact versions in §6 (aide, rkhunter, clamav, fail2ban, audit, firewalld), then copies and runs F1. It is idempotent: a second run reports `changed=0`. | `ansible/hardening.yml` (tag `hardening`) |
| F3 | **Snort 2.9.11.1 sensor install**: `setup_snort.sh` builds DAQ 2.0.6 and Snort 2.9.11.1 from checksum-verified source tarballs on CentOS 7, creates the `snort` user and directories, and installs the config. | `scripts/setup_snort.sh`, `docker/snort/` |
| F4 | **Snort configuration and local rules**: a valid `snort.conf` (it must pass `snort -T`) with frag3/stream5 preprocessors, fast alert output, and four local rules: lab ICMP probe, telnet connection attempt, nmap XMAS scan, and SSH SYN burst using `detection_filter`. | `config/snort.conf`, `config/rules/local.rules` |
| F5 | **OSSEC 2.9.4 install (local mode)**: `deploy_ossec.sh` builds OSSEC from checksum-verified source with preloaded vars, installs `ossec.conf` (JSON alert output on; monitors `/var/log/secure`, `/var/log/audit/audit.log` and a lab input file), and installs local rules. | `scripts/deploy_ossec.sh`, `config/ossec.conf`, `config/ossec_local_rules.xml`, `docker/ossec/` |
| F6 | **Ansible plays for sensors and agents**: the Snort play targets `ids_sensors` and the OSSEC play targets `all`. Both reuse F3/F5. Service enable/start is controlled by a variable. | `ansible/hardening.yml` (tags `snort`, `ossec`) |
| F7 | **Log shipping with Filebeat 6.3.2**: ships the Snort fast-alert file, OSSEC `alerts.json`, `/var/log/secure` and `/var/log/audit/audit.log` to Logstash. Each event is tagged with `fields.log_type`. Also has an Ansible play that installs Filebeat from the Elastic 6.x yum repo. | `elk/filebeat.yml`, `ansible/hardening.yml` (tag `filebeat`) |
| F8 | **Logstash 6.3.2 security pipeline**: Beats input on 5044 and UDP syslog input on 5140 (for pfSense). Grok for Snort fast alerts, including IPs and ports. Maps OSSEC JSON fields. Parses pfSense `filterlog` CSV for IPv4 TCP/UDP. GeoIP on `src_ip`. Routes each event to the index `security-<log_type>-YYYY.MM.dd`. Sends an email for Snort priority ≤ 2. | `elk/logstash.conf` |
| F9 | **Elasticsearch index template** for `security-*`. It maps IP fields as `ip`, `geoip.location` as `geo_point`, and numeric priority and level fields as `integer`. | `elk/es-template.json` |
| F11 | **Snort + OSSEC correlation CLI**: queries Elasticsearch for events in a time range and reports source IPs that appear in both Snort and OSSEC within a time window. Output formats are table, JSON, or Ansible extra-vars. | `tools/correlate.py` |
| F12 | **Playbook-driven response**: blocks (or unblocks) a list of IPs with a firewalld rich rule in the `drop` zone. It validates the IPs, is idempotent, and uses `firewall-offline-cmd` when firewalld is not running. It consumes F11's `--format ansible` output. | `ansible/respond_block_ip.yml` |
| F13 | **Docker lab**: `docker-compose.yml` with Elasticsearch, Logstash, Kibana, Filebeat, a Snort sensor sniffing the lab network, an OSSEC host, an SSH-managed CentOS 7 target, MailHog, and a test runner. `make lab-up` and `make demo` show the flow end to end. | `docker-compose.yml`, `docker/*`, `Makefile` |
| F14 | **Traffic and log simulators used for tests and the demo**: a scapy tool that writes or sends packets matching each local Snort rule plus benign traffic, and a pfSense filterlog syslog sender. | `tools/traffic.py`, `tools/pfsense_sim.py` |

The ID F10 is deliberately unused: the ELK server RPM play was moved to §3 because it is never executed, and the other IDs stay stable.

## 3. Out of scope

| Original README item | Reason |
|---|---|
| pfSense 2.4 appliance install/configuration (firewall rules, NAT) | pfSense is a FreeBSD appliance and cannot run in a Linux container. Only its log output is used: it is **simulated** by `tools/pfsense_sim.py` sending recorded `filterlog` lines. |
| pfSense VPN (OpenVPN/IPsec) | Needs the appliance and a second site. It has nothing to do with the detection and logging core. |
| OSSEC server/agent mode (ossec-authd, key exchange, central manager) | Key management across hosts adds a lot of moving parts for a solo lab. Every host runs OSSEC in `local` mode and ships alerts through Filebeat, so ELK does the centralization. |
| Incident-reduction business metric | Not a technical feature. The repo cannot measure it. |
| Real-time/streaming correlation of Snort and OSSEC events | Out of scope. F11 polls Elasticsearch on demand over a time range (see §11). |
| ELK server install on real hosts via RPMs (the original playbook's ELK play, formerly F10) | The lab's ELK comes from the official 6.3.2 images (§7). The `elk`-tagged play is kept as an illustrative example pinned to 6.3.2, but it is only syntax-checked and linted, never executed, so it is not claimed as implemented. |
| "Compliance Ready" as a certification claim | Only the technical part is built (auditd rules plus central audit-log shipping, F1/F7). No compliance mapping or CIS benchmark scoring. |
| Scheduled AIDE / rkhunter / ClamAV scans and their reporting | The original playbook only installed these packages. Installing them is kept (F2). Scheduling scans and parsing their reports was never described. |
| Snort community/registered ruleset download (Oinkcode, PulledPork) | Registered rules need an account, and the community tarball is not pinned to a date. `snort.conf` keeps a commented `include` for `community.rules`, and only local rules are tested. |
| Kibana dashboards / saved searches | Not described in the README. Kibana is in the lab only for browsing indices. |
| Full-system package update (`yum update '*'`) | Not deterministic, and on a real host it would pull packages from after the period. It stays available behind `hardening_update_all_packages: false` (tagged `skip_ansible_lint`) and is not tested. In the lab only the 7.5.1804 `os` repo is enabled, so it would be a no-op there. |
| Debian/Ubuntu support | The existing script and playbook are CentOS/RHEL 7 only (yum, firewalld, `/var/log/secure`). The current README's "Debian/Ubuntu-oriented" note is wrong and is dropped. |

## 4. Architecture

```
                      lab network 10.42.0.0/24 (compose "lab")
 ┌────────────────────────────────────────────────────────────────────────────────┐
 │                                                                                │
 │  tests (python:3.6.6)  ── scapy packets ──► snort (CentOS 7, snort -i eth0)    │
 │   │  pytest / testinfra                        │ /var/log/snort/alert          │
 │   │  ansible-playbook ── SSH ──► target        ▼   (volume snort-logs)         │
 │   │                    (CentOS 7 + sshd)                                        │
 │   │  appends auth lines ─► ossec-input ─► ossec (CentOS 7, OSSEC local)         │
 │   │                                         │ alerts/alerts.json               │
 │   │                                         ▼   (volume ossec-logs)            │
 │   │                                     filebeat 6.3.2 ── beats:5044 ─┐        │
 │   │  pfsense_sim.py ── UDP syslog:5140 ─────────────────────────────► logstash │
 │   │                                                         6.3.2  │  │ email  │
 │   │                                                                ▼  ▼        │
 │   │  correlate.py ◄── search ── elasticsearch 6.3.2        mailhog (SMTP 1025) │
 │   │        │ --format ansible                 ▲                              │
 │   │        ▼                                  └── kibana 6.3.2 (browse)       │
 │   └─ ansible-playbook respond_block_ip.yml ── SSH ──► target (firewalld rule) │
 └────────────────────────────────────────────────────────────────────────────────┘
```

Components:

- **base image** (`docker/base`): `centos:7.5.1804` pinned by digest (§7). Yum is limited to one remote repo, `vault.centos.org/7.5.1804/os` (the 7.5 GA tree, 2018-05-10); `updates` and `extras` are not configured, so every OS package resolves to its single GA build (NVRs in §6). The EPEL packages are not taken from a live EPEL repo: the exact RPMs in §6 are downloaded, sha256-checked and served from a local file repo `/opt/pinned-rpms` (`createrepo`). bats-core 1.1.0 is installed from source. The snort, ossec and target images build on it.
- **snort**: built by running `scripts/setup_snort.sh` during `docker build`, so the Ansible sensor play uses the same install script.
- **ossec**: built by running `scripts/deploy_ossec.sh` during `docker build`. Its entrypoint starts `ossec-control`.
- **target**: a CentOS 7 managed node with sshd and an `ansible` sudo user. On first start the entrypoint generates an SSH keypair into the shared `lab-keys` volume. It stands in for "a server" for the hardening, Filebeat, Snort and OSSEC plays and the response play.
- **tests**: `python:3.6.6-stretch` (pinned by digest, §7) with pinned Ansible, lint and test tooling, plus the shellcheck binary copied from `koalaman/shellcheck:v0.5.0`.
- **ELK**: `elastic/elasticsearch`, `elastic/logstash`, `elastic/kibana`, `elastic/filebeat`, all at `6.3.2`. The filebeat service runs with `user: root` (and `-strict.perms=false`): the image's default user is `filebeat`, which cannot read OSSEC's `alerts.json` (owned by `ossec`, in a 750 directory) or Snort's root-owned alert file. Elasticsearch runs with `xpack.ml.enabled=false`.

Data flow: sensors and hosts write local log files → Filebeat tails them and adds `fields.log_type` → Logstash parses and enriches them → Elasticsearch indexes `security-<log_type>-YYYY.MM.dd`. `correlate.py` polls ES and writes Ansible vars, and `respond_block_ip.yml` applies the blocks.

## 5. Data model & interfaces

### 5.1 `scripts/harden_linux.sh`

```
harden_linux.sh [--check] [--root DIR] [--skip-services] [--skip-packages] [--only STEP[,STEP..]]
  STEP ∈ ssh,password,firewall,services,permissions,audit,sysctl,fail2ban
env equivalents: HARDEN_ROOT, HARDEN_SKIP_SERVICES=1, HARDEN_SKIP_PACKAGES=1
exit: 0 compliant/applied · 1 usage or not root · 2 (--check only) non-compliant items found
stdout: "[n/8] <step>" headers; "CHANGED: <file>: <what>" per modification; "NONCOMPLIANT: ..." in --check
```

Settings that are enforced. The values are the ones in the existing script:

- sshd_config: `PermitRootLogin no`, `PasswordAuthentication no`, `MaxAuthTries 3`, `ClientAliveInterval 300`, `ClientAliveCountMax 2`. Each option is set by replacing any existing line, commented or not, or appending it. The current script's `sed` turns `#PasswordAuthentication yes` into `PasswordAuthentication no` but leaves a conflicting later `PasswordAuthentication yes` line (the effective value is the first one, so it was `no`); the refactor leaves exactly one line per option. `Protocol 2` is dropped because OpenSSH 7.4 ignores it.
- login.defs: `PASS_MAX_DAYS 90`, `PASS_MIN_DAYS 7`, `PASS_MIN_LEN 12`.
- firewalld: default zone `drop`; services `ssh` and `https` in `drop`. When the root is `/`, it uses `firewall-cmd` if the daemon is running and `firewall-offline-cmd` otherwise or when `--skip-services` is set. `firewall-offline-cmd` has no alternate-root option, so when `--root` is not `/` the script writes the permanent config files directly instead: `$ROOT/etc/firewalld/firewalld.conf` (`DefaultZone=drop`, replacing the existing key or appending it) and `$ROOT/etc/firewalld/zones/drop.xml` (the `drop` zone with `<service name="ssh"/>` and `<service name="https"/>`, written only if the content differs). It never touches the running system's `/etc/firewalld` in that mode.
- Every step `mkdir -p`s its target directories under `$ROOT` (`etc/cron.d`, `etc/audit/rules.d`, `etc/sysctl.d`, `etc/fail2ban`, `etc/firewalld/zones`) before writing.
- services disabled: `avahi-daemon cups bluetooth postfix rpcbind`. Skipped with `--skip-services`.
- permissions: `/etc/crontab` 600, `/etc/cron.d/*` 600 (safe on an empty directory), `/root` 700, `/etc/passwd` 644, `/etc/shadow` 000 root:root.
- `/etc/audit/rules.d/hardening.rules`: the six existing rules, written only if the content differs.
- `/etc/sysctl.d/99-hardening.conf`: the seven existing keys, in a drop-in file instead of appended to `/etc/sysctl.conf`, so repeated runs do not duplicate them. `sysctl --system` runs unless `--skip-services` is set.
- `/etc/fail2ban/jail.local`: the existing jail content.

### 5.2 Snort fast alert line (input to Logstash)

```
07/20-14:03:11.123456  [**] [1:1000002:1] LAB telnet connection attempt [**] [Classification: Attempted Administrator Privilege Gain] [Priority: 1] {TCP} 10.42.0.20:40000 -> 10.42.0.10:23
```

Local rules (`config/rules/local.rules`, SIDs 1000001–1000004):

| SID | msg | match | classtype → priority |
|---|---|---|---|
| 1000001 | LAB ICMP probe | `icmp any any -> $HOME_NET any (itype:8; content:"LAB-PROBE";)` | misc-activity → 3 |
| 1000002 | LAB telnet connection attempt | `tcp any any -> $HOME_NET 23 (flags:S;)` | attempted-admin → 1 |
| 1000003 | LAB nmap XMAS scan | `tcp any any -> $HOME_NET any (flags:FPU;)` | attempted-recon → 2 |
| 1000004 | LAB SSH SYN burst | `tcp any any -> $HOME_NET 22 (flags:S; detection_filter:track by_src, count 5, seconds 60;)` | attempted-admin → 1 |

### 5.3 OSSEC

- `config/ossec.conf`: `<global><jsonout_output>yes</jsonout_output>`. Local files: `/var/log/secure` (syslog), `/var/log/audit/audit.log` (syslog), `/var/log/lab/secure` (syslog, lab input). Rules: the stock includes plus `local_rules.xml`.
- `config/ossec_local_rules.xml` (installed as `/var/ossec/rules/local_rules.xml`):
  - `100010` level 10, `if_sid 5700` (sshd), match `ROOT LOGIN REFUSED`: "Root SSH login attempt blocked by hardening policy".
  - `100020` level 12, `<if_sid>5720</if_sid>`: "SSH authentication failures from one source (possible brute force)". It is a child of the stock composite rule 5720 (`sshd_rules.xml`: level 10, `frequency 6`, `if_matched_sid 5716`, `same_source_ip`), which already matches repeated failures first. A separate `if_matched_sid 5716` rule would never be reached. 100020 only raises the level and gives a lab-specific description.
  - OSSEC's frequency check (`analysisd/eventinfo.c`) needs more earlier matches than the `frequency` value (8 events in total for `frequency 6`), so the brute-force fixture holds **10** `Failed password` lines from `10.42.0.20`.
- JSON alert (one per line in `/var/ossec/logs/alerts/alerts.json`). OSSEC 2.9.4's `src/analysisd/format/to_json.c` emits only these keys, each only when the value is set: `rule.{level,comment,sidid,cve,info}`, `action`, `srcip`, `srcport`, `srcuser`, `dstip`, `dstport`, `dstuser`, `location`, `full_log`, `file`. There is no rule group, alert id, timestamp or hostname. Expected shape:
  `{"rule":{"level":12,"comment":"SSH authentication failures from one source (possible brute force)","sidid":100020},"srcip":"10.42.0.20","dstuser":"root","location":"/var/log/lab/secure","full_log":"Jul 20 14:03:11 target sshd[2211]: Failed password for root from 10.42.0.20 port 40022 ssh2"}`
  T8 captures a real alert from the built image into `tests/fixtures/ossec_alert.json`. That fixture is the contract: if it differs from the shape above, this section is corrected to match it in the same commit.

### 5.4 pfSense filterlog (simulated, UDP syslog to Logstash:5140)

```
<134>Jul 20 14:03:11 filterlog: 5,,,1000000103,em0,match,block,in,4,0x0,,64,12345,0,none,6,tcp,60,8.8.8.8,10.42.0.10,51234,22,0,S,123456,,64240,,mss
```

Logstash extracts `fw_rule`, `fw_interface`, `fw_reason`, `fw_action`, `fw_direction`, `proto`, `src_ip`, `dst_ip`, `src_port`, `dst_port` for IPv4 TCP/UDP. Any other line is tagged `_pfsense_unparsed`.

### 5.5 Elasticsearch document (common fields)

| Field | Type | Sources |
|---|---|---|
| `@timestamp` | date | all |
| `log_type` | keyword | `snort`, `ossec`, `pfsense`, `secure`, `audit` |
| `hostname`, `beat.hostname` | keyword | filebeat (`hostname` from `[host][name]`), pfsense (`hostname` from the UDP input's `host`) |
| `src_ip`, `dst_ip` | ip | snort, ossec (`srcip`), pfsense |
| `src_port`, `dst_port` | integer | snort, pfsense |
| `proto` | keyword | snort, pfsense |
| `gid`, `sid`, `rev` | integer | snort |
| `alert_msg`, `classification` | keyword (+text) | snort |
| `priority` | integer | snort |
| `rule_id`, `alert_level` | integer | ossec (`rule.sidid`, `rule.level`) |
| `alert_description` | keyword | ossec (`rule.comment`) |
| `fw_action`, `fw_interface`, `fw_direction`, `fw_rule`, `fw_reason` | keyword | pfsense |
| `geoip.*` (`country_code2`, `location` geo_point) | object | any event with a public `src_ip` |

Index: `security-%{log_type}-%{+YYYY.MM.dd}`. Template: `elk/es-template.json`, `index_patterns: ["security-*"]`, single mapping type `doc`.

`host` is **not** mapped in the template. Beats 6.3 adds a `host.name` object field to every event, while the Logstash `udp` input sets `host` to a string, so any fixed mapping for `host` rejects one of the two with `mapper_parsing_exception`. (This is the known 6.3 Beats/Logstash conflict; T10 confirms it against the 6.3.2 Beats release notes and records the note in `elk/logstash.conf`.) Logstash therefore copies `[host][name]` (beats) or `host` (udp) into `hostname` and removes `host` before output.

`@timestamp` for OSSEC events: the JSON alert has no timestamp, so Logstash parses the syslog prefix of `full_log` with a `date` filter (`MMM dd HH:mm:ss`, `MMM  d HH:mm:ss`). If that fails, the event keeps the Filebeat read time and gets the tag `_ossec_time_fallback`.

Email (logstash `email` output): sent when `log_type == "snort"` and `priority <= 2`. Server `${SMTP_HOST:mailhog}:${SMTP_PORT:1025}`, to `${ALERT_TO:security@example.local}`, subject `High Priority Snort Alert: %{alert_msg}`.

### 5.6 Filebeat (`elk/filebeat.yml`)

`filebeat.inputs` (6.3 syntax), one `log` input per source, each with `fields: {log_type: ...}` and `fields_under_root: false`. The OSSEC input uses `json.keys_under_root: false` and `json.add_error_key: true`. `output.logstash.hosts: ["${LOGSTASH_HOST:logstash:5044}"]`.

### 5.7 `tools/correlate.py`

```
python tools/correlate.py [--es http://elasticsearch:9200] [--since 15m] [--window 900]
                          [--min-events 2] [--format table|json|ansible] [--fail-on-match]
exit: 0 ok · 3 matches found and --fail-on-match · 1 ES/usage error
```

The library functions (`tools/correlate.py`, importable, Python 3.6-compatible, no dataclasses):

- `parse_since(s) -> datetime.timedelta` for `30s`, `15m`, `2h`, `1d`.
- `correlate(snort_events, ossec_events, window_seconds, min_events) -> list[dict]`. Each event is `{"@timestamp": iso, "src_ip": str, ...}`. An IP matches when at least one Snort event and one OSSEC event from that IP fall within `window_seconds` of each other and the total count is ≥ `min_events`. Each result is `{src_ip, snort_count, ossec_count, first_seen, last_seen, sids, rule_ids, min_priority, max_level}`, sorted by (min_priority asc, max_level desc, src_ip).
- `fetch_events(es, index_pattern, since, until) -> list[dict]` (elasticsearch-py `helpers.scan` with a `range` on `@timestamp` and `exists: src_ip`).
- `--format ansible` prints `{"block_ips": ["10.42.0.20", ...]}`.

### 5.8 `ansible/respond_block_ip.yml`

```
ansible-playbook -i INVENTORY ansible/respond_block_ip.yml -e @blocklist.json [-e block_state=absent] [-e respond_hosts=all]
vars: block_ips (list, required, each validated with the ipaddr filter → netaddr), block_state present|absent,
      respond_zone (default drop)
```

It uses the `firewalld` module (`rich_rule: 'rule family="ipv4" source address="X" drop'`, `permanent: true`, `immediate: true`) when `firewalld` is active (detected with `firewall-cmd --state`, `changed_when: false`, `failed_when: false`, where a non-zero exit means not active; `systemctl is-active` is avoided because ansible-lint's ANSIBLE0006 flags it and Ansible 2.4 has no `service_facts`), and `firewall-offline-cmd --zone=... --add-rich-rule/--remove-rich-rule` guarded by `--query-rich-rule` otherwise. The second run reports `changed=0`.

### 5.9 Ansible layout and inventory

- `ansible/ansible.cfg`: `inventory = inventory/docker.ini`, `host_key_checking = False`, `retry_files_enabled = False`, `roles_path` unused. Ansible only reads `ansible.cfg` from the current directory, so the `tests` service sets `ANSIBLE_CONFIG=/src/ansible/ansible.cfg`.
- `ansible/inventory/docker.ini`: groups `targets` (host `target`, user `ansible`, key `/lab/keys/id_rsa`), `ids_sensors` (`target`), `elk_server` (empty in the lab). Vars: `hardening_manage_services=false`, `snort_manage_service=false`, `ossec_manage_service=false`, `filebeat_manage_service=false`.
- `ansible/inventory/example.ini`: a documented example for real hosts (not used in tests). It notes that real hosts need a yum repo that carries the pinned NVRs below (for example a copy of the base image's `/opt/pinned-rpms`).
- `ansible/group_vars/all.yml`: `snort_version: 2.9.11.1`, `daq_version: 2.0.6`, `ossec_version: 2.9.4`, `elastic_version: 6.3.2`, `hardening_update_all_packages: false`, `hardening_packages` as exact NVRs: `aide-0.15.1-13.el7`, `rkhunter-1.4.6-1.el7`, `clamav-0.99.2-1.el7`, `clamav-data-empty-0.99.2-1.el7`, `fail2ban-0.9.7-1.el7`, `audit-2.8.1-3.el7`, `firewalld-0.4.4.4-14.el7`.
- `ansible/hardening.yml` (site playbook), plays in order: hardening (all) → OSSEC (all) → Snort (ids_sensors) → Filebeat (all) → ELK (elk_server). Each play is tagged `hardening`, `ossec`, `snort`, `filebeat`, `elk`, and docs and tasks refer to plays by tag, never by number. Loops use `with_items:` (the `loop:` keyword only exists from Ansible 2.5).

### 5.10 Makefile targets (host)

| Target | Runs |
|---|---|
| `build` | `docker compose build base` then `docker compose build` (from T2 on; in T1 only `tests` exists) |
| `test` | every `test-*` target below, in order |
| `test-static` | tests image: yamllint, shellcheck, `bash -n`, `ansible-playbook --syntax-check`, ansible-lint, `python -m py_compile` |
| `test-unit` | tests image: `pytest tests/unit` |
| `test-base` | base image: `bats tests/bats/base.bats` |
| `test-harden` | base image: `bats tests/bats/harden_linux.bats` |
| `test-snort` | runs `lab-down` first (the lab's static IPs clash with one-off containers); tests image writes pcaps to the `pcaps` volume; snort image (`run --rm --no-deps`): `bats tests/bats/snort.bats` |
| `test-ossec` | runs `lab-down` first; ossec image (`run --rm --no-deps`): `bats tests/bats/ossec.bats` |
| `test-ansible` | starts `target`; tests image: hardening/snort/ossec/filebeat plays twice plus testinfra |
| `test-pipeline` | starts ES, Logstash, Filebeat, MailHog; tests image: `pytest tests/integration/test_pipeline.py` |
| `test-e2e` | full lab; tests image: `pytest tests/integration/test_end_to_end.py tests/integration/test_response.py` |
| `lab-up` / `lab-down` / `demo` / `shell` / `clean` | convenience targets |

## 6. Stack & pinned versions

Python packages are pinned in `requirements-dev.txt` and installed with `pip install --no-deps -r`, so no transitive dependency can float. These pins were checked with `tools/check_period.py` against the period end of 2018-08-31 (30 packages, 0 problems).

| Component | Version | Released | Why it was the popular choice then |
|---|---|---|---|
| CentOS | 7.5.1804 | 2018-05-10 | The current RHEL-compatible server OS in mid-2018. The existing script and playbook target it (yum, firewalld). |
| Bash | 4.2.46 (CentOS 7 base) | shipped with 7.5 | The system shell on the target OS. |
| Python (tooling) | 3.6.6 | 2018-06-27 | Latest Python 3 at the time. Ansible 2.4 supports Python 3 on the control node. |
| Python (managed nodes) | 2.7.5 (CentOS 7 base) | shipped with 7.5 | Ansible's default interpreter on EL7 in 2018. |
| ansible | 2.4.6.0 | 2018-07-05 | The assigned target stack is Ansible 2.4. 2.4.6.0 is the last 2.4 release in the period. Playbooks avoid 2.5-only syntax such as `loop:` and use `with_items:`. |
| ansible-lint | 3.4.23 | 2018-06-18 | Last stable 3.4.x. 3.5 was still an RC. |
| yamllint | 1.11.1 | 2018-04-06 | Current release. |
| Jinja2 | 2.10 | 2017-11-08 | Ansible dependency. |
| MarkupSafe | 1.0 | 2017-03-07 | Jinja2 dependency. |
| PyYAML | 3.13 | 2018-07-05 | Ansible/yamllint dependency. |
| paramiko | 2.4.1 | 2018-03-13 | Ansible dependency. |
| cryptography | 2.3.1 | 2018-08-14 | paramiko dependency. |
| asn1crypto | 0.24.0 | 2017-12-14 | cryptography dependency. |
| cffi | 1.11.5 | 2018-02-27 | cryptography/bcrypt/PyNaCl dependency. |
| pycparser | 2.18 | 2017-07-04 | cffi dependency. |
| bcrypt | 3.1.4 | 2017-10-11 | paramiko dependency. |
| PyNaCl | 1.2.1 | 2017-12-04 | paramiko dependency. |
| pyasn1 | 0.4.4 | 2018-07-26 | paramiko dependency. |
| six | 1.11.0 | 2017-09-17 | Many dependents. |
| idna | 2.7 | 2018-06-11 | cryptography/requests dependency. |
| pathspec | 0.5.6 | 2018-04-06 | yamllint dependency. |
| netaddr | 0.7.19 | 2017-01-13 | Needed by Ansible's `ipaddr` filter (F12). |
| pytest | 3.5.1 | 2018-04-24 | The most-used Python test runner. 3.5.1 is the newest release whose dependencies are all verifiable in the period: pytest ≥ 3.6 needs `atomicwrites`, and every atomicwrites file on PyPI was re-uploaded in 2022. |
| py | 1.5.4 | 2018-06-27 | pytest dependency. |
| attrs | 18.1.0 | 2018-05-03 | pytest dependency. |
| more-itertools | 4.3.0 | 2018-07-31 | pytest dependency. |
| pluggy | 0.6.0 | 2017-11-24 | pytest 3.5 needs `<0.7`. |
| testinfra | 1.14.1 | 2018-07-23 | The standard server-state test library for Ansible/Molecule in 2018. It has an Ansible inventory backend. |
| elasticsearch (py) | 6.3.1 | 2018-08-09 | Official client matching ES 6.3. |
| urllib3 | 1.23 | 2018-06-05 | elasticsearch/requests dependency. |
| requests | 2.19.1 | 2018-06-14 | Used to query the MailHog API in tests. |
| chardet | 3.0.4 | 2017-06-08 | requests dependency. |
| certifi | 2018.8.24 | 2018-08-24 | requests dependency. |
| scapy | 2.4.0 | 2018-03-27 | First release with Python 3 support. Crafts pcaps and live packets (F14). |
| Snort | 2.9.11.1 | 2017-12-06 (ChangeLog; tarball 2017-12-20) | Latest Snort 2 during the whole period. 2.9.12 came out in September 2018 (ChangeLog 2018-09-18), so the old `snort_version: "2.9.12"` is replaced. Snort 3 was alpha. |
| DAQ | 2.0.6 | 2015-07-15 | The DAQ version required by Snort 2.9.11.x. |
| OSSEC HIDS | 2.9.4 | 2018-06-20 (git tag) | The 2.9 line the README names. 3.0.0 was tagged only on 2018-06-26. |
| Elasticsearch / Logstash / Kibana / Filebeat | 6.3.2 | 2018-07-24 | The stable 6.x release for most of summer 2018. 6.4.0 came on 2018-08-23, a week before the period ends. The old playbook's `6.5.0` (November 2018) is out of period. |
| MailHog | 1.0.0 | 2017-04-16 | The usual SMTP catch-all for dev and test in 2017–2018. |
| bats-core | 1.1.0 | 2018-07-09 | The maintained fork of bats, and the standard Bash test framework. |
| ShellCheck | 0.5.0 | 2018-06-01 (Docker tag push) | Current release. |
| firewalld | 0.4.4.4-14.el7 (CentOS 7.5 GA) | built 2018-04-11 | Default EL7 firewall. |
| Docker Compose file format | 2.4 | Compose 1.21, 2018-04 | Supports `platform:` and single-host `depends_on` conditions. |

OS packages (RPMs). The base image enables only the CentOS 7.5.1804 `os` vault repo, which holds a single GA build per package, so these are the only versions yum can resolve. Build dates are the RPM `buildtime` from the repo metadata. `tests/bats/base.bats` asserts each with `rpm -q <nvr>` after installing it, or `yum -q list available <nvr>` for build-only packages that the base image does not install.

| Package (NVR) | Source | Built | Used by |
|---|---|---|---|
| `gcc-4.8.5-28.el7`, `gcc-c++-4.8.5-28.el7` | CentOS 7.5 os | 2018-04-10 | Snort/DAQ/OSSEC builds |
| `make-3.82-23.el7` | CentOS 7.5 os | 2016-11-05 | builds |
| `flex-2.5.37-3.el7`, `bison-3.0.4-1.el7` | CentOS 7.5 os | 2014-06-09, 2017-08-02 | DAQ/Snort builds |
| `libpcap-devel-1.5.3-11.el7` | CentOS 7.5 os | 2018-04-11 | DAQ/Snort builds |
| `pcre-devel-8.32-17.el7` | CentOS 7.5 os | 2017-08-02 | Snort build |
| `zlib-devel-1.2.7-17.el7` | CentOS 7.5 os | 2016-11-05 | Snort build |
| `openssl-devel-1.0.2k-12.el7` (with `openssl-libs-1.0.2k-12.el7`) | CentOS 7.5 os | 2018-04-11 | Snort/OSSEC builds |
| `openssh-server-7.4p1-16.el7`, `openssh-clients-7.4p1-16.el7` | CentOS 7.5 os | 2018-04-11 | target |
| `python-2.7.5-68.el7` | CentOS 7.5 os | 2018-04-11 | target (Ansible managed node) |
| `sudo-1.8.19p2-13.el7` | CentOS 7.5 os | 2018-04-11 | base, target |
| `firewalld-0.4.4.4-14.el7` | CentOS 7.5 os | 2018-04-11 | base (`firewall-offline-cmd`), hardening |
| `aide-0.15.1-13.el7`, `audit-2.8.1-3.el7` | CentOS 7.5 os | 2017-08-03, 2018-04-11 | hardening packages |
| `createrepo-0.9.9-28.el7` | CentOS 7.5 os | 2017-08-03 | base (builds `/opt/pinned-rpms`) |
| `which-2.20-7.el7`, `tar-1.26-34.el7`, `gzip-1.5-10.el7` | CentOS 7.5 os | 2014-06-10, 2018-04-11, 2018-04-11 | base |
| `fail2ban-0.9.7-1.el7` (+ `fail2ban-server`, `fail2ban-firewalld`, `fail2ban-sendmail`, same NVR) | EPEL 7 (file below) | 2017-07-13 | hardening packages. Last EL7 build before 2019 (next: 0.10.4, 2019-11). |
| `rkhunter-1.4.6-1.el7` | EPEL 7 (file below) | 2018-02-25 | hardening packages |
| `clamav-0.99.2-1.el7` (+ `clamav-lib`, `clamav-filesystem`, `clamav-data-empty`, same NVR) | Fedora koji | 2016-06-13 | hardening packages. The in-period builds 0.100.0/0.100.1 were garbage-collected from koji and never reached an archived EPEL snapshot, so 0.99.2-1.el7 is the newest build still downloadable that predates the period end. `clamav-data-empty` keeps the image small; signature updates and scans are out of scope (§3). |
| `libdnet-1.12-0.13.1.el7`, `libdnet-devel-1.12-0.13.1.el7` | EPEL 7 (file below) | 2018-07-23 | DAQ/Snort builds |

Dependencies of those RPMs that are not listed (for example `ipset`, `iptables`, `systemd-python`, `postfix`, `perl`, `libxml2`) come from the same CentOS 7.5 `os` repo, which has one GA build of each.

Download sources for tools that have no registry (each is checked by sha256 in the install scripts):

| Artifact | URL | sha256 |
|---|---|---|
| `snort-2.9.11.1.tar.gz` | `http://distcache.freebsd.org/ports-distfiles/snort-2.9.11.1.tar.gz` (snort.org's archive answers 403 to scripted downloads) | `9f6b3aeac5a109f55504bd370564ac431cb1773507929dc461626898f33f46cd` |
| `daq-2.0.6.tar.gz` | `http://distcache.freebsd.org/ports-distfiles/daq-2.0.6.tar.gz` | `b40e1d1273e08aaeaa86e69d4f28d535b7e53bdb3898adf539266b63137be7cb` |
| `ossec-hids-2.9.4.tar.gz` | `https://github.com/ossec/ossec-hids/archive/2.9.4.tar.gz` | `3a8df000cd2cd3430f0d9a41034df025951579e15dea8e57ad7e7d0291fec7b6` |
| `bats-core-1.1.0.tar.gz` | `https://github.com/bats-core/bats-core/archive/v1.1.0.tar.gz` | `855d8b8bed466bc505e61123d12885500ef6fcdb317ace1b668087364717ea82` |
| Elastic RPMs 6.3.2 | yum repo `https://artifacts.elastic.co/packages/6.x/yum`, key `https://artifacts.elastic.co/GPG-KEY-elasticsearch`, installed as `filebeat-6.3.2` etc. | yum GPG check |
| `fail2ban-0.9.7-1.el7.noarch.rpm` | `https://archives.fedoraproject.org/pub/archive/epel/7.2019-05-29/x86_64/Packages/f/` (the oldest archived EPEL 7 snapshot; the directory date is after the period, but every file taken from it was built before it) | `c3b765326dc27885003e7ba154ee32e6cf57827ca7e1033712b4c2f7418a395e` |
| `fail2ban-server-0.9.7-1.el7.noarch.rpm` | same | `ff460f1595c970b55f4249cc0ca22be14604b968eaa1e5d790f364fd9b820674` |
| `fail2ban-firewalld-0.9.7-1.el7.noarch.rpm` | same | `65f18bca7604130de5928cbea5e7653b353c6c67a066471d2a056ceb1b3475b1` |
| `fail2ban-sendmail-0.9.7-1.el7.noarch.rpm` | same | `a53ef1a15e188e14fe1b24cbb98006011e9a6e8f126df757caac50ea06cb785b` |
| `rkhunter-1.4.6-1.el7.noarch.rpm` | same snapshot, `Packages/r/` | `745aa41299eaf58a82c18c10319ff25d9c9dc7326890ad19aaa0b9bc54fea307` |
| `libdnet-1.12-0.13.1.el7.x86_64.rpm` | same snapshot, `Packages/l/` | `53d0700e60f1e87a15f0b9279510a0675f86bed78e2bd1e4eab898b224c19b99` |
| `libdnet-devel-1.12-0.13.1.el7.x86_64.rpm` | same snapshot, `Packages/l/` | `1217efca7b102fff06edd5315f48f19e9713cfa7123db7085d1ef982e6d36078` |
| `clamav-0.99.2-1.el7.x86_64.rpm` | `https://kojipkgs.fedoraproject.org/packages/clamav/0.99.2/1.el7/x86_64/` | `e4a577dc8c5aab232d616d29db8be60825baf03ef6839d9b3e5513956b03ee96` |
| `clamav-lib-0.99.2-1.el7.x86_64.rpm` | same, `x86_64/` | `a758edd4ac73736e40ed57162bca75c6c9be805a59ea1e3296b4bc8c9336df29` |
| `clamav-filesystem-0.99.2-1.el7.noarch.rpm` | same, `noarch/` | `4ce9de93716d4d0f756e0187d1056e2263516624a627700f4a735b799eee16ba` |
| `clamav-data-empty-0.99.2-1.el7.noarch.rpm` | same, `noarch/` | `0ea1373d14a5cbfa01fe91f01ce03cb09c8bd48a4854d97d9a9d0d99d01647a7` |

## 7. Docker images (tags verified on Docker Hub)

| Image | Tag | Hub API | Last pushed | Arch | Used for |
|---|---|---|---|---|---|
| `python` (library) | `3.6.6-stretch@sha256:5b2e0d981c74fa8b53db311e0c5b7672c8c3958053496f42ef29697cec3af277` (manifest list) | 200 | 2018-10-17 | multi-arch | `docker/tests` (test runner, Ansible control node) |
| `centos` (library) | `7.5.1804@sha256:7a45e4a1efbaafc1d9aa89925b6fdb33288a96d35ea0581412316e2f0ad3720a` (manifest list) | 200 | 2019-05-11 | amd64 | `docker/base` → snort, ossec, target |
| `elastic/elasticsearch` | `6.3.2` | 200 | 2018-07-24 | amd64 | ES |
| `elastic/logstash` | `6.3.2` | 200 | | amd64 | Logstash |
| `elastic/kibana` | `6.3.2` | 200 | | amd64 | Kibana |
| `elastic/filebeat` | `6.3.2` | 200 | 2018-07-24 | amd64 | Filebeat (image user is `filebeat`, not root) |
| `mailhog/mailhog` | `v1.0.0` | 200 | | amd64 | fake SMTP |
| `koalaman/shellcheck` | `v0.5.0` | 200 | | amd64 | build stage only (`COPY --from`) |

Notes:

- The library tags `elasticsearch:6.3.2`, `logstash:6.3.2` and `kibana:6.3.2` return 404 now. The nearest library tag is `6.4.0`, which is after the period. Elastic's own Docker Hub namespace `elastic/*` still has `6.3.2`, so that is used. `docker.elastic.co/{elasticsearch/elasticsearch-oss,logstash/logstash-oss,kibana/kibana-oss,beats/filebeat}:6.3.2` also answer 200 and are the documented fallback.
- The floating `python:3.6` candidate is replaced by the exact `3.6.6-stretch`.
- `python:3.6.6-stretch` (last pushed 2018-10-17) and `centos:7.5.1804` (last pushed 2019-05-11) are post-period rebuilds of in-period releases, and may carry later Debian/CentOS package updates in the base layer. The Dockerfiles pin both by the manifest-list digests above (`FROM image@sha256:...`) so every build uses the same bytes. For `centos`, `base.bats` also asserts the key libraries the builds link against (`openssl-libs-1.0.2k-12.el7`); if the rebuilt rootfs had newer ones, the `openssl-devel` install would fail loudly rather than drift.
- Every service except `tests` is amd64-only. `docker-compose.yml` sets `platform: linux/amd64` on them, so Apple Silicon hosts run them under emulation.
- CentOS 7 mirrors are end-of-life. `docker/base/CentOS-Vault.repo` defines only `[base]` → `https://vault.centos.org/7.5.1804/os/$basearch/` (7.5 GA, 2018-05-10). `updates` and `extras` are deliberately absent, because the 7.5.1804 `updates` repo carries errata up to the 7.6 release (late 2018). No live EPEL repo is configured. The pinned EPEL/koji RPMs (§6) are fetched by URL, sha256-checked, and served from `file:///opt/pinned-rpms` (`pinned-rpms.repo`, `gpgcheck=0`, since integrity comes from the sha256 list). The vault repo, the EPEL snapshot files and the koji files were all checked to answer 200.

## 8. Simulated / mocked integrations

| Real thing | Replacement | Notes |
|---|---|---|
| pfSense 2.4 firewall | **pfSense simulator** `tools/pfsense_sim.py` | Sends recorded pfSense 2.4 `filterlog` lines (`tests/fixtures/pfsense_filterlog.log`) as RFC3164 syslog over UDP to Logstash. It never talks to a real pfSense. |
| Corporate SMTP relay / security mailbox | **MailHog** `mailhog/mailhog:v1.0.0` | Logstash's email output goes to `mailhog:1025`. Tests read `http://mailhog:8025/api/v2/messages`. |
| Real servers and network sensors | **CentOS 7.5 containers** (`target`, `snort`, `ossec`) | Services run without systemd. Plays take a `*_manage_service` flag that the lab inventory sets to false. |
| Hostile network traffic | **scapy traffic generator** `tools/traffic.py` | Crafted packets (ICMP probe, telnet SYN, XMAS, SSH SYN burst, benign) written as pcaps or sent live on the isolated compose network only. |
| SSH brute-force against a real host | **log-line injection** | Test fixtures of real CentOS 7 sshd log lines, appended to the OSSEC lab input file. |
| Running firewalld | **`firewall-offline-cmd`** | firewalld needs D-Bus and systemd, so containers edit the permanent zone XML. Live `firewall-cmd` paths run only on real hosts. |

## 9. Existing code inventory (`git ls-files` at HEAD)

| File | Decision | Reason |
|---|---|---|
| `README.md` | refactor (regenerate, last task) | It still says "Comprehensive ... initiative", describes pfSense/OSSEC as if they were built, and wrongly calls the script Debian/Ubuntu-oriented. It will be rewritten from `tools/readme_template.md`. |
| `ansible/hardening.yml` | refactor | The play structure (all / ids_sensors / elk_server) and package list are kept. Fixes: it calls a missing `deploy_ossec.sh`; it pins out-of-period `snort 2.9.12` and ELK `6.5.0`; it runs an unconditional `yum '*' latest`; its `copy: src: ../config` paths are fragile; it has no Filebeat play; the ELK play's `loop:` needs Ansible 2.5 and becomes `with_items:` for the pinned 2.4; the Snort play installs `daq` from yum, which no configured repo has. Adds tags, service flags and exact package NVRs. |
| `config/snort.conf` | refactor | The variables, portvars, logdir, pcre limits, search method and fast output are kept. It needs `ipvar` for IP variables, dynamic engine/preprocessor paths, frag3/stream5, the classification/reference includes, and the missing `local.rules`. The `community.rules` include becomes an optional commented line so `snort -T` passes. |
| `elk/logstash.conf` | refactor | The input/filter/output structure, Snort grok idea, GeoIP, dated index and email alert are kept. Fixes: the grok extracts no IPs, so GeoIP never matched; `rename => "rule.level"` is wrong for nested fields (must be `[rule][level]`); it relies on `type`, which Filebeat 6 no longer sets; ES and SMTP hosts are hard-coded. Adds pfSense syslog input and the template. |
| `scripts/harden_linux.sh` | refactor | All eight hardening steps and their values are kept. Fixes: it is not idempotent (appends to sysctl.conf and sshd_config each run); the `sed` patterns leave CentOS 7's uncommented `PasswordAuthentication yes` in place as a conflicting duplicate after the rewritten commented line (the effective value is already `no`, because sshd uses the first one); `chmod /etc/cron.d/*` fails under `set -e` on an empty directory; `Protocol 2` is obsolete. Adds `--check`, `--root`, skip flags and `CHANGED:` output for Ansible and bats. |

New files the original README listed that were never committed: `scripts/setup_snort.sh`, `scripts/deploy_ossec.sh`, `config/ossec.conf`. They are created in T6/T8.

## 10. Test strategy

All tests run in containers through `make test`. Every task adds its suite to `test`, so the target stays green commit by commit.

1. **Static** (`test-static`, tests image): yamllint (`.yamllint`, line length 120) over `ansible/`, `elk/*.yml` and `docker-compose.yml`; shellcheck 0.5.0 over `scripts/*.sh` and `docker/*/*.sh`; `bash -n`; `ansible-playbook --syntax-check` for both playbooks; ansible-lint 3.4.23 (with `.ansible-lint`, whose `skip_list` is empty; the one deliberate `state: latest` task carries the `skip_ansible_lint` tag, and no other task, including in `respond_block_ip.yml`, has a lint exception); `python -m py_compile tools/*.py`; a JSON parse of `elk/es-template.json`.
2. **Unit, Python** (`test-unit`): `tests/unit/test_correlate.py` covers window edges, `min_events`, sort order, IPs seen by only one source, `parse_since` errors, and the ansible/json formatters. `tests/unit/test_traffic.py` checks that each generated pcap has the expected packet flags, payload and count. `tests/unit/test_pfsense_sim.py` checks syslog framing and timestamp rewrite. `tests/unit/test_requirements.py` checks that every requirement is `==`-pinned.
3. **Unit, Bash** (`test-harden`, base CentOS image with bats 1.1.0): runs `harden_linux.sh --root $BATS_TMPDIR/root --skip-services --skip-packages` against a fixture rootfs copied from stock CentOS 7.5 files (`tests/fixtures/rootfs/`). Creates an empty `etc/cron.d` in setup (git does not track empty directories). Asserts each setting, that exactly one `PasswordAuthentication no` line remains, that the firewall step wrote `etc/firewalld/firewalld.conf` (`DefaultZone=drop`) and `etc/firewalld/zones/drop.xml` under the fixture root and left the container's own `/etc/firewalld` untouched, that a second run prints no `CHANGED:`, that `--check` exits 2 before and 0 after, the empty `cron.d` case, `--only`, and the non-root refusal.
4. **Snort** (`test-snort`): `snort -V` reports 2.9.11.1. `snort -T -c /etc/snort/snort.conf` passes. Each pcap from `tools/traffic.py write` fires exactly its expected SID in `-A fast` output (the SSH burst fires only after the 5th SYN). The benign pcap produces no alerts.
5. **OSSEC** (`test-ossec`): `ossec-logtest` on fixture lines gives rule 5716 (failed password), 100010 (ROOT LOGIN REFUSED) and 5715 (accepted). With the daemons started, appending 10 failures from one IP produces a JSON line with `sidid` 100020 in `alerts.json` within 30 s. The captured line becomes `tests/fixtures/ossec_alert.json`, and a test checks that its key set is a subset of the §5.3 list.
6. **Ansible integration** (`test-ansible`): each play runs against the `target` container twice. The second run must have `changed=0`, checked by parsing the `PLAY RECAP`. testinfra (`--hosts=ansible://targets --sudo`, because `sshd -T` and `/etc/shadow` need root) then checks `sshd -T` effective values, login.defs, sysctl drop-in, audit rules, jail.local, `drop` zone XML, packages installed, `snort -V`, `/var/ossec/etc/ossec.conf`, and the filebeat package version and config.
7. **Pipeline integration** (`test-pipeline`): fixture Snort/OSSEC/secure/audit lines written to the volumes Filebeat reads, plus a pfSense UDP send. Asserts parsed documents in each `security-*` index (fields from §5.5, `src_ip` mapped as `ip`), that every fixture line produced exactly one document with no `_grokparsefailure` tag and no mapping rejection in the Logstash log, GeoIP on the public-IP pfSense event, and exactly one MailHog message for the priority-1 Snort alert and none for priority 3.
8. **End-to-end** (`test-e2e`): live scapy traffic to the `snort` container and log injection into `ossec` from the same lab IP. Both indices get documents, `correlate.py --format ansible` returns that IP, `respond_block_ip.yml` adds the rich rule on `target` (idempotent), and `block_state=absent` removes it.

`make test-pipeline` greps the Filebeat container log for `permission denied` and fails with that message instead of a bare document timeout. Integration fixtures poll with timeouts: ES cluster health yellow within 120 s, and each document within 60 s. The timeouts are generous because amd64 images may run under emulation.

## 11. Known limitations that will remain

- Nothing is enabled or started through systemd in tests. `systemctl` paths (sshd restart, auditd, fail2ban, snort/ossec/filebeat units, ELK services) are exercised only by lint and syntax checks.
- The `elk`-tagged server play is illustrative only (moved out of scope, §3): it is syntax-checked and linted, never executed. The runtime ELK stack in the lab comes from the official 6.3.2 Docker images at the same version.
- OS packages are the CentOS 7.5 GA builds with no errata from the `updates` repo, so the lab lacks security fixes released after May 2018. ClamAV is 0.99.2 (2016), because the mid-2018 EL7 builds are no longer downloadable (§6).
- Snort sees only traffic on the compose bridge that reaches its own container. It is not a SPAN/TAP deployment. The Snort ruleset is the four local rules only.
- OSSEC runs in local mode on each host. There is no central OSSEC manager and no active response. Blocking is done by F12.
- Correlation is by source IP and time window only. It polls ES (no streaming) and cannot tell apart hosts behind the same NAT.
- `harden_linux.sh` and the plays are CentOS/RHEL 7 only.
- The lab SSH key for `target` is generated at container start into a Docker volume. It is lab-only.
- The amd64-only images run slowly under emulation on ARM hosts. Elasticsearch runs with `xpack.ml.enabled=false`, because the ML native controller tends to fail under amd64 emulation. Elasticsearch may need `vm.max_map_count=262144` on Linux hosts.
