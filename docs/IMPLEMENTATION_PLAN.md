# cybersecurity — Implementation Plan

Each task is one commit and leaves `make test` green. Tasks are in dependency order.
All commands run from the repo root on a host with Docker. Nothing else is installed locally.
Versions, images, schemas and CLI signatures are the ones in `docs/SPEC.md`. Section references (§) point there.

Conventions:

- `COMPOSE ?= docker compose`. Every `test-*` target runs inside a period container (§5.10).
- A task that adds a `test-*` target also appends it to the `test:` prerequisite list.
- Every compose service that builds an image uses the repo root as its build context:
  `build: {context: ., dockerfile: docker/<svc>/Dockerfile}`. Dockerfiles `COPY` repo paths such as `scripts/...` and `config/...`, and the root `.dockerignore` applies to all of them.
- In T1, `make build` builds only `tests`. From T2 on it builds `base` first, because `snort`, `ossec` and `target` are `FROM cybersecurity:base`.
- The `tests` image sets `ANSIBLE_CONFIG=/src/ansible/ansible.cfg`, so every `ansible-playbook` run from `/src` picks up the lab config.
- Plays in `ansible/hardening.yml` are referred to by tag (`hardening`, `ossec`, `snort`, `filebeat`, `elk`), never by number. Loops use `with_items:` (Ansible 2.4 has no `loop:`).
- The Docker host is shared, so the lab stays in its own lane: compose project `cybersecurity`, images named `cybersecurity:<tag>` (`cybersecurity:tests`, `cybersecurity:base`, ...), network subnet `172.48.0.0/24`, and any port published to the host is taken from `20800`–`20899` (for example Kibana `20856:5601`, MailHog `20825:8025`).
- OS packages are installed by exact NVR from §6. Python in `tools/` and `tests/` must run on Python 3.6. Bash must run on CentOS 7's bash 4.2.

---

## T1 — Scaffold Docker test image, Makefile and static/unit harness

**Goal:** `make test` runs lint and pytest inside `python:3.6.6-stretch` with every pinned tool, from the first commit.

**Files**
- create `docker/tests/Dockerfile` (build context: repo root):
  - `FROM koalaman/shellcheck:v0.5.0 AS shellcheck`, then `FROM python:3.6.6-stretch@sha256:5b2e0d981c74fa8b53db311e0c5b7672c8c3958053496f42ef29697cec3af277`.
  - `COPY --from=shellcheck /bin/shellcheck /usr/local/bin/`.
  - `COPY requirements-dev.txt /tmp/`, then `pip install --no-deps -r /tmp/requirements-dev.txt && pip check`.
  - `ENV ANSIBLE_CONFIG=/src/ansible/ansible.cfg`; `WORKDIR /src`.
- create `requirements-dev.txt`: the 30 exact pins from §6 (`ansible==2.4.6.0`).
- create `docker-compose.yml`:
  - format `2.4`; top-level `name: cybersecurity`; network `lab` (subnet `172.48.0.0/24`).
  - service `tests`: `build: {context: ., dockerfile: docker/tests/Dockerfile}`, `image: cybersecurity:tests`, mounts `.:/src`, joins `lab`.
- create `Makefile`: `build` (`$(COMPOSE) build tests`), `test`, `test-static`, `test-unit`, `shell`, `clean`.
  - `test-static` runs `yamllint -s ansible docker-compose.yml`, `shellcheck scripts/*.sh`, `bash -n scripts/*.sh`, and `ansible-playbook -i localhost, --syntax-check ansible/hardening.yml`.
- modify `ansible/hardening.yml`: replace the ELK play's `loop:` with `with_items:`. It is the only Ansible 2.5 keyword in the file, and 2.4's syntax check rejects it. Nothing else changes.
- create `.yamllint`: extends default, `line-length: {max: 120}`, `truthy: disable`.
- create `pytest.ini`: `testpaths = tests/unit`.
- create `tests/unit/test_requirements.py`.
- create `.gitignore`: `__pycache__/`, `.pytest_cache/`, `out/`, `*.retry`.
- create `.dockerignore`: `.git`, `out`.
- modify `scripts/harden_linux.sh` only if shellcheck 0.5.0 reports errors (quoting only, no behaviour change).

**Tests to write first:** `test_requirements.py` checks that:
- every non-comment line of `requirements-dev.txt` matches `^[A-Za-z0-9_.-]+==[0-9][^ ]*$`;
- `ansible.__version__ == "2.4.6.0"`, `pytest.__version__ == "3.5.1"` and `testinfra` imports;
- `subprocess.check_output(["shellcheck", "--version"])` contains `0.5.0`.

**Acceptance:** `make build && make test`

**Commit:**
```
Add Docker test harness with pinned Ansible and lint tooling

Build a Python 3.6 image with Ansible 2.4, yamllint, shellcheck and
pytest pinned to exact versions, and a Makefile that runs them in Docker.
Replace the one Ansible 2.5 loop keyword so the playbook parses on 2.4.
```

---

## T2 — Add CentOS 7.5 base image with GA vault repo, pinned RPMs and bats

**Goal:** A reproducible CentOS 7.5.1804 image for the snort, ossec and target images and for Bash tests, in which yum can only resolve the package versions listed in §6.

**Files**
- create `docker/base/Dockerfile` (build context: repo root):
  - `FROM centos:7.5.1804@sha256:7a45e4a1efbaafc1d9aa89925b6fdb33288a96d35ea0581412316e2f0ad3720a`.
  - `rm -f /etc/yum.repos.d/*.repo`; `COPY docker/base/CentOS-Vault.repo docker/base/pinned-rpms.repo /etc/yum.repos.d/`.
  - `rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7`.
  - `yum install -y --disablerepo=pinned-rpms which-2.20-7.el7 tar-1.26-34.el7 gzip-1.5-10.el7 make-3.82-23.el7 sudo-1.8.19p2-13.el7 firewalld-0.4.4.4-14.el7 createrepo-0.9.9-28.el7`.
  - `COPY docker/base/pinned-rpms.txt docker/base/fetch_pinned_rpms.sh /tmp/`; run `fetch_pinned_rpms.sh /opt/pinned-rpms`, which downloads each URL, runs `sha256sum -c` and then `createrepo /opt/pinned-rpms`.
  - Install bats-core 1.1.0 from the tarball, sha256-checked (§6), into `/usr/local`.
  - `yum clean all`; `WORKDIR /src`.
- create `docker/base/CentOS-Vault.repo`: a single `[base]` section, `baseurl=https://vault.centos.org/7.5.1804/os/$basearch/`, `gpgcheck=1`. No `updates` and no `extras`.
- create `docker/base/pinned-rpms.repo`: `[pinned-rpms]`, `baseurl=file:///opt/pinned-rpms`, `gpgcheck=0` (integrity comes from the sha256 list).
- create `docker/base/pinned-rpms.txt`: one `<sha256>  <url>` line per EPEL/koji RPM in the §6 download table (fail2ban ×4, rkhunter, libdnet ×2, clamav ×4).
- create `docker/base/fetch_pinned_rpms.sh`.
- modify `docker-compose.yml`: service `base` (`build: {context: ., dockerfile: docker/base/Dockerfile}`, `image: cybersecurity:base`, `platform: linux/amd64`, mounts `.:/src`).
- modify `Makefile`: `build` builds `base` first, then the rest; add `test-base` (`$(COMPOSE) run --rm --no-deps base bats tests/bats/base.bats`); add `shellcheck docker/*/*.sh` to `test-static`.
- create `tests/bats/base.bats`.

**Tests to write first:** `base.bats` checks that:
- `/etc/centos-release` contains `7.5.1804`;
- `bats --version` contains `1.1.0`;
- `yum -q repolist enabled` lists exactly `base` and `pinned-rpms`;
- `rpm -q` succeeds for each NVR the image installs (`which-2.20-7.el7`, `tar-1.26-34.el7`, `gzip-1.5-10.el7`, `make-3.82-23.el7`, `sudo-1.8.19p2-13.el7`, `firewalld-0.4.4.4-14.el7`, `createrepo-0.9.9-28.el7`) and for `openssl-libs-1.0.2k-12.el7` from the base rootfs;
- `yum -q list <nvr>` (installed or available) succeeds for the build and target NVRs in §6 (`gcc-4.8.5-28.el7`, `libpcap-devel-1.5.3-11.el7`, `pcre-devel-8.32-17.el7`, `openssl-devel-1.0.2k-12.el7`, `libdnet-devel-1.12-0.13.1.el7`, `openssh-server-7.4p1-16.el7`, `python-2.7.5-68.el7`, `fail2ban-0.9.7-1.el7`, `rkhunter-1.4.6-1.el7`, `clamav-0.99.2-1.el7`, `clamav-data-empty-0.99.2-1.el7`);
- `yum -q list available --showduplicates fail2ban clamav` shows only the pinned versions, so no newer build is reachable;
- `firewall-offline-cmd --version` prints `0.4.4.4`.

**Acceptance:** `make build && make test`

**Commit:**
```
Add CentOS 7.5 base image limited to GA packages and pinned RPMs

Point yum only at the 7.5.1804 vault os tree, serve checksum-verified
EPEL builds from a local repo so every package predates the target
period, and bundle bats-core 1.1.0 for shell tests.
```

---

## T3 — Make harden_linux.sh idempotent and testable

**Goal:** Implement §5.1, keeping the eight existing steps and values.

**Files**
- modify `scripts/harden_linux.sh`:
  - argument parsing (`--check`, `--root`, `--skip-services`, `--skip-packages`, `--only`) and the env equivalents;
  - helpers `set_kv FILE KEY VALUE SEP` (replace commented or uncommented line, or append), `write_if_changed FILE`, `ensure_mode PATH MODE OWNER`, `changed MSG`;
  - every step `mkdir -p`s its target directories under `$ROOT`;
  - sysctl moved to the `/etc/sysctl.d/99-hardening.conf` drop-in;
  - `Protocol 2` removed;
  - safe handling of an empty `cron.d`;
  - firewalld: with root `/`, `firewall-cmd` when the daemon is running, else `firewall-offline-cmd`; with any other `--root`, write `$ROOT/etc/firewalld/firewalld.conf` (`DefaultZone=drop`) and `$ROOT/etc/firewalld/zones/drop.xml` directly (§5.1);
  - `NONCOMPLIANT:` and exit 2 in `--check`.
- create `tests/fixtures/rootfs/etc/ssh/sshd_config` (stock CentOS 7.5; `#PermitRootLogin yes`, `#PasswordAuthentication yes` followed by the uncommented `PasswordAuthentication yes`).
- create `tests/fixtures/rootfs/etc/login.defs` (stock values).
- create `tests/fixtures/rootfs/etc/crontab`, `tests/fixtures/rootfs/etc/passwd`, `tests/fixtures/rootfs/etc/shadow`, `tests/fixtures/rootfs/etc/firewalld/firewalld.conf` (stock, `DefaultZone=public`).
- create `tests/bats/harden_linux.bats`.
- modify `Makefile`: `test-harden` runs `$(COMPOSE) run --rm --no-deps base bats tests/bats/harden_linux.bats`.

**Tests to write first:** `harden_linux.bats`. `setup` copies the fixture rootfs to `$BATS_TMPDIR/root` and creates an empty `etc/cron.d` there (git does not track empty directories). Tests check that:
- `--check` exits 2 and lists `PasswordAuthentication`;
- the apply run sets all five sshd options exactly once (`grep -c` = 1), so only one `PasswordAuthentication no` line remains;
- login.defs has 90/7/12;
- the sysctl drop-in holds the 7 keys;
- the audit rules file holds 6 lines;
- jail.local exists;
- `etc/firewalld/firewalld.conf` has `DefaultZone=drop`, `etc/firewalld/zones/drop.xml` has `<service name="ssh"/>` and `<service name="https"/>`, and the container's own `/etc/firewalld/firewalld.conf` checksum is unchanged;
- shadow mode is `000`; `/etc/crontab` mode is `600`;
- an empty `etc/cron.d` does not fail;
- the second run prints no `CHANGED:`;
- `--check` exits 0 after the apply run;
- `--only ssh` touches only sshd_config;
- running as non-root (via `sudo -u nobody`) exits 1.

**Acceptance:** `make test-harden && make test`

**Commit:**
```
Make Linux hardening script idempotent with check mode

Replace blind sed/append edits with helpers that set or append each
option once, add --check/--root/skip flags, and cover it with bats.
```

---

## T4 — Add SSH-managed target container and refactor hardening play

**Goal:** The `hardening` play of `ansible/hardening.yml` hardens the `target` container idempotently, and testinfra verifies the result (F2). The playbook gets its final five-play structure.

**Files**
- create `docker/target/Dockerfile` (build context: repo root): `FROM cybersecurity:base`; `yum install -y openssh-server-7.4p1-16.el7 openssh-clients-7.4p1-16.el7 python-2.7.5-68.el7`; `yum downgrade -y libcom_err-1.42.9-11.el7` (the `centos:7.5.1804` rootfs carries `libcom_err-1.42.9-12.el7_5` from `updates`, and the GA `e2fsprogs` that aide and rkhunter pull in requires exactly `-11.el7`); add user `ansible` with NOPASSWD sudo; `COPY docker/target/entrypoint.sh /usr/local/bin/`.
- create `docker/target/entrypoint.sh`:
  - generate `/lab/keys/id_rsa` if missing (mode 600), install the public key for `ansible`;
  - `ssh-keygen -A`;
  - `exec /usr/sbin/sshd -D -e`.
- create `ansible/ansible.cfg`, `ansible/inventory/docker.ini`, `ansible/inventory/example.ini`, `ansible/group_vars/all.yml` (§5.9, including the NVR list in `hardening_packages`).
- rewrite `ansible/hardening.yml` into the five tagged plays of §5.9, in order:
  - `hardening` (hosts `all`):
    - `yum: name='*' state=latest` only `when: hardening_update_all_packages`, tagged `skip_ansible_lint` with a comment explaining why;
    - `yum: name={{ hardening_packages }} state=present` (retried 3 times with `until`, because the vault mirror is flaky);
    - `script: "{{ playbook_dir }}/../scripts/harden_linux.sh {{ '--skip-services' if not hardening_manage_services else '' }}"` with `register` and `changed_when: "'CHANGED:' in result.stdout"`.
  - `ossec`, `snort`, `filebeat`, `elk`: each a placeholder play with one `debug` task naming the task that fills it (T9, T7, T13, T13). The legacy Snort tasks (yum `daq`, which no repo has, and an unconditional `systemd` start) and the legacy ELK tasks (6.5.0 pins) are removed here, so a full-playbook run and ansible-lint stay green. The broken `deploy_ossec.sh` task is removed and comes back in T9.
- create `.ansible-lint`: `skip_list: []` (documented as empty on purpose; the one exception is tagged in place).
- create `tests/integration/conftest.py`: `wait_for_ssh`, `run_playbook(tags) -> recap dict` parsed from `PLAY RECAP`, and a `pytest_configure` hook that defaults `--ansible-inventory` to `ansible/inventory/docker.ini` (testinfra 1.14's Ansible backend does not read the inventory from `ansible.cfg`).
- create `tests/integration/test_hardening.py`.
- modify `docker-compose.yml`: service `target` (`build: {context: ., dockerfile: docker/target/Dockerfile}`, `platform: linux/amd64`, volume `lab-keys:/lab/keys`); `tests` mounts `lab-keys:/lab/keys:ro`.
- modify `Makefile`:
  - `test-ansible` runs `$(COMPOSE) up -d --force-recreate target` (so the first play run always meets a fresh target), then `$(COMPOSE) run --rm tests pytest --hosts=ansible://targets --sudo tests/integration/test_hardening.py`;
  - add `ansible-lint ansible/hardening.yml` to `test-static`.

**Tests to write first:** `test_hardening.py` (testinfra runs commands with `--sudo`, because `sshd -T` and `/etc/shadow` need root):
- the first run finishes with `failed=0` and `changed>0` (fresh target), the second with `changed=0`;
- `host.run("sshd -T")` has `permitrootlogin no`, `passwordauthentication no` and `maxauthtries 3`;
- for each NVR in `hardening_packages`, `rpm -q <nvr>` succeeds;
- `/etc/sysctl.d/99-hardening.conf` contains `net.ipv4.tcp_syncookies = 1`;
- `/etc/firewalld/zones/drop.xml` contains `<service name="ssh"/>` and `/etc/firewalld/firewalld.conf` has `DefaultZone=drop`;
- `/etc/shadow` mode is `0o000`.

**Acceptance:** `make test-ansible && make test`

**Commit:**
```
Run hardening play against a CentOS 7 target container

Add an SSH-managed CentOS 7.5 target, lab inventory and group vars,
split the playbook into five tagged plays, install pinned package
versions idempotently and verify host state with testinfra.
```

---

## T5 — Add scapy traffic generator for the Snort lab rules

**Goal:** The packet side of F14. Pcaps that match each local Snort rule, plus benign traffic, tested without Snort.

**Files**
- create `tools/traffic.py`:
  - `write DIR` produces `lab_probe.pcap`, `telnet_syn.pcap`, `xmas_scan.pcap`, `ssh_burst.pcap` (6 SYNs), `benign.pcap` (TCP handshake to 443, DNS query);
  - `send HOST [--only NAME]` sends the same packets live;
  - the source IP defaults to `172.48.0.20` for pcaps.
- create `tests/unit/test_traffic.py`.
- modify `Makefile`: `test-unit` also covers `test_traffic.py` (it is under `tests/unit`, so only the `py_compile` list in `test-static` changes).

**Tests to write first:** `test_traffic.py` (scapy `rdpcap`, pcaps written to pytest's `tmpdir`; pytest 3.5.1 predates `tmp_path`) checks flags and ports per pcap, 6 SYN packets to port 22 in `ssh_burst`, the `LAB-PROBE` payload with ICMP type 8, FIN+PSH+URG in `xmas_scan`, and that `benign.pcap` has no packet to port 22 or 23.

**Acceptance:** `make test-unit && make test`

**Commit:**
```
Add scapy traffic generator for the lab Snort rules

Write or send ICMP probe, telnet SYN, XMAS scan, SSH SYN burst and
benign packets, with unit tests on the generated pcaps.
```

---

## T6 — Build Snort 2.9.11.1 sensor from source with local rules

**Goal:** F3 and F4. A working Snort sensor image built by the same script Ansible will use.

**Files**
- create `scripts/setup_snort.sh`:
  - options `--prefix`, `--src-dir`, `--config-dir DIR` (defaults to the repo's `config`), `--no-deps`;
  - yum build deps by exact NVR (§6): `gcc-4.8.5-28.el7 gcc-c++-4.8.5-28.el7 make-3.82-23.el7 flex-2.5.37-3.el7 bison-3.0.4-1.el7 libpcap-devel-1.5.3-11.el7 pcre-devel-8.32-17.el7 libdnet-devel-1.12-0.13.1.el7 zlib-devel-1.2.7-17.el7 openssl-devel-1.0.2k-12.el7`;
  - download DAQ 2.0.6 and Snort 2.9.11.1 from the FreeBSD distcache and check the sha256 values in §6;
  - `./configure --disable-open-appid --enable-sourcefire`, `make install`, `ldconfig` (with `$PREFIX/lib` added to `/etc/ld.so.conf.d/snort.conf`; DAQ is built with `make -j1` because its libsfbpf makefile races on the generated `tokdefs.h`);
  - create the `snort` user and group and `/etc/snort/{rules,so_rules,preproc_rules}`, `/var/log/snort`, `/usr/local/lib/snort_dynamicrules`;
  - copy `etc/*.config` and `*.map` from the source tree;
  - install `config/snort.conf` and `config/rules/local.rules`, and touch empty `white_list.rules` / `black_list.rules`;
  - on success, write the marker `/etc/snort/.installed-2.9.11.1`; skip the build if the marker exists and `snort -V` reports 2.9.11.1.
- modify `config/snort.conf`:
  - `ipvar` for IP variables; `HOME_NET` becomes `[10.0.0.0/8,172.48.0.0/24]` so the lab network (and the pcaps' destination `172.48.0.10`) is inside it;
  - `dynamicpreprocessor directory`, `dynamicengine`, `dynamicdetection directory`;
  - `preprocessor frag3_global/frag3_engine`, `stream5_global/tcp/udp/icmp`;
  - `include classification.config` and `reference.config`;
  - keep the existing vars, pcre limits, `ac-bnfa` and fast output;
  - `# include $RULE_PATH/community.rules` becomes an optional comment.
- create `config/rules/local.rules`: SIDs 1000001–1000004 (§5.2).
- create `docker/snort/Dockerfile` (build context: repo root): `FROM cybersecurity:base`; first `yum downgrade` the rootfs's updates-repo `krb5-libs`, `libcom_err`, `libstdc++` and `libgcc` to their 7.5 GA builds (`krb5-libs-1.15.1-18.el7 libcom_err-1.42.9-11.el7 libstdc++-4.8.5-28.el7 libgcc-4.8.5-28.el7`), because the GA `krb5-devel`, `libcom_err-devel` and `libstdc++-devel` pulled in by the build deps require exactly those (same cause as the `target` image's `libcom_err` downgrade, §7); `COPY scripts/setup_snort.sh /opt/cybersec/scripts/`; `COPY config/ /opt/cybersec/config/`; `RUN /opt/cybersec/scripts/setup_snort.sh --config-dir /opt/cybersec/config`; default `CMD ["snort","-i","eth0","-c","/etc/snort/snort.conf","-l","/var/log/snort","-A","fast","-k","none","-q"]`.
- create `tests/bats/snort.bats`.
- modify `docker-compose.yml`: service `snort` (`build: {context: ., dockerfile: docker/snort/Dockerfile}`, `platform: linux/amd64`, `cap_add: [NET_ADMIN, NET_RAW]`, volumes `snort-logs:/var/log/snort`, `pcaps:/lab/pcaps:ro`, `./tests:/src/tests:ro`); `tests` mounts `pcaps:/lab/pcaps`.
- modify `Makefile`: `test-snort` runs `$(COMPOSE) run --rm --no-deps tests python tools/traffic.py write /lab/pcaps`, then `$(COMPOSE) run --rm --no-deps snort bats /src/tests/bats/snort.bats`.

**Tests to write first:** `snort.bats` checks that:
- `snort -V 2>&1` contains `2.9.11.1`, and `/etc/snort/.installed-2.9.11.1` exists;
- `snort -T -c /etc/snort/snort.conf` exits 0;
- for each malicious pcap, `snort -r pcap -c ... -A console -q -k none` output contains exactly its SID (the burst fires only after the 5th SYN, so `grep -c 1000004` is ≥ 1 and < 6);
- `benign.pcap` produces no output.

**Acceptance:** `make build && make test-snort && make test`

**Commit:**
```
Build Snort 2.9.11.1 sensor from source with local rules

Add setup_snort.sh (checksum-verified DAQ and Snort builds with pinned
build dependencies), a snort.conf that passes -T, and four local rules
tested against the generated pcaps.
```

---

## T7 — Deploy Snort to ids_sensors with Ansible

**Goal:** F6 (Snort part). The `snort` play installs Snort on `ids_sensors` by reusing `setup_snort.sh`.

**Files**
- modify `ansible/hardening.yml`, play tagged `snort` (replaces the placeholder):
  - `copy` `config/` and `scripts/setup_snort.sh` to `/opt/cybersec/`;
  - `command: /opt/cybersec/scripts/setup_snort.sh --config-dir /opt/cybersec/config` with `creates: /etc/snort/.installed-2.9.11.1`, and a separate config `copy` that has `notify`;
  - render the systemd unit from `ansible/templates/snort.service.j2`;
  - `systemd` enable/start only `when: snort_manage_service`.
- create `ansible/templates/snort.service.j2`: `ExecStart=/usr/local/bin/snort -q -u snort -g snort -c /etc/snort/snort.conf -i {{ snort_interface }}` (`snort_interface` defaults to `eth0` in `group_vars/all.yml`).
- create `tests/integration/test_snort_play.py`.
- modify `docker/target/Dockerfile`: next to `libcom_err`, also `yum downgrade` `krb5-libs-1.15.1-18.el7 libstdc++-4.8.5-28.el7 libgcc-4.8.5-28.el7`, because `setup_snort.sh` installs the same GA build deps on the target as in the `snort` image (deviation found in T7: without it `krb5-devel` does not resolve against the rootfs's `krb5-libs-1.15.1-19.el7`).
- modify `Makefile`: `test-ansible` also runs `test_snort_play.py`.

**Tests to write first:** `test_snort_play.py` checks that:
- the play with tag `snort` runs twice, the second with `changed=0`;
- `snort -V` on the target reports 2.9.11.1;
- `snort -T -c /etc/snort/snort.conf` returns rc 0;
- `/etc/snort/rules/local.rules` contains `sid:1000004`;
- `/etc/systemd/system/snort.service` exists and contains `-c /etc/snort/snort.conf`.

**Acceptance:** `make test-ansible && make test`

**Commit:**
```
Deploy Snort sensors from the hardening playbook

Reuse setup_snort.sh from Ansible, ship snort.conf and local rules, and
install a systemd unit that is only started when services are managed.
```

---

## T8 — Build OSSEC 2.9.4 in local mode with JSON alerts and local rules

**Goal:** F5. An OSSEC HIDS image whose rules and JSON alert output are tested.

**Files**
- create `scripts/deploy_ossec.sh`:
  - options `--src-dir`, `--config-dir`, `--no-deps`;
  - `yum install -y gcc-4.8.5-28.el7 make-3.82-23.el7 openssl-devel-1.0.2k-12.el7`;
  - download the 2.9.4 tarball and check its sha256;
  - write `etc/preloaded-vars.conf` (`USER_LANGUAGE="en"`, `USER_NO_STOP="y"`, `USER_INSTALL_TYPE="local"`, `USER_DIR="/var/ossec"`, `USER_ENABLE_ACTIVE_RESPONSE="n"`, `USER_ENABLE_SYSCHECK="y"`, `USER_ENABLE_ROOTCHECK="y"`, `USER_UPDATE_RULES="y"`);
  - run `./install.sh`;
  - install `config/ossec.conf` → `/var/ossec/etc/ossec.conf` and `config/ossec_local_rules.xml` → `/var/ossec/rules/local_rules.xml`;
  - skip the build if `/etc/ossec-init.conf` has `VERSION="v2.9.4"`.
- create `config/ossec.conf` (§5.3).
- create `config/ossec_local_rules.xml`: rule 100010, and rule 100020 as a child of stock rule 5720 (`<rule id="100020" level="12"><if_sid>5720</if_sid><description>...</description></rule>`, §5.3).
- create `docker/ossec/Dockerfile` (build context: repo root): `FROM cybersecurity:base`; `yum downgrade -y krb5-libs-1.15.1-18.el7 libcom_err-1.42.9-11.el7` (deviation found in T8: the GA `krb5-devel` and `libcom_err-devel` that `openssl-devel` pulls in require exactly these GA builds, and the rootfs carries the newer `updates` builds — same cause as the `snort` and `target` downgrades, §7); `COPY scripts/deploy_ossec.sh /opt/cybersec/scripts/`; `COPY config/ossec.conf config/ossec_local_rules.xml /opt/cybersec/config/`; `RUN /opt/cybersec/scripts/deploy_ossec.sh --config-dir /opt/cybersec/config`; `COPY docker/ossec/entrypoint.sh /usr/local/bin/`.
- create `docker/ossec/entrypoint.sh`: `mkdir -p /var/log/lab && touch /var/log/lab/secure /var/log/secure`; `/var/ossec/bin/ossec-control start`; `exec tail -F /var/ossec/logs/ossec.log`.
- create `tests/fixtures/secure_auth_failures.log` (real-format CentOS 7 sshd lines: 10× `Failed password for root from 172.48.0.20`, 1× `ROOT LOGIN REFUSED FROM 172.48.0.20`, 1× `Accepted publickey`).
- create `tests/fixtures/ossec_alert.json` (one 100020 line captured from the running image).
- create `tests/bats/ossec.bats`.
- create `tests/unit/test_ossec_fixture.py`.
- modify `docker-compose.yml`: service `ossec` (`build: {context: ., dockerfile: docker/ossec/Dockerfile}`, `platform: linux/amd64`, volumes `ossec-logs:/var/ossec/logs/alerts`, `ossec-input:/var/log/lab`, `./tests:/src/tests:ro`).
- modify `Makefile`: `test-ossec` runs `$(COMPOSE) run --rm --no-deps ossec bats /src/tests/bats/ossec.bats`.
- modify `docs/SPEC.md` §5.3 if the captured alert's key set differs from the documented one.

**Tests to write first:**
- `ossec.bats` checks that:
  - `/var/ossec/bin/ossec-logtest -v` on single fixture lines reports `Rule id: '5716'` and `'100010'`; for the `Accepted publickey` line the verbose trace shows `*Rule 5715 matched.` and the reported rule is its stock child `'10100'` (first time user logged in);
  - feeding the 10 failure lines to one `ossec-logtest` session reports `Rule id: '100020'` for a later line (and not for the first);
  - after `ossec-control start` and appending the fixture to `/var/log/lab/secure`, `alerts.json` gets a line whose `rule.sidid` is 100020 and whose `srcip` is `172.48.0.20` within 30 s (poll loop);
  - that line parses with `python -c 'import json,sys; json.loads(...)'`.
- `test_ossec_fixture.py` checks that `ossec_alert.json` parses, that its keys are a subset of the §5.3 list (`rule`, `action`, `srcip`, `srcport`, `srcuser`, `dstip`, `dstport`, `dstuser`, `location`, `full_log`, `file`; `rule` ⊆ `level`, `comment`, `sidid`, `cve`, `info`), and that `rule.sidid == 100020`.

**Acceptance:** `make build && make test-ossec && make test`

**Commit:**
```
Add OSSEC 2.9.4 local install with JSON alerts and local rules

deploy_ossec.sh builds OSSEC unattended from a verified tarball; local
rules flag refused root logins and escalate the stock SSH brute-force
rule, tested via logtest and a live alerts.json capture.
```

---

## T9 — Deploy OSSEC in local mode with Ansible

**Goal:** F6 (OSSEC part). The `ossec` play installs OSSEC through `deploy_ossec.sh`.

**Files**
- modify `ansible/hardening.yml`, play tagged `ossec` (replaces the placeholder):
  - copy the script and configs to `/opt/cybersec/`;
  - run `deploy_ossec.sh` with `creates: /var/ossec/bin/ossec-control`;
  - `copy` `ossec.conf` and local rules with a `notify` handler (`ossec-control restart` when `ossec_manage_service`);
  - `ossec-control start` guarded by `ossec_manage_service`.
- create `tests/integration/test_ossec_play.py`.
- modify `Makefile`: `test-ansible` also runs `test_ossec_play.py`.

**Tests to write first:** `test_ossec_play.py` checks that:
- the tag `ossec` runs twice, the second with `changed=0`;
- `/etc/ossec-init.conf` contains `v2.9.4`;
- `/var/ossec/etc/ossec.conf` contains `<jsonout_output>yes</jsonout_output>`;
- `/var/ossec/bin/ossec-logtest -t` returns rc 0 (the rules compile).

**Acceptance:** `make test-ansible && make test`

**Commit:**
```
Deploy OSSEC in local mode from the hardening playbook

Install OSSEC via deploy_ossec.sh and manage its config and local
rules with change handlers gated on service management.
```

---

## T10 — Ship Snort and OSSEC alerts through Filebeat and Logstash to Elasticsearch

**Goal:** The Snort/OSSEC part of F7 and F8. Fixture alert lines end up as parsed documents in `security-snort-*` and `security-ossec-*`.

**Files**
- create `elk/filebeat.yml` (§5.6) with the Snort and OSSEC inputs. Paths use `${SNORT_ALERT:/var/log/snort/alert}` and `${OSSEC_ALERTS:/var/ossec/logs/alerts/alerts.json}`.
- modify `elk/logstash.conf`:
  - `beats { port => 5044 }` replaces the file inputs;
  - set `log_type` from `[fields][log_type]`;
  - host handling (§5.5): copy `[host][name]` to `hostname` and remove `host`. A comment records the Beats 6.3 `host.name` change, after checking it against the 6.3.2 Beats release notes;
  - Snort grok as in §5.2 with IPs and ports; `mutate convert` for the integer fields;
  - OSSEC: `rename` `[json][rule][level]`→`alert_level`, `[json][rule][sidid]`→`rule_id`, `[json][rule][comment]`→`alert_description`, `[json][srcip]`→`src_ip`, `[json][full_log]`→`message`; `date` on the syslog prefix of `message` (tag `_ossec_time_fallback` on failure); `remove_field json`;
  - `geoip` only if `[src_ip]`;
  - output `elasticsearch { hosts => ["${ES_HOSTS:elasticsearch:9200}"] index => "security-%{log_type}-%{+YYYY.MM.dd}" }`.
  - the old hard-coded `email` output is removed here; T12 adds it back with the MailHog/env settings.
- modify `docker-compose.yml`:
  - `elasticsearch` (`elastic/elasticsearch:6.3.2`, `discovery.type=single-node`, `ES_JAVA_OPTS=-Xms512m -Xmx512m`, `xpack.security.enabled=false`, `xpack.ml.enabled=false`, healthcheck on `_cluster/health`);
  - `logstash` (`elastic/logstash:6.3.2`; mounts the pipeline at `/usr/share/logstash/pipeline/logstash.conf`; `xpack.monitoring.enabled=false`);
  - `kibana` (`elastic/kibana:6.3.2`, published as `20856:5601`);
  - `filebeat` (`elastic/filebeat:6.3.2`, `user: root`, command adds `-strict.perms=false`, mounts `snort-logs` and `ossec-logs` read-only, env `SNORT_ALERT`/`OSSEC_ALERTS` pointing at the mounts);
  - `tests` mounts `snort-logs` and `ossec-logs` read-write for fixture injection.
- create `tests/fixtures/snort_alert.fast` (one line each for SIDs 1000001–1000004, priorities 3/1/2/1, src `172.48.0.20` / `8.8.8.8`).
- create `tests/integration/test_pipeline.py`.
- modify `Makefile`: `test-pipeline` runs `$(COMPOSE) up -d elasticsearch logstash filebeat`, then `$(COMPOSE) run --rm tests pytest tests/integration/test_pipeline.py`. Before pytest it waits 10 s and fails with `filebeat cannot read shipped logs: permission denied` if `$(COMPOSE) logs filebeat` contains `permission denied`; it runs the same check again when pytest fails, so a permission problem never shows up as a bare document timeout.

**Tests to write first:** `test_pipeline.py`. The fixture waits for ES health and then appends each fixture line with a unique marker (Snort lines from `snort_alert.fast`, the OSSEC line from `ossec_alert.json`). Tests check that:
- `security-snort-*` has a doc with `sid == 1000002`, `priority == 1`, `src_ip == "172.48.0.20"`, `dst_port == 23`;
- `security-ossec-*` has `rule_id == 100020`, `alert_level == 12` and `src_ip`;
- every injected line produced exactly one document, none tagged `_grokparsefailure`, and each has `hostname` and no `host` field;
- the snort doc from `8.8.8.8` has `geoip.country_code2`.

**Acceptance:** `make test-pipeline && make test`

**Commit:**
```
Ship Snort and OSSEC alerts to Elasticsearch via Filebeat

Replace file inputs with Filebeat 6.3, fix the Snort grok and OSSEC
nested field names, and normalise the Beats host field to hostname.
```

---

## T11 — Add auth and audit log inputs and the security index template

**Goal:** The secure/audit part of F7 and F8, and F9.

**Files**
- modify `elk/filebeat.yml`: `secure` and `audit` inputs reading `${SECURE_LOG:/var/log/secure}` and `${AUDIT_LOG:/var/log/audit/audit.log}`.
- create `elk/es-template.json` (§5.5 mappings, `index_patterns: ["security-*"]`, `order: 1`; `hostname` and `beat.hostname` as keyword; no `host` mapping).
- modify `elk/logstash.conf`:
  - `secure` log: grok `%{SYSLOGBASE} %{GREEDYDATA:syslog_message}` plus `Failed password ... from %{IP:src_ip}`;
  - `audit` log: `kv` on `type=... msg=audit(...)`;
  - output adds `template => "/usr/share/logstash/templates/security.json" template_name => "security" template_overwrite => true`.
- modify `docker-compose.yml`: `logstash` mounts the template; `filebeat` mounts `lab-logs:/lab/logs/system:ro` with `SECURE_LOG=/lab/logs/system/secure` and `AUDIT_LOG=/lab/logs/system/audit/audit.log`; `tests` mounts `lab-logs:/lab/logs/system` read-write with the same env. (Not `/lab/logs`: a read-only volume there cannot hold the mount points of the nested `snort-logs`/`ossec-logs` mounts, and runc refuses to start Filebeat.)
- create `tests/fixtures/audit.log` (3 lines). The secure input reuses `tests/fixtures/secure_auth_failures.log`.
- modify `tests/integration/test_pipeline.py`.
- modify `Makefile`: add a JSON-parse check of the template to `test-static`.
- modify `Makefile`: `test-pipeline` fails when the Logstash log contains `mapper_parsing_exception`.
- The pipeline fixture waits for the `security` template and deletes any `security-*` index whose `src_ip` is not mapped as `ip` (an index created before the template existed), because a template applies only to indices created after it.

**Tests to write first:** `test_pipeline.py` additions:
- `security-secure-*` has a `src_ip` extracted from `Failed password`;
- `security-audit-*` has `type == "SYSCALL"` or `"USER_LOGIN"`;
- the ES mapping reports `src_ip` type `ip` and `hostname` type `keyword`, and the template has no `host` property;
- no document was rejected: the Logstash log has no `mapper_parsing_exception`, and every injected line is indexed.

**Acceptance:** `make test-pipeline && make test`

**Commit:**
```
Index auth and audit logs with a typed security template

Add secure and audit Filebeat inputs with their Logstash parsers, and
an index template that maps IPs, geo points and alert levels.
```

---

## T12 — Ingest simulated pfSense filterlog and email high-priority alerts

**Goal:** The pfSense part of F8, the email output via MailHog, and the F14 pfSense simulator.

**Files**
- create `tools/pfsense_sim.py`: `--host`, `--port 5140`, `--file`, `--rate`. It rewrites each line's syslog timestamp to now and sends it over UDP. Also exposes `frame(line, now) -> bytes`.
- create `tests/fixtures/pfsense_filterlog.log`: 3 IPv4 TCP/UDP block/pass lines with public source `8.8.8.8` and lab destinations, plus 1 IPv6 line that should end up `_pfsense_unparsed`.
- create `tests/unit/test_pfsense_sim.py`.
- modify `elk/logstash.conf`:
  - `udp { port => 5140 type => "pfsense_syslog" }` sets `log_type => pfsense`; its string `host` goes to `hostname` through the same host filter;
  - grok the syslog header, then `filterlog: %{GREEDYDATA:fw_csv}`, then `csv` or `dissect` into the §5.4 fields for ipversion 4 and proto tcp/udp; tag `_pfsense_unparsed` otherwise;
  - `email` output when `[log_type] == "snort" and [priority] <= 2`, using `${SMTP_HOST:mailhog}`, `${SMTP_PORT:1025}` and `${ALERT_TO:security@example.local}`.
- modify `docker-compose.yml`: `mailhog` (`mailhog/mailhog:v1.0.0`, UI/API 8025 published as `20825:8025`); `logstash` env `SMTP_HOST=mailhog`; expose `5140/udp` on the lab network; `tests` env `MAILHOG_URL` and `PFSENSE_HOST`/`PFSENSE_PORT`. `filebeat` keeps its registry in a named volume `filebeat-data:/usr/share/filebeat/data`, so a recreated container does not re-ship (and re-mail) alerts from earlier runs.
- modify `Makefile`: `test-pipeline` also starts `mailhog`.
- modify `tests/integration/test_pipeline.py`: add the pfSense and email tests. The fixture first waits for the Logstash Beats listener on 5044 (up to 300 s), because a template kept in the ES volume does not show that a recreated Logstash is ready; it sends the UDP lines only after the Beats documents are indexed, so no datagram reaches a pipeline that is still starting.

**Tests to write first:**
- `test_pfsense_sim.py`: the frame starts with `<134>`, the timestamp is rewritten, and the CSV body is kept byte for byte.
- `test_pipeline.py` additions:
  - after sending the fixture, `security-pfsense-*` has `fw_action == "block"`, `dst_port == 22`, `hostname` set and `geoip.country_code2` set;
  - the IPv6 line carries tag `_pfsense_unparsed`;
  - the MailHog API has exactly one message whose subject contains `LAB telnet connection attempt` for the injected priority-1 alert, and no message for the priority-3 `LAB ICMP probe`. Both checks match on this run's marker, so alerts re-shipped from earlier runs are not counted. Messages are cleared with `DELETE /api/v1/messages` before the test.

**Acceptance:** `make test-pipeline && make test`

**Commit:**
```
Parse simulated pfSense filterlog and email high-priority alerts

Add a UDP syslog input and filterlog parser fed by a pfSense log
simulator, and route priority 1-2 Snort alerts to MailHog via SMTP.
```

---

## T13 — Add Filebeat play and illustrative ELK server play

**Goal:** F7 (Ansible part). The `elk` play is kept as a syntax-checked example only (§3).

**Files**
- modify `ansible/hardening.yml`:
  - play tagged `filebeat` (hosts `all`, replaces the placeholder): `rpm_key` for the Elastic GPG key; `yum_repository` for the elastic 6.x repo; `yum: name=filebeat-{{ elastic_version }}`; template `elk/filebeat.yml` → `/etc/filebeat/filebeat.yml` (mode 0600); the `logstash_host` var (`group_vars/all.yml`, default `logstash:5044`) reaches the file's `${LOGSTASH_HOST}` through a systemd drop-in `/etc/systemd/system/filebeat.service.d/logstash.conf` (`Environment="LOGSTASH_HOST=..."`), so the config file stays byte-identical to the container's and re-runs stay `changed=0`; service guarded by `filebeat_manage_service`.
  - play tagged `elk` (hosts `elk_server`, replaces the placeholder): the same repo; `elasticsearch-6.3.2`, `logstash-6.3.2`, `kibana-6.3.2`; copy `logstash.conf` → `/etc/logstash/conf.d/security.conf` and the template → `/etc/logstash/templates/security.json`; `systemd` enable/start `with_items` over the three services. A comment at the top of the play says it is illustrative and not executed in tests.
- modify `elk/filebeat.yml`: the logstash host as `${LOGSTASH_HOST:logstash:5044}`, so the same file serves the container and the Ansible copy.
- create `tests/integration/test_filebeat_play.py`.
- modify `Makefile`: `test-ansible` also runs `test_filebeat_play.py`; `test-static` adds `ansible-playbook --syntax-check --tags elk` and `ansible-playbook --list-tasks --tags elk`.

**Tests to write first:** `test_filebeat_play.py` checks that:
- the tag `filebeat` runs twice, the second with `changed=0`;
- `host.package("filebeat").version == "6.3.2"`;
- `/usr/share/filebeat/bin/filebeat test config -c /etc/filebeat/filebeat.yml -path.home /usr/share/filebeat` returns rc 0;
- `/etc/filebeat/filebeat.yml` mode is `0o600`.

**Acceptance:** `make test-ansible && make test`

**Commit:**
```
Add Filebeat play and pin the example ELK play to 6.3.2

Install Filebeat on all hosts from the Elastic 6.x yum repo with the
shared config, and pin the illustrative ELK server play to 6.3.2.
```

---

## T14 — Run the live lab end to end

**Goal:** F13. Live Snort sniffing plus OSSEC log injection reach ES without fixture files.

**Files**
- modify `docker-compose.yml`:
  - `snort` runs its live CMD with a static IP `172.48.0.10`;
  - `tests` gets static IP `172.48.0.20`, `cap_add: [NET_RAW]`, and mounts `ossec-input:/lab/ossec-input`;
  - `ossec` runs its entrypoint;
  - `depends_on` with `condition: service_healthy` for elasticsearch;
  - the `lab` network's IPAM gets `ip_range: 172.48.0.128/25`, so dynamically addressed containers (Docker allocates serially, and `target` is recreated often) never take `.10` or `.20`.
- modify `Makefile`:
  - `lab-up` runs `$(COMPOSE) up -d elasticsearch logstash kibana filebeat mailhog snort ossec target`;
  - `lab-down` runs `$(COMPOSE) down -v`;
  - `test-snort` and `test-ossec` depend on `lab-down`, because one-off `run` containers clash with the lab's static IPs;
  - `demo` runs `tools/traffic.py send snort`, `pfsense_sim.py`, appends the auth fixture, then prints ES counts per index;
  - `test-e2e` runs `lab-up`, then `pytest tests/integration/test_end_to_end.py`.
- create `tests/integration/test_end_to_end.py`.

**Tests to write first:** `test_end_to_end.py`:
- `traffic.py send snort --only telnet_syn` gives a `security-snort-*` doc with `sid == 1000002`, `src_ip == "172.48.0.20"` and `dst_ip == "172.48.0.10"` within 60 s;
- `traffic.py send snort --only ssh_burst` gives `sid == 1000004`;
- appending the auth fixture (10 failures) to `/lab/ossec-input/secure` gives a `security-ossec-*` doc with `rule_id == 100020` from `172.48.0.20`.

**Acceptance:** `make test-e2e && make test`

**Commit:**
```
Wire the live lab so sniffed traffic and host alerts reach ELK

Give the lab fixed addresses, run Snort on the lab bridge and OSSEC on
injected auth logs, and add an end-to-end test and demo target.
```

---

## T15 — Add Snort and OSSEC correlation CLI

**Goal:** F11 (§5.7).

**Files**
- create `tools/correlate.py`: `parse_since`, `correlate`, `fetch_events`, formatters `format_table`/`format_json`/`format_ansible`, and `main(argv)`. Python 3.6, no f-string-only features beyond 3.6.
- create `tests/unit/test_correlate.py`.
- create `tests/integration/test_correlate_es.py`: bulk-index synthetic docs into `security-snort-test` and `security-ossec-test`, then run `main([...,'--format','json'])`.
- modify `Makefile`: `test-e2e` also runs `test_correlate_es.py`.

**Tests to write first:** `test_correlate.py` checks that:
- an IP with Snort at t and OSSEC at t+899 s matches with window 900, and at t+901 s does not;
- an IP seen only by Snort is excluded;
- `min_events=3` excludes a 1+1 pair;
- sorting puts priority 1 before priority 3;
- `sids` and `rule_ids` are deduplicated and sorted;
- `parse_since("15m") == timedelta(minutes=15)`, and `"15x"` raises `ValueError`;
- `format_ansible` produces `{"block_ips": [...]}`;
- `--fail-on-match` exits 3.

**Acceptance:** `make test-unit && make test-e2e && make test`

**Commit:**
```
Add CLI that correlates Snort and OSSEC events by source IP

Query security-* indices for a time range, report IPs seen by both
sensors within a window, and emit table, JSON or Ansible vars.
```

---

## T16 — Add playbook-driven IP blocking response

**Goal:** F12 (§5.8), fed by F11.

**Files**
- create `ansible/respond_block_ip.yml`:
  - `assert` that `block_ips` is a non-empty list and each item `| ipaddr` is truthy;
  - detect firewalld with `command: firewall-cmd --state` (`register`, `changed_when: false`, `failed_when: false`); `rc != 0` (including no D-Bus in the container) means not active. Do not use `systemctl`: ansible-lint 3.4.23's ANSIBLE0006 maps `systemctl` to the `systemd` module and flags it, and Ansible 2.4 has no `service_facts`. `firewall-cmd` is not in that rule's list, so no lint exception is needed;
  - `firewalld` module path when active (`with_items: "{{ block_ips }}"`);
  - `firewall-offline-cmd --query-rich-rule` then `--add-rich-rule` / `--remove-rich-rule` when not active, with `changed_when` based on the query result.
- create `tests/integration/test_response.py`.
- modify `Makefile`:
  - `test-e2e` also runs `test_response.py`;
  - `test-static` adds a syntax check and ansible-lint for `respond_block_ip.yml`;
  - `demo` ends with `correlate.py --format ansible > out/blocklist.json` and the response play.

**Tests to write first:** `test_response.py`:
- `ansible-lint ansible/respond_block_ip.yml` (with the repo `.ansible-lint`) exits 0, and the playbook contains no `skip_ansible_lint` tag;
- running `-e '{"block_ips":["203.0.113.9"]}'` puts `source address="203.0.113.9"` and `drop` in the target's `/etc/firewalld/zones/drop.xml`;
- the second run has `changed=0`;
- `block_state=absent` removes it;
- `block_ips: ["not-an-ip"]` fails at the assert;
- end to end: after the T14 traffic and auth injection, `correlate.py --since 15m --format ansible` includes `172.48.0.20`, and feeding that file to the playbook blocks it on `target`.

**Acceptance:** `make test-e2e && make test`

**Commit:**
```
Add Ansible response playbook to block correlated IPs

Validate IPs and add or remove firewalld drop-zone rich rules, using
firewall-offline-cmd when the daemon is not running; idempotent.
```

---

## T17 — Regenerate README from the template

**Goal:** An honest README that follows `tools/readme_template.md`.

**Files**
- modify `README.md`, filled from `/Users/alexsanders.ephrem/deployment/portfolio-rebuild/tools/readme_template.md`:
  - **Title:** "Cybersecurity Hardening Lab".
  - **Description:** one paragraph saying what it concretely does.
  - **Era line:** "Personal project built on the 2018-era stack (Ansible 2.4, Snort 2.9, OSSEC 2.9, Elastic Stack 6.3, Bash on CentOS 7)".
  - **Implemented:** one bullet per F1–F9 and F11–F14 that exists in code and has a test.
  - **Not implemented / known limitations:** every §3 and §11 item, including the illustrative-only ELK server play. It states the mocks explicitly: "pfSense is simulated by tools/pfsense_sim.py; never run against a real pfSense", "email goes to MailHog", "servers and sensors are CentOS 7 containers without systemd", "hostile traffic is generated by scapy on an isolated Docker network".
  - **Built with:** the pinned versions.
  - **Running it:** `make build`, `make lab-up`, `make demo`.
  - **Tests:** `make test`.
  - **Layout:** a tree generated after `git add` from `git ls-files --cached --others --exclude-standard | python3 -c '<tree printer>'`, so files added in this same commit (such as `tests/unit/test_readme.py`) are included.
  - No badges, employer, role, dates or metrics. Remove the template's comment block.
- create `tests/unit/test_readme.py`.

**Tests to write first:** `test_readme.py` checks that:
- the set of paths in the Layout block equals the output of `git ls-files --cached --others --exclude-standard` (a `.git` checkout is mounted at `/src`);
- outside fenced code blocks, the README has no line starting with `**Organization**`, `**Role**`, `**Duration**` or `**Project**`, no `Developed during`, no `img.shields.io`, and nothing matching `\b\d+(\.\d+)?%` (so Logstash text such as `security-%{log_type}` inside code blocks is not flagged). The test holds no employer or person names;
- every `make` target named in the README exists in the `Makefile`.

**Acceptance:** `make test`

**Commit:**
```
Rewrite README to match the implemented lab

Describe what is built and tested, list mocked integrations and known
limitations, and generate the layout tree from tracked files.
```

---

Task count: 17 (T1–T17). Suites added: static (T1), unit (T1, T5, T8, T12, T15, T17), base (T2), harden (T3), ansible (T4, T7, T9, T13), snort (T6), ossec (T8), pipeline (T10, T11, T12), e2e (T14–T16).
