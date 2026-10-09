#!/usr/bin/env bats
# Runs scripts/harden_linux.sh against a copy of a stock CentOS 7.5 /etc
# tree and checks what it changes, what it reports and that a second run
# changes nothing.

SCRIPT="$BATS_TEST_DIRNAME/../../scripts/harden_linux.sh"
FIXTURE="$BATS_TEST_DIRNAME/../fixtures/rootfs"

setup() {
  ROOT="$BATS_TMPDIR/root"
  rm -rf "$ROOT"
  cp -a "$FIXTURE" "$ROOT"
  mkdir -p "$ROOT/etc/cron.d"
}

teardown() {
  rm -rf "$ROOT"
}

harden() {
  bash "$SCRIPT" --root "$ROOT" --skip-services --skip-packages "$@"
}

@test "--check on a stock tree exits 2 and lists PasswordAuthentication" {
  run harden --check
  [ "$status" -eq 2 ]
  [[ "$output" == *"NONCOMPLIANT:"*"PasswordAuthentication"* ]]
}

@test "--check does not modify the tree" {
  before=$(cd "$ROOT" && find . -type f -exec md5sum {} + | sort)
  run harden --check
  after=$(cd "$ROOT" && find . -type f -exec md5sum {} + | sort)
  [ "$before" = "$after" ]
}

@test "apply sets each of the five sshd options exactly once" {
  run harden
  [ "$status" -eq 0 ]
  cfg="$ROOT/etc/ssh/sshd_config"
  for opt in PermitRootLogin PasswordAuthentication MaxAuthTries ClientAliveInterval ClientAliveCountMax; do
    [ "$(grep -c "^$opt " "$cfg")" -eq 1 ]
  done
  grep -qx "PermitRootLogin no" "$cfg"
  grep -qx "PasswordAuthentication no" "$cfg"
  grep -qx "MaxAuthTries 3" "$cfg"
  grep -qx "ClientAliveInterval 300" "$cfg"
  grep -qx "ClientAliveCountMax 2" "$cfg"
  [ -z "$(grep "^PasswordAuthentication yes" "$cfg")" ]
  [ -z "$(grep "^Protocol" "$cfg")" ]
}

@test "apply sets password ageing and length in login.defs" {
  run harden
  [ "$status" -eq 0 ]
  grep -Eq "^PASS_MAX_DAYS[[:space:]]+90$" "$ROOT/etc/login.defs"
  grep -Eq "^PASS_MIN_DAYS[[:space:]]+7$" "$ROOT/etc/login.defs"
  grep -Eq "^PASS_MIN_LEN[[:space:]]+12$" "$ROOT/etc/login.defs"
  [ "$(grep -c "^PASS_MAX_DAYS" "$ROOT/etc/login.defs")" -eq 1 ]
}

@test "apply writes the seven sysctl keys to a drop-in" {
  run harden
  [ "$status" -eq 0 ]
  dropin="$ROOT/etc/sysctl.d/99-hardening.conf"
  [ "$(grep -c " = " "$dropin")" -eq 7 ]
  grep -qx "net.ipv4.ip_forward = 0" "$dropin"
  grep -qx "net.ipv4.tcp_syncookies = 1" "$dropin"
  grep -qx "kernel.randomize_va_space = 2" "$dropin"
  [ ! -e "$ROOT/etc/sysctl.conf" ]
}

@test "apply writes the six audit rules" {
  run harden
  [ "$status" -eq 0 ]
  [ "$(wc -l < "$ROOT/etc/audit/rules.d/hardening.rules")" -eq 6 ]
  grep -qx -- "-w /etc/shadow -p wa -k identity" "$ROOT/etc/audit/rules.d/hardening.rules"
}

@test "apply writes the fail2ban jail" {
  run harden
  [ "$status" -eq 0 ]
  [ -f "$ROOT/etc/fail2ban/jail.local" ]
  grep -qx "\[sshd\]" "$ROOT/etc/fail2ban/jail.local"
  grep -qx "maxretry = 3" "$ROOT/etc/fail2ban/jail.local"
}

@test "apply writes firewalld config under the root only" {
  host_sum=$(md5sum /etc/firewalld/firewalld.conf)
  run harden
  [ "$status" -eq 0 ]
  grep -qx "DefaultZone=drop" "$ROOT/etc/firewalld/firewalld.conf"
  [ "$(grep -c "^DefaultZone=" "$ROOT/etc/firewalld/firewalld.conf")" -eq 1 ]
  grep -q '<service name="ssh"/>' "$ROOT/etc/firewalld/zones/drop.xml"
  grep -q '<service name="https"/>' "$ROOT/etc/firewalld/zones/drop.xml"
  [ "$(md5sum /etc/firewalld/firewalld.conf)" = "$host_sum" ]
}

@test "apply sets shadow to 000 root:root and crontab to 600" {
  run harden
  [ "$status" -eq 0 ]
  [ "$(stat -c '%a %U:%G' "$ROOT/etc/shadow")" = "0 root:root" ]
  [ "$(stat -c '%a' "$ROOT/etc/crontab")" = "600" ]
  [ "$(stat -c '%a' "$ROOT/etc/passwd")" = "644" ]
}

@test "files in cron.d are set to 600" {
  echo "0 * * * * root true" > "$ROOT/etc/cron.d/job"
  chmod 644 "$ROOT/etc/cron.d/job"
  run harden
  [ "$status" -eq 0 ]
  [ "$(stat -c '%a' "$ROOT/etc/cron.d/job")" = "600" ]
}

@test "an empty cron.d does not fail" {
  [ -z "$(ls -A "$ROOT/etc/cron.d")" ]
  run harden --only permissions
  [ "$status" -eq 0 ]
  [[ "$output" != *"No such file"* ]]
}

@test "the first run reports changes and the second run reports none" {
  run harden
  [ "$status" -eq 0 ]
  [[ "$output" == *"CHANGED:"* ]]
  [[ "$output" == *"[1/8] ssh"* ]]
  [[ "$output" == *"[8/8] fail2ban"* ]]
  run harden
  [ "$status" -eq 0 ]
  [[ "$output" != *"CHANGED:"* ]]
}

@test "--check exits 0 after the apply run" {
  run harden
  [ "$status" -eq 0 ]
  run harden --check
  [ "$status" -eq 0 ]
  [[ "$output" != *"NONCOMPLIANT:"* ]]
}

@test "--only ssh touches only sshd_config" {
  before=$(cd "$ROOT" && find . -exec stat -c '%n %a' {} + | sort; find . -type f -exec md5sum {} + | sort)
  run harden --only ssh
  [ "$status" -eq 0 ]
  after=$(cd "$ROOT" && find . -exec stat -c '%n %a' {} + | sort; find . -type f -exec md5sum {} + | sort)
  diff <(echo "$before") <(echo "$after") | grep '^[<>]' > "$BATS_TMPDIR/only.diff" || true
  [ -s "$BATS_TMPDIR/only.diff" ]
  [ -z "$(grep -v "sshd_config" "$BATS_TMPDIR/only.diff")" ]
  [[ "$output" != *"[2/8]"* ]]
}

@test "HARDEN_ROOT and skip variables work like the flags" {
  HARDEN_ROOT="$ROOT" HARDEN_SKIP_SERVICES=1 HARDEN_SKIP_PACKAGES=1 run bash "$SCRIPT" --only password
  [ "$status" -eq 0 ]
  grep -Eq "^PASS_MAX_DAYS[[:space:]]+90$" "$ROOT/etc/login.defs"
}

@test "an unknown step or option is a usage error" {
  run harden --only nosuchstep
  [ "$status" -eq 1 ]
  run harden --bogus
  [ "$status" -eq 1 ]
}

@test "running as non-root exits 1" {
  chmod 755 "$BATS_TMPDIR" "$ROOT"
  run sudo -u nobody bash "$SCRIPT" --root "$ROOT" --skip-services --skip-packages --check
  [ "$status" -eq 1 ]
  [[ "$output" == *"root"* ]]
}
