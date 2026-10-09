#!/bin/bash
# Linux Security Hardening Script
#
# CIS Benchmark-based hardening for CentOS/RHEL 7 servers.
#
# Usage: harden_linux.sh [--check] [--root DIR] [--skip-services]
#                        [--skip-packages] [--only STEP[,STEP..]]
#   STEP is one of: ssh,password,firewall,services,permissions,audit,sysctl,fail2ban
#
# Environment equivalents: HARDEN_ROOT, HARDEN_SKIP_SERVICES=1,
# HARDEN_SKIP_PACKAGES=1.
#
# Every setting is applied only when it differs from the wanted value, so
# repeated runs change nothing. Each modification prints "CHANGED: ...".
# With --check nothing is modified; each difference prints
# "NONCOMPLIANT: ..." and the script exits 2 if any were found.
#
# Exit codes: 0 compliant/applied, 1 usage error or not root,
#             2 non-compliant items found (--check only).

set -euo pipefail

STEPS="ssh password firewall services permissions audit sysctl fail2ban"
DISABLE_SERVICES="avahi-daemon cups bluetooth postfix rpcbind"

CHECK=0
ROOT="${HARDEN_ROOT:-/}"
SKIP_SERVICES="${HARDEN_SKIP_SERVICES:-0}"
SKIP_PACKAGES="${HARDEN_SKIP_PACKAGES:-0}"
ONLY=""
NONCOMPLIANT=0

usage() {
    echo "usage: $0 [--check] [--root DIR] [--skip-services] [--skip-packages] [--only STEP[,STEP..]]" >&2
    echo "  STEP: ${STEPS// /,}" >&2
    exit 1
}

while [ $# -gt 0 ]; do
    case "$1" in
        --check) CHECK=1 ;;
        --root)
            [ $# -ge 2 ] || usage
            ROOT="$2"
            shift
            ;;
        --root=*) ROOT="${1#--root=}" ;;
        --skip-services) SKIP_SERVICES=1 ;;
        --skip-packages) SKIP_PACKAGES=1 ;;
        --only)
            [ $# -ge 2 ] || usage
            ONLY="$2"
            shift
            ;;
        --only=*) ONLY="${1#--only=}" ;;
        -h|--help) usage ;;
        *)
            echo "unknown option: $1" >&2
            usage
            ;;
    esac
    shift
done

if [ -n "$ONLY" ]; then
    for step in ${ONLY//,/ }; do
        case " $STEPS " in
            *" $step "*) ;;
            *)
                echo "unknown step: $step" >&2
                usage
                ;;
        esac
    done
fi

if [ "$(id -u)" != "0" ]; then
    echo "Must run as root" >&2
    exit 1
fi

if [ ! -d "$ROOT" ]; then
    echo "root directory does not exist: $ROOT" >&2
    exit 1
fi
ROOT="$(cd "$ROOT" && pwd)"
# Path prefix for files under the root; empty when the root is "/".
if [ "$ROOT" = "/" ]; then
    R=""
else
    R="$ROOT"
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# --- helpers ---------------------------------------------------------------

# changed MSG: report a modification.
changed() {
    echo "CHANGED: $1"
}

# noncompliant MSG: report a difference found in --check mode.
noncompliant() {
    echo "NONCOMPLIANT: $1"
    NONCOMPLIANT=1
}

# selected STEP: true when STEP runs in this invocation.
selected() {
    [ -z "$ONLY" ] && return 0
    case ",$ONLY," in
        *",$1,"*) return 0 ;;
        *) return 1 ;;
    esac
}

# live: true when services on the running system may be touched.
live() {
    [ -z "$R" ] && [ "$SKIP_SERVICES" != "1" ] && [ "$CHECK" != "1" ]
}

# install_packages PKG..: install packages unless --skip-packages/--check.
install_packages() {
    if [ "$SKIP_PACKAGES" = "1" ] || [ "$CHECK" = "1" ]; then
        return 0
    fi
    local missing=()
    local pkg
    for pkg in "$@"; do
        rpm --root "$ROOT" -q "$pkg" >/dev/null 2>&1 || missing+=("$pkg")
    done
    if [ ${#missing[@]} -gt 0 ]; then
        yum install -y --installroot="$ROOT" "${missing[@]}"
        changed "packages: installed ${missing[*]}"
    fi
}

# write_if_changed FILE: replace FILE with stdin when the content differs.
write_if_changed() {
    local file="$1"
    local new="$TMP/new"
    cat > "$new"
    if [ -f "$file" ] && cmp -s "$new" "$file"; then
        return 0
    fi
    if [ "$CHECK" = "1" ]; then
        noncompliant "${file#"$R"}: content differs"
        return 0
    fi
    mkdir -p "$(dirname "$file")"
    if [ -f "$file" ]; then
        cat "$new" > "$file"
    else
        cp "$new" "$file"
    fi
    changed "${file#"$R"}: content updated"
}

# set_kv FILE KEY VALUE SEP: make "KEY<SEP>VALUE" the only active setting of
# KEY. The first line holding KEY, commented ("#KEY ...") or not, is replaced;
# later uncommented lines for KEY are removed; if KEY is absent the line is
# appended.
set_kv() {
    local file="$1" key="$2" value="$3" sep="$4"
    local line="${key}${sep}${value}"
    local new="$TMP/kv"
    if [ ! -f "$file" ]; then
        if [ "$CHECK" = "1" ]; then
            noncompliant "${file#"$R"}: missing ($line)"
            return 0
        fi
        mkdir -p "$(dirname "$file")"
        : > "$file"
    fi
    awk -v key="$key" -v line="$line" '
        function is_key(s, active) {
            if (!active) sub(/^#/, "", s)
            if (index(s, key) != 1) return 0
            rest = substr(s, length(key) + 1)
            return rest == "" || rest ~ /^[ \t=]/
        }
        {
            if (!done && is_key($0, 0)) { print line; done = 1; next }
            if (done && is_key($0, 1)) next
            print
        }
        END { if (!done) print line }
    ' "$file" > "$new"
    if cmp -s "$new" "$file"; then
        return 0
    fi
    if [ "$CHECK" = "1" ]; then
        noncompliant "${file#"$R"}: $line"
        return 0
    fi
    cat "$new" > "$file"
    changed "${file#"$R"}: $line"
}

# ensure_mode PATH MODE [OWNER]: set octal MODE and optional OWNER
# (user:group) on PATH when they differ. A missing PATH is skipped.
ensure_mode() {
    local path="$1" mode="$2" owner="${3:-}"
    [ -e "$path" ] || return 0
    local cur
    cur="$(stat -c '%a' "$path")"
    if [ $((8#$cur)) -ne $((8#$mode)) ]; then
        if [ "$CHECK" = "1" ]; then
            noncompliant "${path#"$R"}: mode $cur, want $mode"
        else
            chmod "$mode" "$path"
            changed "${path#"$R"}: mode $cur -> $mode"
        fi
    fi
    if [ -n "$owner" ]; then
        cur="$(stat -c '%U:%G' "$path")"
        if [ "$cur" != "$owner" ]; then
            if [ "$CHECK" = "1" ]; then
                noncompliant "${path#"$R"}: owner $cur, want $owner"
            else
                chown "$owner" "$path"
                changed "${path#"$R"}: owner $cur -> $owner"
            fi
        fi
    fi
}

# --- steps -----------------------------------------------------------------

step_ssh() {
    local cfg="$R/etc/ssh/sshd_config"
    local before=""
    [ -f "$cfg" ] && before="$(cksum < "$cfg")"
    mkdir_root etc/ssh
    set_kv "$cfg" PermitRootLogin no " "
    set_kv "$cfg" PasswordAuthentication no " "
    set_kv "$cfg" MaxAuthTries 3 " "
    set_kv "$cfg" ClientAliveInterval 300 " "
    set_kv "$cfg" ClientAliveCountMax 2 " "
    if live && [ "$before" != "$(cksum < "$cfg")" ]; then
        systemctl restart sshd
    fi
}

step_password() {
    local defs="$R/etc/login.defs"
    mkdir_root etc
    set_kv "$defs" PASS_MAX_DAYS 90 "   "
    set_kv "$defs" PASS_MIN_DAYS 7 "   "
    set_kv "$defs" PASS_MIN_LEN 12 "    "
}

drop_zone_xml() {
    cat << 'ZONE'
<?xml version="1.0" encoding="utf-8"?>
<zone target="DROP">
  <short>Drop</short>
  <description>Unsolicited incoming network packets are dropped. Incoming packets that are related to outgoing network connections are accepted. Outgoing network connections are allowed.</description>
  <service name="ssh"/>
  <service name="https"/>
</zone>
ZONE
}

# firewall_with online|offline: apply the zone settings through the running
# daemon (firewall-cmd, services added permanently) or firewall-offline-cmd.
firewall_with() {
    local zone_cmd svc_cmd zone svc
    if [ "$1" = "online" ]; then
        zone_cmd=(firewall-cmd)
        svc_cmd=(firewall-cmd --permanent)
    else
        zone_cmd=(firewall-offline-cmd)
        svc_cmd=(firewall-offline-cmd)
    fi
    zone="$("${zone_cmd[@]}" --get-default-zone 2>/dev/null || true)"
    if [ "$zone" != "drop" ]; then
        if [ "$CHECK" = "1" ]; then
            noncompliant "firewalld: default zone $zone, want drop"
        else
            "${zone_cmd[@]}" --set-default-zone=drop >/dev/null
            changed "firewalld: default zone drop"
        fi
    fi
    for svc in ssh https; do
        if ! "${svc_cmd[@]}" --zone=drop --query-service="$svc" >/dev/null 2>&1; then
            if [ "$CHECK" = "1" ]; then
                noncompliant "firewalld: service $svc not in zone drop"
            else
                "${svc_cmd[@]}" --zone=drop --add-service="$svc" >/dev/null
                changed "firewalld: service $svc added to zone drop"
            fi
        fi
    done
}

step_firewall() {
    install_packages firewalld
    mkdir_root etc/firewalld/zones
    if [ -n "$R" ]; then
        # firewall-offline-cmd cannot target another root, so write the
        # permanent configuration files directly.
        set_kv "$R/etc/firewalld/firewalld.conf" DefaultZone drop "="
        drop_zone_xml | write_if_changed "$R/etc/firewalld/zones/drop.xml"
        return 0
    fi
    if [ "$SKIP_SERVICES" != "1" ] && firewall-cmd --state >/dev/null 2>&1; then
        firewall_with online
        if [ "$CHECK" != "1" ]; then
            firewall-cmd --reload >/dev/null
        fi
    else
        firewall_with offline
    fi
    if live; then
        systemctl enable firewalld
    fi
}

step_services() {
    if [ "$SKIP_SERVICES" = "1" ] || [ -n "$R" ]; then
        echo "skipped"
        return 0
    fi
    local svc
    for svc in $DISABLE_SERVICES; do
        if systemctl is-enabled "$svc" >/dev/null 2>&1 || systemctl is-active "$svc" >/dev/null 2>&1; then
            if [ "$CHECK" = "1" ]; then
                noncompliant "service $svc is enabled or running"
            else
                systemctl disable "$svc" >/dev/null 2>&1 || true
                systemctl stop "$svc" >/dev/null 2>&1 || true
                changed "service $svc disabled"
            fi
        fi
    done
}

step_permissions() {
    mkdir_root etc/cron.d
    local f
    ensure_mode "$R/etc/crontab" 600
    for f in "$R"/etc/cron.d/*; do
        [ -e "$f" ] || continue
        ensure_mode "$f" 600
    done
    ensure_mode "$R/root" 700
    ensure_mode "$R/etc/passwd" 644
    ensure_mode "$R/etc/shadow" 000 root:root
}

step_audit() {
    install_packages audit
    mkdir_root etc/audit/rules.d
    local rules="$R/etc/audit/rules.d/hardening.rules"
    local before=""
    [ -f "$rules" ] && before="$(cksum < "$rules")"
    write_if_changed "$rules" << 'AUDIT_RULES'
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k actions
-w /var/log/lastlog -p wa -k logins
-a always,exit -F arch=b64 -S execve -k commands
AUDIT_RULES
    if live; then
        systemctl enable auditd
        if [ "$before" != "$(cksum < "$rules")" ]; then
            service auditd restart
        fi
    fi
}

step_sysctl() {
    mkdir_root etc/sysctl.d
    write_if_changed "$R/etc/sysctl.d/99-hardening.conf" << 'SYSCTL'
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.tcp_syncookies = 1
kernel.randomize_va_space = 2
SYSCTL
    if live; then
        sysctl --system >/dev/null
    fi
}

step_fail2ban() {
    install_packages fail2ban
    mkdir_root etc/fail2ban
    write_if_changed "$R/etc/fail2ban/jail.local" << 'F2B'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/secure
F2B
    if live; then
        systemctl enable fail2ban
        systemctl restart fail2ban
    fi
}

# mkdir_root DIR: create DIR under the root (not in --check mode).
mkdir_root() {
    [ "$CHECK" = "1" ] && return 0
    mkdir -p "$ROOT/$1"
}

# --- main ------------------------------------------------------------------

echo "=== Linux Hardening Script ==="
echo "Host: $(hostname)  Root: $ROOT  Mode: $([ "$CHECK" = "1" ] && echo check || echo apply)"

n=0
for step in $STEPS; do
    n=$((n + 1))
    selected "$step" || continue
    echo "[$n/8] $step"
    "step_$step"
done

if [ "$CHECK" = "1" ] && [ "$NONCOMPLIANT" = "1" ]; then
    echo "=== Non-compliant items found ==="
    exit 2
fi
echo "=== Hardening complete ==="
