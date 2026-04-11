#!/bin/bash
# Linux Security Hardening Script
# IT Administrator - Zambaiti (2018)
#
# CIS Benchmark-based hardening for CentOS/RHEL 7 servers

set -e

echo "=== Zambaiti Linux Hardening Script ==="
echo "Date: $(date)"
echo "Host: $(hostname)"

# Ensure running as root
if [ "$(id -u)" != "0" ]; then
    echo "Must run as root"
    exit 1
fi

echo "[1/8] Configuring SSH hardening..."
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/#MaxAuthTries 6/MaxAuthTries 3/' /etc/ssh/sshd_config
sed -i 's/#ClientAliveInterval 0/ClientAliveInterval 300/' /etc/ssh/sshd_config
sed -i 's/#ClientAliveCountMax 3/ClientAliveCountMax 2/' /etc/ssh/sshd_config
echo "Protocol 2" >> /etc/ssh/sshd_config
systemctl restart sshd

echo "[2/8] Setting password policies..."
sed -i 's/PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sed -i 's/PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/' /etc/login.defs
sed -i 's/PASS_MIN_LEN.*/PASS_MIN_LEN    12/' /etc/login.defs

echo "[3/8] Configuring firewall rules..."
systemctl enable firewalld
systemctl start firewalld
firewall-cmd --set-default-zone=drop
firewall-cmd --zone=drop --add-service=ssh --permanent
firewall-cmd --zone=drop --add-service=https --permanent
firewall-cmd --reload

echo "[4/8] Disabling unnecessary services..."
DISABLE_SERVICES="avahi-daemon cups bluetooth postfix rpcbind"
for svc in $DISABLE_SERVICES; do
    systemctl disable "$svc" 2>/dev/null || true
    systemctl stop "$svc" 2>/dev/null || true
done

echo "[5/8] Setting file permissions..."
chmod 600 /etc/crontab
chmod 600 /etc/cron.d/*
chmod 700 /root
chmod 644 /etc/passwd
chmod 000 /etc/shadow
chown root:root /etc/shadow

echo "[6/8] Configuring audit logging..."
yum install -y audit
cat > /etc/audit/rules.d/hardening.rules << 'AUDIT_RULES'
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k actions
-w /var/log/lastlog -p wa -k logins
-a always,exit -F arch=b64 -S execve -k commands
AUDIT_RULES
systemctl enable auditd
systemctl restart auditd

echo "[7/8] Kernel hardening (sysctl)..."
cat >> /etc/sysctl.conf << 'SYSCTL'
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.tcp_syncookies = 1
kernel.randomize_va_space = 2
SYSCTL
sysctl -p

echo "[8/8] Installing and configuring fail2ban..."
yum install -y fail2ban
cat > /etc/fail2ban/jail.local << 'F2B'
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
systemctl enable fail2ban
systemctl start fail2ban

echo "=== Hardening complete ==="
