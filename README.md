# Cybersecurity Hardening Initiative

Comprehensive cybersecurity hardening initiative implementing network perimeter defense with pfSense, intrusion detection with Snort IDS, host-based security with OSSEC, and centralized logging with ELK Stack.

Personal project, built to explore host and network hardening as repeatable automation. It is not production software — see **Status** below for exactly what is and isn't implemented.

## Status

**Implemented**

- Linux hardening shell script
- Ansible hardening playbook
- Snort IDS ruleset config
- Logstash pipeline for shipping security events to ELK

**Not implemented / known limitations**

- No pfSense or OSSEC setup scripts (the earlier README claimed these; they did not exist)
- Hardening script is Debian/Ubuntu-oriented and not idempotent
- No CIS benchmark scoring

## Layout

```
ansible/
  hardening.yml
config/
  snort.conf
elk/
  logstash.conf
scripts/
  harden_linux.sh
```

