#!/bin/bash
# Start the OSSEC local-mode daemons and follow ossec.log in the foreground.
set -euo pipefail

mkdir -p /var/log/lab
touch /var/log/lab/secure /var/log/secure
/var/ossec/bin/ossec-control start
exec tail -F /var/ossec/logs/ossec.log
