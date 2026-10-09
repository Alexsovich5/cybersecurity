#!/bin/bash
# Starts the SSH-managed lab target. On first start a keypair is written to
# the shared key volume; its public half is authorized for the ansible user.
set -euo pipefail

KEY_DIR=/lab/keys
KEY="$KEY_DIR/id_rsa"

mkdir -p "$KEY_DIR"
if [ ! -f "$KEY" ]; then
    ssh-keygen -q -t rsa -b 2048 -N '' -C 'lab-ansible' -f "$KEY.tmp"
    mv "$KEY.tmp.pub" "$KEY.pub"
    mv "$KEY.tmp" "$KEY"
fi
chmod 600 "$KEY"
chmod 644 "$KEY.pub"

install -d -m 700 -o ansible -g ansible /home/ansible/.ssh
install -m 600 -o ansible -g ansible "$KEY.pub" /home/ansible/.ssh/authorized_keys

ssh-keygen -A
exec /usr/sbin/sshd -D -e
