#!/bin/bash
# Starts the SSH-managed lab target. On first start a keypair is written to
# the shared key volume; its public half is authorized for the ansible user.
# On every start the host's public keys are written to known_hosts in the
# same volume, so clients can verify the target instead of trusting any key.
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

# Entries for the service name and the container address on the lab network.
names="$(hostname)"
for addr in $(hostname -i); do
    names="$names,$addr"
done
: > "$KEY_DIR/known_hosts.tmp"
for pub in /etc/ssh/ssh_host_*_key.pub; do
    read -r keytype blob _ < "$pub"
    printf '%s %s %s\n' "$names" "$keytype" "$blob" >> "$KEY_DIR/known_hosts.tmp"
done
chmod 644 "$KEY_DIR/known_hosts.tmp"
mv "$KEY_DIR/known_hosts.tmp" "$KEY_DIR/known_hosts"

exec /usr/sbin/sshd -D -e
