FROM cybersecurity:base

# The centos:7.5.1804 rootfs ships libcom_err-1.42.9-12.el7_5 from the
# updates repo, but the GA e2fsprogs (pulled in by aide and rkhunter)
# requires exactly libcom_err-1.42.9-11.el7, so it is moved back to the GA
# build to let the hardening play resolve its packages.
RUN for i in 1 2 3; do \
      yum install -y --disablerepo=pinned-rpms \
        openssh-server-7.4p1-16.el7 openssh-clients-7.4p1-16.el7 python-2.7.5-68.el7 \
      && yum downgrade -y --disablerepo=pinned-rpms libcom_err-1.42.9-11.el7 \
      && break; \
      [ "$i" -lt 3 ] || exit 1; yum clean all; sleep 5; \
    done \
    && yum clean all && rm -rf /var/cache/yum

# Managed-node account: key-only login, passwordless sudo without a tty.
RUN useradd -m ansible \
    && usermod -p '*' ansible \
    && printf 'ansible ALL=(ALL) NOPASSWD: ALL\nDefaults:ansible !requiretty\n' > /etc/sudoers.d/ansible \
    && chmod 440 /etc/sudoers.d/ansible \
    && sed -i 's/^session\s\+required\s\+pam_loginuid.so/session optional pam_loginuid.so/' /etc/pam.d/sshd \
    && mkdir -p /lab/keys

COPY docker/target/entrypoint.sh /usr/local/bin/
RUN chmod 755 /usr/local/bin/entrypoint.sh

EXPOSE 22
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
