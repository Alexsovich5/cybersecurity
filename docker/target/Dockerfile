FROM cybersecurity:base

# The centos:7.5.1804 rootfs ships libcom_err, krb5-libs, libstdc++ and
# libgcc from the updates repo. The GA e2fsprogs (pulled in by aide and
# rkhunter) requires exactly libcom_err-1.42.9-11.el7, and the GA -devel
# packages that setup_snort.sh installs for the snort play (krb5-devel via
# openssl-devel, libstdc++-devel via gcc-c++) require exactly the GA builds
# of the others, so all four are moved back to the 7.5 GA versions.
RUN for i in 1 2 3; do \
      yum install -y --disablerepo=pinned-rpms \
        openssh-server-7.4p1-16.el7 openssh-clients-7.4p1-16.el7 python-2.7.5-68.el7 \
      && yum downgrade -y --disablerepo=pinned-rpms \
        libcom_err-1.42.9-11.el7 krb5-libs-1.15.1-18.el7 \
        libstdc++-4.8.5-28.el7 libgcc-4.8.5-28.el7 \
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
