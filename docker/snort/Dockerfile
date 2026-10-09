FROM cybersecurity:base

# The centos:7.5.1804 rootfs carries these libraries from the updates repo,
# but the GA -devel packages the build needs (krb5-devel via openssl-devel,
# libcom_err-devel, libstdc++-devel via gcc-c++) require exactly their GA
# builds, so they are moved back to the 7.5 GA versions first.
RUN for i in 1 2 3; do \
      yum downgrade -y --disablerepo=pinned-rpms \
        krb5-libs-1.15.1-18.el7 libcom_err-1.42.9-11.el7 \
        libstdc++-4.8.5-28.el7 libgcc-4.8.5-28.el7 \
      && break; \
      [ "$i" -lt 3 ] || exit 1; yum clean all; sleep 5; \
    done

COPY scripts/setup_snort.sh /opt/cybersec/scripts/
COPY config/ /opt/cybersec/config/
RUN /opt/cybersec/scripts/setup_snort.sh --config-dir /opt/cybersec/config \
    && yum clean all && rm -rf /var/cache/yum

CMD ["snort", "-i", "eth0", "-c", "/etc/snort/snort.conf", "-l", "/var/log/snort", "-A", "fast", "-k", "none", "-q"]
