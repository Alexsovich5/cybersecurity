FROM cybersecurity:base

# The centos:7.5.1804 rootfs carries krb5-libs and libcom_err from the updates
# repo, but the GA krb5-devel and libcom_err-devel pulled in by openssl-devel
# require exactly their GA builds, so both are moved back to 7.5 GA first.
RUN for i in 1 2 3; do \
      yum downgrade -y --disablerepo=pinned-rpms \
        krb5-libs-1.15.1-18.el7 libcom_err-1.42.9-11.el7 \
      && break; \
      [ "$i" -lt 3 ] || exit 1; yum clean all; sleep 5; \
    done

COPY scripts/deploy_ossec.sh /opt/cybersec/scripts/
COPY config/ossec.conf config/ossec_local_rules.xml /opt/cybersec/config/
RUN /opt/cybersec/scripts/deploy_ossec.sh --config-dir /opt/cybersec/config \
    && yum clean all && rm -rf /var/cache/yum

COPY docker/ossec/entrypoint.sh /usr/local/bin/
RUN chmod 755 /usr/local/bin/entrypoint.sh

CMD ["/usr/local/bin/entrypoint.sh"]
