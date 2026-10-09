FROM centos:7.5.1804@sha256:7a45e4a1efbaafc1d9aa89925b6fdb33288a96d35ea0581412316e2f0ad3720a

# Yum sees only the 7.5 GA tree and the local repo of checksum-verified RPMs.
RUN rm -f /etc/yum.repos.d/*.repo
COPY docker/base/CentOS-Vault.repo docker/base/pinned-rpms.repo /etc/yum.repos.d/
RUN rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7

RUN for i in 1 2 3; do \
      yum install -y --disablerepo=pinned-rpms \
        which-2.20-7.el7 tar-1.26-34.el7 gzip-1.5-10.el7 make-3.82-23.el7 \
        sudo-1.8.19p2-13.el7 firewalld-0.4.4.4-14.el7 createrepo-0.9.9-28.el7 \
      && break; \
      [ "$i" -lt 3 ] || exit 1; yum clean all; sleep 5; \
    done

COPY docker/base/pinned-rpms.txt docker/base/fetch_pinned_rpms.sh /tmp/
RUN bash /tmp/fetch_pinned_rpms.sh /opt/pinned-rpms /tmp/pinned-rpms.txt \
    && rm -f /tmp/pinned-rpms.txt /tmp/fetch_pinned_rpms.sh

ARG BATS_VERSION=1.1.0
ARG BATS_SHA256=855d8b8bed466bc505e61123d12885500ef6fcdb317ace1b668087364717ea82
RUN cd /tmp \
    && for i in 1 2 3; do \
         curl -fsSL -o bats.tar.gz "https://github.com/bats-core/bats-core/archive/v${BATS_VERSION}.tar.gz" \
         && break; \
         [ "$i" -lt 3 ] || exit 1; sleep 5; \
       done \
    && echo "${BATS_SHA256}  bats.tar.gz" | sha256sum -c - \
    && tar -xzf bats.tar.gz \
    && "bats-core-${BATS_VERSION}/install.sh" /usr/local \
    && rm -rf bats.tar.gz "bats-core-${BATS_VERSION}"

RUN yum clean all && rm -rf /var/cache/yum
WORKDIR /src
