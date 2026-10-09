#!/usr/bin/env bats
# Checks the CentOS base image: release, bats, yum repositories and the
# exact package builds that yum can install from them.

@test "base image is CentOS 7.5.1804" {
  run cat /etc/centos-release
  [ "$status" -eq 0 ]
  [[ "$output" == *"7.5.1804"* ]]
}

@test "bats-core 1.1.0 is installed" {
  run bats --version
  [ "$status" -eq 0 ]
  [[ "$output" == *"1.1.0"* ]]
}

@test "only the base and pinned-rpms repositories are enabled" {
  run bash -c "yum -q repolist enabled | awk 'NR > 1 && \$1 != \"repolist:\" {sub(/\\/.*/, \"\", \$1); print \$1}' | sort | tr '\n' ' '"
  [ "$status" -eq 0 ]
  [ "$output" = "base pinned-rpms " ]
}

@test "packages installed by the image are at their pinned builds" {
  for nvr in which-2.20-7.el7 tar-1.26-34.el7 gzip-1.5-10.el7 make-3.82-23.el7 \
             sudo-1.8.19p2-13.el7 firewalld-0.4.4.4-14.el7 createrepo-0.9.9-28.el7 \
             openssl-libs-1.0.2k-12.el7; do
    run rpm -q "$nvr"
    [ "$status" -eq 0 ] || { echo "not installed: $nvr ($output)"; return 1; }
  done
}

@test "build and target packages resolve to their pinned builds" {
  for nvr in gcc-4.8.5-28.el7 libpcap-devel-1.5.3-11.el7 pcre-devel-8.32-17.el7 \
             openssl-devel-1.0.2k-12.el7 libdnet-devel-1.12-0.13.1.el7 \
             openssh-server-7.4p1-16.el7 python-2.7.5-68.el7 fail2ban-0.9.7-1.el7 \
             rkhunter-1.4.6-1.el7 clamav-0.99.2-1.el7 clamav-data-empty-0.99.2-1.el7; do
    run yum -q list "$nvr"
    [ "$status" -eq 0 ] || { echo "not resolvable: $nvr ($output)"; return 1; }
  done
}

@test "only the pinned fail2ban and clamav builds are available" {
  run bash -c "yum -q list available --showduplicates fail2ban clamav | awk 'NR > 1 {print \$1, \$2}'"
  [ "$status" -eq 0 ]
  [ "${#lines[@]}" -eq 2 ]
  [[ "$output" == *"clamav.x86_64 0.99.2-1.el7"* ]]
  [[ "$output" == *"fail2ban.noarch 0.9.7-1.el7"* ]]
}

@test "firewall-offline-cmd reports firewalld 0.4.4.4" {
  run firewall-offline-cmd --version
  [ "$status" -eq 0 ]
  [[ "$output" == *"0.4.4.4"* ]]
}
