"""Static checks on the lab's network exposure, SSH trust and download sources."""
import configparser
import os
import re
import subprocess

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
COMPOSE = os.path.join(REPO, "docker-compose.yml")
ANSIBLE_CFG = os.path.join(REPO, "ansible", "ansible.cfg")
DOCKER_INVENTORY = os.path.join(REPO, "ansible", "inventory", "docker.ini")
LAB_KNOWN_HOSTS = "/lab/keys/known_hosts"

# Plain-HTTP URLs that are allowed, each with the reason. Everything fetched
# from them is checked against a pinned sha256 before use.
HTTP_ALLOWED = {
    # distcache.freebsd.org serves no valid certificate for its own name;
    # setup_snort.sh verifies both tarballs against pinned sha256 sums.
    "http://distcache.freebsd.org/ports-distfiles",
}
INSECURE_FLAGS = re.compile(
    r"--nogpgcheck|--no-check-certificate|--insecure\b|\bcurl\b[^\n]*\s-k\b|sslverify\s*=\s*0"
    r"|validate_certs:\s*(no|false)",
    re.IGNORECASE)
HTTP_URL = re.compile(r"http://[^\s\"'<>]+")
# Service URLs inside the lab network, not download sources.
LAB_SERVICE_URL = re.compile(
    r"^http://(localhost|elasticsearch|mailhog|logstash|kibana)(:\d+)?(/|$)|^http://\$|"
    r"^http://127\.0\.0\.1[:/]")


def tracked_files():
    output = subprocess.check_output(["git", "ls-files"], cwd=REPO).decode()
    return [line for line in output.splitlines() if line]


def published_ports():
    with open(COMPOSE) as handle:
        services = yaml.safe_load(handle)["services"]
    for name, service in sorted(services.items()):
        for port in service.get("ports", []):
            yield name, str(port)


def test_compose_publishes_at_least_one_port():
    assert list(published_ports())


def test_every_published_port_is_bound_to_loopback():
    exposed = [(name, port) for name, port in published_ports()
               if not port.startswith("127.0.0.1:")]
    assert exposed == []


def test_published_host_ports_stay_in_the_lab_range():
    for name, port in published_ports():
        host_port = int(port.split(":")[-2])
        assert 20800 <= host_port <= 20899, (name, port)


def read_cfg(path):
    parser = configparser.ConfigParser(allow_no_value=True, interpolation=None)
    parser.optionxform = str
    with open(path) as handle:
        text = handle.read()
    if not text.lstrip().startswith("["):
        text = "[top]\n" + text
    parser.read_string(text)
    return parser


def test_ansible_cfg_keeps_host_key_checking_on():
    cfg = read_cfg(ANSIBLE_CFG)
    for section in cfg.sections():
        value = cfg[section].get("host_key_checking")
        assert value is None or value.strip().lower() in ("true", "yes", "1"), (section, value)
        ssh_args = cfg[section].get("ssh_args") or ""
        assert "StrictHostKeyChecking=no" not in ssh_args


def test_lab_inventory_trusts_only_the_exported_target_host_keys():
    cfg = read_cfg(DOCKER_INVENTORY)
    args = cfg["all:vars"]["ansible_ssh_common_args"]
    assert "UserKnownHostsFile={}".format(LAB_KNOWN_HOSTS) in args
    assert "StrictHostKeyChecking=yes" in args


def test_no_inventory_disables_host_key_checking():
    inventories = os.path.join(REPO, "ansible", "inventory")
    for name in os.listdir(inventories):
        with open(os.path.join(inventories, name)) as handle:
            text = handle.read()
        assert "StrictHostKeyChecking=no" not in text, name
        assert "host_key_checking" not in text, name


def test_target_entrypoint_exports_its_host_keys():
    with open(os.path.join(REPO, "docker", "target", "entrypoint.sh")) as handle:
        text = handle.read()
    assert LAB_KNOWN_HOSTS.split("/")[-1] in text
    assert "ssh_host_" in text


def build_and_config_files():
    for path in tracked_files():
        name = os.path.basename(path)
        if (name == "Dockerfile" or path.endswith((".sh", ".repo", ".yml", ".j2", ".cfg"))
                or name == "Makefile"):
            yield path


def test_no_tls_or_signature_bypass_in_build_and_deploy_files():
    found = []
    for path in build_and_config_files():
        with open(os.path.join(REPO, path)) as handle:
            for number, line in enumerate(handle, 1):
                if INSECURE_FLAGS.search(line):
                    found.append("{}:{}: {}".format(path, number, line.strip()))
    assert found == []


def test_downloads_use_https_unless_allowlisted():
    found = []
    for path in build_and_config_files():
        with open(os.path.join(REPO, path)) as handle:
            for number, line in enumerate(handle, 1):
                if line.lstrip().startswith("#"):
                    continue
                for url in HTTP_URL.findall(line):
                    if LAB_SERVICE_URL.match(url):
                        continue
                    if any(url.startswith(allowed) for allowed in HTTP_ALLOWED):
                        continue
                    found.append("{}:{}: {}".format(path, number, url))
    assert found == []


def test_yum_repos_check_signatures_except_the_local_checksummed_one():
    for path in tracked_files():
        if not path.endswith(".repo"):
            continue
        cfg = read_cfg(os.path.join(REPO, path))
        for section in cfg.sections():
            repo = cfg[section]
            baseurl = repo.get("baseurl", "")
            if repo.get("gpgcheck", "1").strip() == "1":
                assert baseurl.startswith("https://"), (path, section, baseurl)
            else:
                # Only the local repo built from sha256-verified RPMs.
                assert baseurl.startswith("file://"), (path, section, baseurl)
