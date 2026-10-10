COMPOSE ?= docker compose
RUN_TESTS = $(COMPOSE) run --rm tests

.PHONY: build test test-static test-unit test-base test-harden test-snort test-ossec test-ansible test-pipeline \
	test-e2e lab-up lab-down demo shell clean

build:
	$(COMPOSE) build base
	$(COMPOSE) build

test: test-static test-unit test-base test-harden test-snort test-ossec test-ansible test-pipeline test-e2e

test-static:
	$(RUN_TESTS) sh -c '\
		yamllint -s ansible elk/*.yml docker-compose.yml && \
		shellcheck scripts/*.sh && \
		shellcheck docker/*/*.sh && \
		for f in scripts/*.sh; do bash -n "$$f" || exit 1; done && \
		ansible-playbook -i localhost, --syntax-check ansible/hardening.yml && \
		ansible-playbook --syntax-check --tags elk ansible/hardening.yml && \
		ansible-playbook --list-tasks --tags elk ansible/hardening.yml && \
		ansible-lint ansible/hardening.yml && \
		ansible-playbook -i localhost, --syntax-check ansible/respond_block_ip.yml && \
		ansible-lint ansible/respond_block_ip.yml && \
		python -m py_compile tools/*.py && \
		python -m json.tool elk/es-template.json > /dev/null'

test-unit:
	$(RUN_TESTS) pytest tests/unit

test-base:
	$(COMPOSE) run --rm --no-deps base bats tests/bats/base.bats

test-harden:
	$(COMPOSE) run --rm --no-deps base bats tests/bats/harden_linux.bats

test-snort: lab-down
	$(COMPOSE) run --rm --no-deps tests python tools/traffic.py write /lab/pcaps
	$(COMPOSE) run --rm --no-deps snort bats /src/tests/bats/snort.bats

test-ossec: lab-down
	$(COMPOSE) run --rm --no-deps ossec bats /src/tests/bats/ossec.bats

test-ansible:
	$(COMPOSE) up -d --force-recreate target
	$(RUN_TESTS) pytest --hosts=ansible://targets --sudo tests/integration/test_hardening.py tests/integration/test_snort_play.py tests/integration/test_ossec_play.py tests/integration/test_filebeat_play.py

FILEBEAT_PERMS_CHECK = if $(COMPOSE) logs filebeat 2>&1 | grep -qi 'permission denied'; then \
		echo 'filebeat cannot read shipped logs: permission denied' >&2; exit 1; fi

LOGSTASH_REJECT_CHECK = if $(COMPOSE) logs logstash 2>&1 | grep -q 'mapper_parsing_exception'; then \
		echo 'logstash: Elasticsearch rejected documents (mapper_parsing_exception)' >&2; exit 1; fi

test-pipeline:
	$(COMPOSE) up -d elasticsearch mailhog logstash filebeat
	sleep 10
	@$(FILEBEAT_PERMS_CHECK)
	$(RUN_TESTS) pytest tests/integration/test_pipeline.py || { $(FILEBEAT_PERMS_CHECK); exit 1; }
	@$(LOGSTASH_REJECT_CHECK)

LAB_SERVICES = elasticsearch logstash kibana filebeat mailhog snort ossec target

lab-up:
	$(COMPOSE) up -d $(LAB_SERVICES)

lab-down:
	$(COMPOSE) down -v

test-e2e: lab-up
	$(RUN_TESTS) pytest tests/integration/test_end_to_end.py tests/integration/test_correlate_es.py \
		tests/integration/test_response.py

ES_COUNTS = import requests; print(requests.get("http://elasticsearch:9200/_cat/indices/security-*", \
	params={"v": "true", "h": "index,docs.count", "s": "index"}, timeout=10).text)

demo: lab-up
	$(RUN_TESTS) python tools/traffic.py send snort
	$(RUN_TESTS) python tools/pfsense_sim.py --host logstash --port 5140
	$(RUN_TESTS) sh -c 'sed "s/^.\{15\}/$$(date -u "+%b %e %H:%M:%S")/" tests/fixtures/secure_auth_failures.log >> /lab/ossec-input/secure'
	sleep 15
	$(RUN_TESTS) python -c '$(ES_COUNTS)'
	mkdir -p out
	$(RUN_TESTS) sh -c 'python tools/correlate.py --since 15m --format ansible > out/blocklist.json'
	$(RUN_TESTS) ansible-playbook ansible/respond_block_ip.yml -e @out/blocklist.json

shell:
	$(RUN_TESTS) bash

clean:
	$(COMPOSE) down --remove-orphans
	rm -rf out .pytest_cache
