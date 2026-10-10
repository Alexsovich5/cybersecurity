COMPOSE ?= docker compose
RUN_TESTS = $(COMPOSE) run --rm tests

.PHONY: build test test-static test-unit test-base test-harden test-snort test-ossec test-ansible test-pipeline shell clean

build:
	$(COMPOSE) build base
	$(COMPOSE) build

test: test-static test-unit test-base test-harden test-snort test-ossec test-ansible test-pipeline

test-static:
	$(RUN_TESTS) sh -c '\
		yamllint -s ansible elk/*.yml docker-compose.yml && \
		shellcheck scripts/*.sh && \
		shellcheck docker/*/*.sh && \
		for f in scripts/*.sh; do bash -n "$$f" || exit 1; done && \
		ansible-playbook -i localhost, --syntax-check ansible/hardening.yml && \
		ansible-lint ansible/hardening.yml && \
		python -m py_compile tools/*.py && \
		python -m json.tool elk/es-template.json > /dev/null'

test-unit:
	$(RUN_TESTS) pytest tests/unit

test-base:
	$(COMPOSE) run --rm --no-deps base bats tests/bats/base.bats

test-harden:
	$(COMPOSE) run --rm --no-deps base bats tests/bats/harden_linux.bats

test-snort:
	$(COMPOSE) run --rm --no-deps tests python tools/traffic.py write /lab/pcaps
	$(COMPOSE) run --rm --no-deps snort bats /src/tests/bats/snort.bats

test-ossec:
	$(COMPOSE) run --rm --no-deps ossec bats /src/tests/bats/ossec.bats

test-ansible:
	$(COMPOSE) up -d --force-recreate target
	$(RUN_TESTS) pytest --hosts=ansible://targets --sudo tests/integration/test_hardening.py tests/integration/test_snort_play.py tests/integration/test_ossec_play.py

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

shell:
	$(RUN_TESTS) bash

clean:
	$(COMPOSE) down --remove-orphans
	rm -rf out .pytest_cache
