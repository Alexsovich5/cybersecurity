COMPOSE ?= docker compose
RUN_TESTS = $(COMPOSE) run --rm tests

.PHONY: build test test-static test-unit test-base test-harden test-snort test-ossec test-ansible shell clean

build:
	$(COMPOSE) build base
	$(COMPOSE) build

test: test-static test-unit test-base test-harden test-snort test-ossec test-ansible

test-static:
	$(RUN_TESTS) sh -c '\
		yamllint -s ansible docker-compose.yml && \
		shellcheck scripts/*.sh && \
		shellcheck docker/*/*.sh && \
		for f in scripts/*.sh; do bash -n "$$f" || exit 1; done && \
		ansible-playbook -i localhost, --syntax-check ansible/hardening.yml && \
		ansible-lint ansible/hardening.yml && \
		python -m py_compile tools/*.py'

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

shell:
	$(RUN_TESTS) bash

clean:
	$(COMPOSE) down --remove-orphans
	rm -rf out .pytest_cache
