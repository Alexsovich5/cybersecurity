COMPOSE ?= docker compose
RUN_TESTS = $(COMPOSE) run --rm tests

.PHONY: build test test-static test-unit shell clean

build:
	$(COMPOSE) build tests

test: test-static test-unit

test-static:
	$(RUN_TESTS) sh -c '\
		yamllint -s ansible docker-compose.yml && \
		shellcheck scripts/*.sh && \
		for f in scripts/*.sh; do bash -n "$$f" || exit 1; done && \
		ansible-playbook -i localhost, --syntax-check ansible/hardening.yml'

test-unit:
	$(RUN_TESTS) pytest tests/unit

shell:
	$(RUN_TESTS) bash

clean:
	$(COMPOSE) down --remove-orphans
	rm -rf out .pytest_cache
