SHELL := /usr/bin/env bash

ENVIRONMENT ?= ansible-current
IMAGE ?= localhost/idarsi/ansible-test:$(ENVIRONMENT)
ROLE_PATH ?=
MOLECULE_ARGS ?= test
export MOLECULE_ARGS

.PHONY: help build build-min build-current build-next validate check-dependencies check-scripts test test-min test-current test-next update-dependencies

help:
	@printf '%s\n' \
		'make build ENVIRONMENT=ansible-current' \
		'make test ROLE_PATH=/path/to/role ENVIRONMENT=ansible-current' \
		'make validate' \
		'make update-dependencies'

build:
	IMAGE=$(IMAGE) scripts/build $(ENVIRONMENT)

build-min:
	ENVIRONMENT=ansible-min IMAGE=$(IMAGE) scripts/build ansible-min

build-current:
	ENVIRONMENT=ansible-current IMAGE=$(IMAGE) scripts/build ansible-current

build-next:
	ENVIRONMENT=ansible-next IMAGE=$(IMAGE) scripts/build ansible-next

validate:
	@scripts/test-scripts
	@for environment in ansible-min ansible-current ansible-next; do \
		scripts/build --validate-only $$environment; \
	done

check-dependencies:
	scripts/check-dependencies

check-scripts:
	scripts/test-scripts

test:
	IMAGE=$(IMAGE) scripts/test $(ENVIRONMENT) $(ROLE_PATH)

test-min:
	ENVIRONMENT=ansible-min make test

test-current:
	ENVIRONMENT=ansible-current make test

test-next:
	ENVIRONMENT=ansible-next make test

update-dependencies:
	scripts/update-dependencies
