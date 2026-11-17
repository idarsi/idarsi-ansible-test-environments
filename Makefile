SHELL := /usr/bin/env bash

ENVIRONMENT ?= ansible-current
PROFILE ?= all

.PHONY: help install uninstall setup-host setup-venv check-scripts check-python check-dependencies validate update-dependencies

help:
	@printf '%s\n' \
		'make install [PROFILE=all|podman|kvm] [ENVIRONMENT=ansible-current]' \
		'make setup-host PROFILE=podman|kvm|all' \
		'make setup-venv ENVIRONMENT=ansible-current' \
		'make uninstall' \
		'make check-scripts' \
		'make check-python (isolated-run unit tests; no backends)' \
		'make check-dependencies' \
		'make validate'

install:
	./install.sh $(PROFILE) $(ENVIRONMENT)

uninstall:
	./uninstall.sh

setup-host:
	scripts/setup-host install $(PROFILE)

setup-venv:
	scripts/setup-venv $(ENVIRONMENT)

check-scripts:
	scripts/test-scripts
	tests/test-nested-kvm-renderer.sh

check-dependencies:
	scripts/check-dependencies

check-python:
	python3 -m unittest discover -s tests -p 'test_isolated*.py' -v

validate: check-scripts check-dependencies check-python

update-dependencies:
	scripts/update-dependencies
