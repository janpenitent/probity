# One command to check, one command to build. CONTRIBUTING lists four separate
# invocations, which is four chances to skip the one that would have failed;
# CI runs all of them, so a contributor should be able to run all of them too.
.PHONY: help install lint format typecheck test check build clean

PYTHON ?= python3

help: ## Show this help
	@grep -E '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-12s %s\n", $$1, $$2}'

install: ## Install Core plus the development tooling
	$(PYTHON) -m pip install -e ".[dev]"

lint: ## Style and import order
	ruff check .

format: ## Rewrite files to the project's format
	ruff format .

typecheck: ## Static types over src/probity
	mypy

test: ## Full suite, failing below the coverage floor
	pytest

check: lint typecheck test ## Everything CI runs, in CI's order

build: ## Build the distributions and verify the wheel ships Core only
	$(PYTHON) -m build
	$(PYTHON) .github/scripts/check_wheel_contents.py

clean: ## Remove build and test artefacts
	rm -rf dist build .coverage .pytest_cache .mypy_cache .ruff_cache
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
