.PHONY: install test test-fast lint format clean help check

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

install: ## Install with dev dependencies
	pip install -e ".[dev]"

test: ## Run all tests with coverage
	pytest tests/ -v --cov=src/firmware_scanner --cov-report=term-missing

test-fast: ## Run unit tests only
	pytest tests/unit/ -v -m "not slow"

lint: ## Run linter and type checker
	ruff check src/ tests/
	ruff format --check src/ tests/
	mypy src/firmware_scanner/ --ignore-missing-imports

format: ## Auto-format code
	ruff format src/ tests/
	ruff check --fix src/ tests/

clean: ## Remove build artifacts
	rm -rf dist/ build/ *.egg-info/
	rm -rf .pytest_cache/ .mypy_cache/ .ruff_cache/ htmlcov/
	rm -f .coverage coverage.xml
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

check: lint test ## Full CI check (lint + tests)
