.PHONY: bootstrap keys test lint up down demo attack experiment verify-runs

KEY_DIR ?= secrets

bootstrap:
	uv sync --dev

keys:
	@test -n "$(NODE_ID)" || (echo "Usage: make keys NODE_ID=edge-1 [KEY_DIR=secrets]" && exit 2)
	python scripts/generate_node_keys.py --node-id "$(NODE_ID)" --output-dir "$(KEY_DIR)"

test:
	python -m pytest

lint:
	python -m ruff check .
	python -m mypy secureedge apps

up:
	docker compose up --build

down:
	docker compose down

demo:
	@echo "The supervisor demo will be enabled after the privacy-mode vertical slice is integrated."
	@exit 2

attack:
	@echo "Attack adapters are reserved for Milestone 2."
	@exit 2

experiment:
	@echo "Experiment runs are reserved for Milestone 3."
	@exit 2

verify-runs:
	@echo "Run-artifact verification is reserved for Milestone 3."
	@exit 2
