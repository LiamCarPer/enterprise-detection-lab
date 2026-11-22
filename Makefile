.PHONY: install lint validate telemetry-check test test-lab coverage check lab-up lab-down lab-status lab-wait lab-bootstrap lab-reset lab-logs

install:
	uv sync --all-extras

lint:
	PYTHONPATH= uv run ruff check .
	PYTHONPATH= uv run ruff format --check .
	PYTHONPATH= uv run mypy src

validate:
	PYTHONPATH= uv run edl validate

telemetry-check:
	PYTHONPATH= uv run edl telemetry matrix --check

test:
	PYTHONPATH= uv run pytest -m "not lab" --cov=edl --cov-report=term-missing --cov-fail-under=90

test-lab:
	PYTHONPATH= uv run pytest -m lab

coverage: test

check: lint validate telemetry-check test

lab-up:
	uv run edl lab up

lab-down:
	uv run edl lab down

lab-status:
	uv run edl lab status

lab-wait:
	uv run edl lab wait

lab-bootstrap:
	uv run edl lab bootstrap

lab-reset:
	uv run edl lab reset --yes

lab-logs:
	uv run edl lab logs
