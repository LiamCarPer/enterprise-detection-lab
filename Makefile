.PHONY: install lint validate telemetry-check metrics-report metrics-check test test-lab test-detections test-opensearch coverage check lab-up lab-down lab-status lab-wait lab-bootstrap ingest-identity ingest-endpoint ingest-cloud ingest-saas lab-reset lab-logs

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

metrics-report:
	PYTHONPATH= uv run edl detection report

metrics-check:
	PYTHONPATH= uv run edl detection report --check

test:
	PYTHONPATH= uv run pytest -m "not lab" --cov=edl --cov-report=term-missing --cov-fail-under=90

test-lab:
	PYTHONPATH= uv run pytest -m lab

test-detections:
	PYTHONPATH= uv run edl detection test --include-templates

test-opensearch:
	PYTHONPATH= uv run pytest -m lab \
		tests/lab/test_ingest_integration.py \
		tests/lab/test_detection_runner.py \
		tests/lab/test_investigations.py \
		tests/lab/test_benign_baseline.py \
		tests/lab/test_benign_baselines.py

coverage: test

check: lint validate telemetry-check metrics-check test

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

ingest-identity:
	PYTHONPATH= uv run edl ingest identity

ingest-endpoint:
	PYTHONPATH= uv run edl ingest endpoint

ingest-cloud:
	PYTHONPATH= uv run edl ingest cloud

ingest-saas:
	PYTHONPATH= uv run edl ingest saas

lab-reset:
	uv run edl lab reset --yes

lab-logs:
	uv run edl lab logs
