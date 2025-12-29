PY ?= python
PIP ?= pip
VENV ?= .venv

.PHONY: setup demo compose-up compose-down

setup:
	$(PY) -m venv $(VENV)
	. $(VENV)/bin/activate && $(PIP) install -U pip && $(PIP) install -e .[observability,redis]

# Run the local synchronous demo (no Kafka/Flink needed).
demo:
	. $(VENV)/bin/activate && $(PY) examples/demo_pipeline.py

compose-up:
	docker compose up -d redis zookeeper kafka flink-jobmanager flink-taskmanager

compose-down:
	docker compose down

test-stack:
	. $(VENV)/bin/activate && pytest -m integration tests/test_stack.py
