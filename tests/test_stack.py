import os
import socket
import time
import uuid

import pytest

try:
    import redis
except ImportError:  # pragma: no cover
    redis = None

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None

try:
    from kafka import KafkaConsumer, KafkaProducer
except ImportError:  # pragma: no cover
    KafkaConsumer = None  # type: ignore
    KafkaProducer = None  # type: ignore


REDIS_HOST = os.getenv("SHIELDFLOW_REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("SHIELDFLOW_REDIS_PORT", "6380"))
KAFKA_BOOTSTRAP = os.getenv("SHIELDFLOW_KAFKA_BOOTSTRAP", "localhost:9092")
FLINK_HOST = os.getenv("SHIELDFLOW_FLINK_HOST", "localhost")
FLINK_PORT = int(os.getenv("SHIELDFLOW_FLINK_PORT", "8081"))


def _is_port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect((host, port))
            return True
        except OSError:
            return False


def _skip_if_missing(condition: bool, reason: str):
    if not condition:
        pytest.skip(reason)


@pytest.mark.integration
def test_redis_ping():
    _skip_if_missing(redis is not None, "redis package not installed")
    _skip_if_missing(_is_port_open(REDIS_HOST, REDIS_PORT), "Redis not reachable")
    client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT)
    pong = client.ping()
    assert pong is True


@pytest.mark.integration
def test_kafka_round_trip():
    _skip_if_missing(KafkaProducer is not None, "kafka-python not installed")
    _skip_if_missing(_is_port_open(KAFKA_BOOTSTRAP.split(":")[0], int(KAFKA_BOOTSTRAP.split(":")[1])), "Kafka not reachable")

    topic = f"shieldflow.test.{uuid.uuid4().hex[:8]}"
    producer = KafkaProducer(bootstrap_servers=KAFKA_BOOTSTRAP, retries=3)
    producer.send(topic, b"hello")
    producer.flush()

    consumer = KafkaConsumer(
        topic,
        bootstrap_servers=KAFKA_BOOTSTRAP,
        auto_offset_reset="earliest",
        consumer_timeout_ms=3000,
        enable_auto_commit=False,
    )
    messages = list(consumer)
    assert any(m.value == b"hello" for m in messages)
    consumer.close()
    producer.close()


@pytest.mark.integration
def test_flink_ui_up():
    _skip_if_missing(requests is not None, "requests not installed")
    _skip_if_missing(_is_port_open(FLINK_HOST, FLINK_PORT), "Flink UI not reachable")
    url = f"http://{FLINK_HOST}:{FLINK_PORT}/overview"
    resp = requests.get(url, timeout=2)
    assert resp.status_code == 200
    data = resp.json()
    assert "taskmanagers" in data or "slots-total" in data
