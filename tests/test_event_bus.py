import pytest

from shieldflow.detectors import DetectorSuite
from shieldflow.event_bus import InMemorySink
from shieldflow.inspector import Inspector
from shieldflow.trust import InMemoryTrustStore, TrustEngine


@pytest.fixture()
def sink():
    return InMemorySink()


def test_inspector_emits_prompt_and_response_events(sink):
    inspector = Inspector(DetectorSuite(), TrustEngine(InMemoryTrustStore()), event_sink=sink)
    session = "evttest"
    decision1 = inspector.inspect_prompt(session, "Hello")
    decision2 = inspector.inspect_response(session, "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()" * 2)

    assert decision1.allowed
    assert not decision2.allowed or decision2.trust.score < 100
    assert len(sink.events) == 2
    assert sink.events[0].stage == "prompt"
    assert sink.events[1].stage == "response"


def test_event_sink_failure_does_not_block(monkeypatch, sink):
    inspector = Inspector(DetectorSuite(), TrustEngine(InMemoryTrustStore()), event_sink=sink)

    def boom(event):
        raise RuntimeError("boom")

    sink.send = boom  # type: ignore
    # Should not raise despite sink failure
    inspector.inspect_prompt("session", "Hello")


def test_kafka_sink_serializes(monkeypatch):
    sent = {}

    class FakeProducer:
        def send(self, topic, value):
            sent["topic"] = topic
            sent["value"] = value

    monkeypatch.setitem(
        __import__("sys").modules,
        "kafka",
        type("K", (), {"KafkaProducer": lambda **kwargs: FakeProducer()}),
    )

    from shieldflow.event_bus import KafkaDetectionSink, DetectionEvent

    sink = KafkaDetectionSink(topic="shieldflow.detections", bootstrap_servers="dummy")
    evt = DetectionEvent(
        session_id="s",
        stage="prompt",
        action="allow",
        reason="",
        trust_score=100,
        detections=[],
        redacted_text=None,
        original_text="hi",
    )
    sink.send(evt)
    assert sent["topic"] == "shieldflow.detections"
    assert "session_id" in sent["value"]
