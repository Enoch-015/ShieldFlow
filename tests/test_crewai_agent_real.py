import os

import pytest

from shieldflow.detectors import DetectorSuite
from shieldflow.inspector import Inspector
from shieldflow.trust import InMemoryTrustStore, TrustEngine
from shieldflow.integrations.crewai_middleware import CrewAIMiddleware

crewai = pytest.importorskip("crewai")  # noqa: E305
Agent = crewai.Agent  # type: ignore[attr-defined]

OPENAI_KEY_PRESENT = bool(os.getenv("OPENAI_API_KEY"))


@pytest.mark.integration
@pytest.mark.skipif(not OPENAI_KEY_PRESENT, reason="OPENAI_API_KEY not set; real agent test skipped")
def test_crewai_agent_kickoff_guarded_real():
    detectors = DetectorSuite()
    trust = TrustEngine(InMemoryTrustStore())
    inspector = Inspector(detectors, trust)
    guard = CrewAIMiddleware(inspector, session_id="crewai-real-test")

    agent = Agent(
        role="Concise assistant",
        goal="Respond briefly",
        backstory="Testing ShieldFlow integration",
        verbose=False,
    )

    result = guard.kickoff_guarded(agent, "Say hi without adding secrets.")
    raw = getattr(result, "raw", "")
    assert isinstance(raw, str)
    assert raw.strip() != ""
