"""Example of guarding CrewAI agent prompts/responses with ShieldFlow.

Prereqs:
- pip install "crewai>=0.28" (or `pip install -e .[crewai]` from project root)
- Export your LLM key (e.g., OPENAI_API_KEY). This example uses CrewAI's defaults.
- Run Redis/Kafka/Flink only if you also want streaming; this example runs inline.

This example shows how to inspect/mask prompts and block risky responses.
"""

from shieldflow.detectors import DetectorSuite
from shieldflow.inspector import Inspector
from shieldflow.trust import InMemoryTrustStore, TrustEngine
from shieldflow.integrations.crewai_middleware import CrewAIMiddleware

try:
    from crewai import Agent
except ImportError:  # pragma: no cover
    raise SystemExit("Install crewai first: pip install 'crewai>=0.28'")


def build_guarded_agent(session_id: str) -> tuple[Agent, CrewAIMiddleware]:
    detectors = DetectorSuite()
    trust = TrustEngine(InMemoryTrustStore())
    inspector = Inspector(detectors, trust)
    guard = CrewAIMiddleware(inspector, session_id=session_id)

    agent = Agent(
        role="Research Analyst",
        goal="Provide concise, safe answers without leaking secrets",
        backstory="You operate behind ShieldFlow and must follow security guidance.",
        verbose=True,
    )
    return agent, guard


def main() -> None:
    agent, guard = build_guarded_agent(session_id="crewai-demo")

    # Guarded single-message kickoff (string input)
    try:
        result = guard.kickoff_guarded(agent, "Hello, please summarize today's news.")
        print("Guarded result:", getattr(result, "raw", result))
    except RuntimeError as exc:
        print("Blocked:", exc)

    # Guarded multi-message kickoff (list-of-dict)
    convo = [
        {"role": "user", "content": "My SSN is 123-45-6789, remember it."},
    ]
    try:
        guard.kickoff_guarded(agent, convo)
    except RuntimeError as exc:
        print("Blocked as expected:", exc)


if __name__ == "__main__":
    main()
