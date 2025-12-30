"""Example of guarding LangChain agents with ShieldFlow.

Requirements:
- pip install -e '.[langchain]'
- Set OPENAI_API_KEY (or configure ChatOpenAI with your base URL/model).

What it shows:
- Validate tool metadata to block malicious descriptions (e.g., prompt-injection text).
- Guard user prompts, tool inputs, and LLM responses via ShieldFlow callbacks.
"""

from shieldflow.detectors import DetectorSuite
from shieldflow.inspector import Inspector
from shieldflow.integrations.langchain_callback import (
    ShieldFlowCallbackHandler,
    validate_tool_metadata,
)
from shieldflow.trust import InMemoryTrustStore, TrustEngine

try:
    from langchain.agents import create_agent
    from langchain.tools import tool
    from langchain_openai import ChatOpenAI
except ImportError as exc:  # pragma: no cover
    raise SystemExit("Install langchain + langchain-openai first: pip install -e '.[langchain]'") from exc


@tool
def search(query: str) -> str:
    """Search for information."""
    return f"Results for: {query}"  # placeholder implementation


def build_guarded_agent(session_id: str):
    detectors = DetectorSuite()
    trust = TrustEngine(InMemoryTrustStore())
    inspector = Inspector(detectors, trust)

    # Validate tool descriptions (catches malicious MCP-like descriptors).
    tools = [search]
    validate_tool_metadata(tools, inspector, session_id=session_id)

    handler = ShieldFlowCallbackHandler(inspector, session_id=session_id)

    model = ChatOpenAI(model="gpt-4o-mini", temperature=0)
    agent = create_agent(model=model, tools=tools, callbacks=[handler])
    return agent


def main() -> None:
    agent = build_guarded_agent(session_id="lc-demo")
    result = agent.invoke({"messages": [{"role": "user", "content": "Find AI news."}]})
    print(result)


if __name__ == "__main__":
    main()
