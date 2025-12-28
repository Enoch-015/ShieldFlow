# ShieldFlow: LLM Runtime IDS

ShieldFlow is a zero-trust runtime security layer for agentic systems. It inspects user prompts, LLM responses, and tool calls in real time before they reach the model or external systems. Built for Confluent (Kafka/Flink) + Datadog, it adds behavioral monitoring, trust scoring, and auditable block actions that plug into LangChain, CrewAI, or any bespoke agent stack.

## Why it exists
- Prevent inadvertent data leaks (PII, API keys) and jailbreak prompt injections.
- Detect behavioral exfiltration (high-entropy output, suspicious tool chaining).
- Provide auditable, explainable blocks with Datadog incidents and traces.

## High-level architecture

```
User/Agent -> API Gateway -> Kafka (ingest)
Kafka -> Flink/Kafka Streams Inspector (Python/SQL UDFs)
Inspector -> Trust Engine (Redis state) -> Allow/Block -> LLM
Inspector -> Tool-call inspection -> allow/deny MCP tools
Inspector -> Datadog (metrics, incidents, traces)
Datadog -> webhook -> revoke tool access / cut hands off
```

- **Inspector**: runs regex + ML/heuristic detectors (PII, injections, entropy).
- **Trust Engine**: rolling score per session; decays on risky events; gates tool access.
- **Datadog**: dashboards for Token Health, Blocked Interventions, high-entropy alerts; incident with exact prompt/response trace.
- **Connectors**: LangChain/CrewAI middleware; HTTP proxy for any model vendor.

## Data flow (prompt loop)
1. Gateway pushes prompt to Kafka topic `shieldflow.prompts.in`.
2. Flink SQL or Kafka Streams app applies UDFs (PII, injection, entropy) and enriches with `trust_score` from Redis.
3. Decision:
   - `allow`: forward to LLM.
   - `allow+mask`: redact PII before forwarding.
   - `block`: stop, emit incident to Datadog with context (trace id, Kafka offset, matched pattern, confidence).
4. Responses flow back through the same inspector; entropy/behavioral signals can degrade trust and optionally revoke tool access.

## Data flow (tool loop)
1. LLM tool calls are sent to Kafka topic `shieldflow.tools.in`.
2. Inspector checks trust score and a tool policy (allow list, max rate, max spend).
3. If trust < threshold → deny tool execution and emit Datadog alert.

## Trust score model
- Starts at 100 per session. Each event applies a delta.
- Example deltas: PII high-confidence -25; injection high-confidence -40; entropy spike -20; clean message +1 (capped).
- If score < 60 → disable non-idempotent tools; < 30 → block all tool calls and require human review.

## Detectors
- **PII**: regex for SSN, credit card, AWS keys; extendable to ML-based detectors.
- **Prompt injection**: keyword/heuristic rules ("ignore previous", "system override", embedded instructions); add embeddings/LLM scorer later.
- **Entropy**: Shannon entropy over response window to flag exfiltration-like dumps.

## Datadog observability
- Metrics: `shieldflow.blocks`, `shieldflow.allows`, `shieldflow.trust_score`, `shieldflow.token_health`.
- Events/Incidents: Detection rule fires when entropy > threshold or trust < floor; payload includes trace, patterns matched, confidence, Kafka offsets.
- Dashboard: Blocked vs Successful, Trust over time, Entropy spikes.

## Components in this repo
- `shieldflow/detectors.py`: PII, injection, entropy detectors with confidences.
- `shieldflow/trust.py`: trust scoring with pluggable store (in-memory or Redis).
- `shieldflow/inspector.py`: orchestrates detection -> decision -> action.
- `shieldflow/datadog.py`: lightweight client for metrics/incidents.
- `shieldflow/gateway_proxy.py`: reference interceptor for synchronous LLM calls.
- `shieldflow/integrations/langchain_callback.py`: callback handler to enforce decisions.
- `shieldflow/integrations/crewai_middleware.py`: simple middleware hook.
- `examples/demo_pipeline.py`: local demo wiring detectors + trust + decisions.

## Integration modes
- **Kafka/Flink**: use UDFs to call `shieldflow.detectors` and write decisions to topics (`shieldflow.decisions`).
- **HTTP middleware**: wrap upstream LLM call with `Inspector.inspect_prompt` and `inspect_response`.
- **LangChain**: attach `ShieldFlowCallbackHandler` to chains/agents to block or redact before downstream call.
- **CrewAI**: wrap agent loop with middleware to check decisions and revoke tools.

## Quick start (local, synchronous demo)
```
python -m venv .venv && source .venv/bin/activate
pip install -U pip
pip install requests
python examples/demo_pipeline.py
```

## Extending
- Swap in ML detectors (e.g., Presidio, llama-guard) in `detectors.py`.
- Implement Redis-backed `TrustStore` for horizontal scale.
- Wire to Confluent by publishing decisions to topics and consuming from Flink SQL.
- Add Datadog detection rule for entropy spikes to auto-open cases.

## Roadmap
- UDFs for Flink SQL and Kafka Streams.
- Masking/redaction options per field.
- Richer audit trails (prompt diff, tool call parameters, MCP trace IDs).
- CI/CD with integration tests against mock Kafka and Datadog.
