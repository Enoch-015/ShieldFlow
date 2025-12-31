<p align="center">
  <h1 align="center">🛡️ ShieldFlow</h1>
  <p align="center">
    <strong>Zero-Trust Runtime Security for LLM Agents</strong>
  </p>
  <p align="center">
    Inspect prompts, responses, and tool calls in real time before they reach the model or external systems.
  </p>
</p>

<p align="center">
  <a href="#installation">Installation</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#features">Features</a> •
  <a href="#integrations">Integrations</a> •
  <a href="#documentation">Documentation</a>
</p>

---

## Why ShieldFlow?

LLM agents are powerful but vulnerable. They can:
- **Leak sensitive data** (PII, API keys, internal documents)
- **Be manipulated** via prompt injection attacks
- **Execute malicious tool calls** from compromised contexts

ShieldFlow acts as a **runtime intrusion detection system (IDS)** for your AI agents, providing:

✅ Real-time inspection of all LLM traffic  
✅ Automatic PII detection and masking  
✅ Prompt injection attack detection (rule-based + Gemini AI)  
✅ Trust scoring with automatic tool revocation  
✅ Full observability via Datadog dashboards  
✅ Kafka/Flink streaming for enterprise scale  

---

## Installation

```bash
# Basic installation
pip install shieldflow

# With Datadog observability
pip install shieldflow[observability]

# With LangChain integration
pip install shieldflow[langchain]

# With CrewAI integration
pip install shieldflow[crewai]

# With Kafka/Flink streaming
pip install shieldflow[streaming]

# Everything
pip install shieldflow[all]
```

---

## Quick Start

### Basic Usage

```python
from shieldflow import Inspector, DetectorSuite, TrustEngine, InMemoryTrustStore

# Initialize ShieldFlow
detectors = DetectorSuite()  # Auto-enables Gemini if GEMINI_API_KEY is set
trust_engine = TrustEngine(InMemoryTrustStore())
inspector = Inspector(detectors, trust_engine)

# Inspect a prompt before sending to LLM
result = inspector.inspect_prompt("session-123", user_prompt)

if result.allowed:
    # Safe to send - use redacted text if PII was found
    clean_prompt = result.redacted_text or user_prompt
    response = llm.generate(clean_prompt)
    
    # Inspect the response too
    response_result = inspector.inspect_response("session-123", response)
else:
    # Blocked - potential attack detected
    print(f"Blocked: {result.reason}")
```

### Environment Variables

```bash
# Gemini AI Detection (recommended)
export GEMINI_API_KEY=your_gemini_api_key

# Datadog Observability
export DATADOG_API_KEY=your_datadog_api_key
export DATADOG_APP_KEY=your_datadog_app_key
export DD_SITE=us5.datadoghq.com  # Your Datadog region

# Kafka Streaming (optional)
export SHIELDFLOW_KAFKA_BOOTSTRAP=localhost:9092
export SHIELDFLOW_KAFKA_TOPIC=shieldflow.detections
```

---

## CLI Commands

ShieldFlow includes a CLI for easy setup:

```bash
# Check your environment
shieldflow doctor

# Interactive setup wizard
shieldflow setup

# Set up Datadog dashboard and monitors
shieldflow setup datadog

# Generate docker-compose.yml for local stack
shieldflow setup docker
```

---

## Features

### 🔍 Detection Suite

| Detector | Description | Confidence |
|----------|-------------|------------|
| **PII Detection** | SSN, credit cards, emails, phone numbers, AWS keys | High |
| **Prompt Injection** | "Ignore previous", "system override", embedded instructions | High |
| **High Entropy** | Detects potential data exfiltration (base64, hex dumps) | Medium |
| **Gemini AI** | Dynamic AI-based analysis for sophisticated attacks | High |

### 📊 Trust Scoring

Each session starts with a trust score of **100**. Risky events decrease the score:

| Event | Score Impact |
|-------|--------------|
| PII detected | -25 |
| Prompt injection | -40 |
| High entropy response | -20 |
| Clean message | +1 (capped) |

**Trust thresholds:**
- `score < 60` → Disable non-idempotent tools
- `score < 30` → Block all tool calls, require human review

### 🛠️ Tool & MCP Guarding

ShieldFlow inspects tool descriptions and outputs for injection attacks:

```python
from shieldflow.integrations.langchain_callback import validate_tool_metadata

# Validate before registering tools
tools = [search_tool, calculator_tool]
issues = validate_tool_metadata(tools, inspector)

if issues:
    print(f"Dangerous tools detected: {issues}")
```

---

## Integrations

### LangChain

```python
from langchain.chat_models import ChatOpenAI
from shieldflow.integrations.langchain_callback import ShieldFlowCallbackHandler

# Create callback handler
handler = ShieldFlowCallbackHandler(inspector, session_id="user-123")

# Attach to your chain
llm = ChatOpenAI(callbacks=[handler])
chain = create_your_chain(llm)

# All prompts and responses are automatically inspected
result = chain.invoke({"input": user_message})
```

### CrewAI

```python
from crewai import Agent, Crew, Task
from shieldflow.integrations.crewai_middleware import CrewAIMiddleware

# Wrap your crew with ShieldFlow
middleware = CrewAIMiddleware(inspector)

# Guarded kickoff - inspects prompts and responses
result = middleware.kickoff_guarded(
    crew=crew,
    inputs={"topic": user_input},
    session_id="crew-session-123"
)
```

### Kafka/Flink Streaming

```python
# Detections are automatically streamed when env vars are set
# SHIELDFLOW_KAFKA_BOOTSTRAP=localhost:9092
# SHIELDFLOW_KAFKA_TOPIC=shieldflow.detections

# Or configure manually
from shieldflow.event_bus import KafkaSink

sink = KafkaSink(bootstrap_servers="kafka:9092", topic="detections")
inspector = Inspector(detectors, trust_engine, event_sink=sink)
```

---

## Datadog Observability

### Automatic Setup

```bash
# Set your credentials
export DATADOG_API_KEY=your_api_key
export DATADOG_APP_KEY=your_app_key
export DD_SITE=us5.datadoghq.com

# Run setup
shieldflow setup datadog
```

This creates:
- **Dashboard** with trust scores, detection counts, and flagged content log
- **Monitors** for high block rates, low trust scores, and attack spikes

### Metrics Sent

| Metric | Type | Description |
|--------|------|-------------|
| `shieldflow.trust_score` | Gauge | Current session trust score |
| `shieldflow.blocks.total` | Gauge | Cumulative blocked requests |
| `shieldflow.masked.total` | Gauge | Cumulative masked requests |
| `shieldflow.detection.*.total` | Gauge | Counts by detection type |

### Log Stream

All flagged prompts, tool descriptions, and outputs are logged with:
- Original text (truncated)
- Detection types
- Action taken
- Session ID

---

## Docker Stack

For local development with Redis, Kafka, and Flink:

```bash
# Generate docker-compose.yml
shieldflow setup docker

# Start the stack
docker-compose up -d

# Services:
# - Redis:  localhost:6380
# - Kafka:  localhost:19092  
# - Flink:  http://localhost:8081
```

### Using Redis for Trust Storage

```python
import redis
from shieldflow.trust import TrustEngine, RedisTrustStore

r = redis.Redis(host="localhost", port=6380)
trust_engine = TrustEngine(RedisTrustStore(r))
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Your Application                          │
│  (LangChain, CrewAI, Custom Agent)                               │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                      ShieldFlow Inspector                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐           │
│  │ PII Detector │  │  Injection   │  │   Entropy    │           │
│  │              │  │  Detector    │  │   Detector   │           │
│  └──────────────┘  └──────────────┘  └──────────────┘           │
│  ┌──────────────────────────────────────────────────┐           │
│  │           Gemini AI Safety Detector              │           │
│  └──────────────────────────────────────────────────┘           │
│                          │                                       │
│                          ▼                                       │
│  ┌──────────────────────────────────────────────────┐           │
│  │              Trust Engine (Redis)                 │           │
│  │         Score: 100 → Decision: allow/block        │           │
│  └──────────────────────────────────────────────────┘           │
└─────────────────────────┬───────────────────────────────────────┘
                          │
          ┌───────────────┼───────────────┐
          ▼               ▼               ▼
    ┌──────────┐    ┌──────────┐    ┌──────────┐
    │  Kafka   │    │ Datadog  │    │   LLM    │
    │ (stream) │    │ (observe)│    │ (if safe)│
    └──────────┘    └──────────┘    └──────────┘
```

---

## API Reference

### Inspector

```python
class Inspector:
    def inspect_prompt(
        self, 
        session_id: str, 
        prompt: str, 
        allow_masking: bool = True
    ) -> InspectionDecision:
        """Inspect a user prompt before sending to LLM."""
        
    def inspect_response(
        self, 
        session_id: str, 
        response: str
    ) -> InspectionDecision:
        """Inspect an LLM response before returning to user."""
```

### InspectionDecision

```python
@dataclass
class InspectionDecision:
    allowed: bool           # Whether to proceed
    redacted_text: str      # Text with PII masked (if any)
    detections: List[DetectionResult]  # What was found
    trust: TrustDecision    # Trust score info
    action: str             # "allow" | "allow_masked" | "block"
    reason: str             # Human-readable explanation
```

### DetectorSuite

```python
class DetectorSuite:
    def __init__(self, use_gemini: bool = None):
        """
        Initialize detectors.
        
        Args:
            use_gemini: Enable Gemini AI detection.
                       None = auto-detect from GEMINI_API_KEY env var
        """
```

---

## Examples

See the `examples/` directory for complete examples:

- `demo_pipeline.py` - Basic detection demo
- `crewai_guarded_agent.py` - CrewAI integration
- `langchain_guarded_agent.py` - LangChain integration
- `flink_sql_example.sql` - Flink SQL UDF usage

---

## Contributing

Contributions are welcome! Please see our [Contributing Guide](CONTRIBUTING.md).

```bash
# Development setup
git clone https://github.com/Enoch-015/ShieldFlow.git
cd ShieldFlow
pip install -e ".[dev]"

# Run tests
pytest

# Run with coverage
pytest --cov=shieldflow
```

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

## Security

Found a vulnerability? Please report it responsibly by emailing security@shieldflow.dev or opening a private security advisory on GitHub.

---

<p align="center">
  Built with ❤️ for safer AI agents
</p>
