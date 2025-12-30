# ShieldFlow Examples

This directory contains examples showing how to integrate ShieldFlow with popular LLM frameworks.

## Quick Start

```bash
# Install ShieldFlow with all extras
pip install -e ".[crewai,langchain,streaming]"

# Copy and configure environment
cp .env.example .env
# Edit .env with your API keys
```

## Automatic Kafka Streaming

ShieldFlow automatically streams all detections to Kafka when you set these environment variables:

```bash
export SHIELDFLOW_KAFKA_BOOTSTRAP=localhost:19092
export SHIELDFLOW_KAFKA_TOPIC=shieldflow.detections
```

**No code changes required!** The `Inspector` class auto-detects these variables and streams events.

## Starting the Infrastructure

```bash
# From project root
docker-compose up -d

# Verify services are running
docker-compose ps
```

This starts:
- **Kafka** (localhost:19092) - Event streaming
- **Flink** (localhost:8081) - Stream processing
- **Redis** (localhost:6380) - Trust score persistence

## Examples

### 1. CrewAI Guarded Agent (`crewai_guarded_agent.py`)

Protects CrewAI agents with automatic:
- Prompt injection detection and blocking
- PII masking (SSN, emails, credit cards)
- Malicious tool description blocking

```bash
# Basic usage
python crewai_guarded_agent.py

# With Kafka streaming
SHIELDFLOW_KAFKA_BOOTSTRAP=localhost:19092 \
SHIELDFLOW_KAFKA_TOPIC=shieldflow.detections \
python crewai_guarded_agent.py
```

### 2. LangChain Guarded Agent (`langchain_guarded_agent.py`)

Protects LangChain chains/agents via callbacks:
- Inspects prompts before LLM calls
- Validates tool inputs/outputs
- Blocks malicious tool registrations

```bash
OPENAI_API_KEY=sk-xxx python langchain_guarded_agent.py
```

### 3. Demo Pipeline (`demo_pipeline.py`)

Shows the core ShieldFlow flow without external LLM:
- Gateway proxy pattern
- PII detection and masking
- Prompt injection blocking

```bash
python demo_pipeline.py

SHIELDFLOW_KAFKA_BOOTSTRAP=localhost:19092 SHIELDFLOW_KAFKA_TOPIC=shieldflow.crewai-demo .venv/bin/python examples/crewai_guarded_agent.py 2>&1
```

## Viewing Detection Events

### Kafka Console Consumer

```bash
docker-compose exec kafka kafka-console-consumer \
  --bootstrap-server localhost:9092 \
  --topic shieldflow.detections \
  --from-beginning
```

### Flink SQL (Real-time Analytics)

```bash
docker-compose exec flink-jobmanager /opt/flink/bin/sql-client.sh
```

Then run queries from `flink_detection_stream.sql`.

## Detection Event Schema

Events streamed to Kafka follow this schema:

```json
{
  "session_id": "crewai-demo-001",
  "stage": "prompt|response|metadata:tool",
  "action": "allow|mask|block",
  "reason": "Description of detection",
  "trust_score": 0.85,
  "detections": [
    {"type": "pii", "subtype": "ssn", "reason": "SSN pattern detected"}
  ],
  "redacted_text": "My SSN is [REDACTED]",
  "original_text": "My SSN is 123-45-6789"
}
```

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   CrewAI Agent  │     │ LangChain Chain │     │   Your App      │
└────────┬────────┘     └────────┬────────┘     └────────┬────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │       Inspector         │
                    │  (auto Kafka if env set)│
                    └────────────┬────────────┘
                                 │
         ┌───────────────────────┼───────────────────────┐
         │                       │                       │
┌────────▼────────┐   ┌──────────▼──────────┐   ┌───────▼───────┐
│  DetectorSuite  │   │    TrustEngine      │   │  KafkaSink    │
│ PII/Injection/  │   │  (score sessions)   │   │ (auto-stream) │
│    Entropy      │   │                     │   │               │
└─────────────────┘   └─────────────────────┘   └───────┬───────┘
                                                        │
                                               ┌────────▼────────┐
                                               │      Kafka      │
                                               │ (Flink consumes)│
                                               └─────────────────┘
```
