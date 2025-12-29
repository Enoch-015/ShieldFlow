-- Register Kafka source/sink and ShieldFlow UDFs inside PyFlink (pseudo-SQL).
-- Assumes you created temporary system functions `sf_detect_prompt` and `sf_detect_response`.

-- Source: prompts topic
CREATE TABLE prompts (
    session_id STRING,
    prompt STRING
) WITH (
  'connector' = 'kafka',
  'topic' = 'shieldflow.prompts.in',
  'properties.bootstrap.servers' = 'kafka:9092',
  'format' = 'json',
  'scan.startup.mode' = 'earliest-offset'
);

CREATE TABLE decisions (
    session_id STRING,
    prompt STRING,
    detections STRING,
    ts TIMESTAMP_LTZ(3),
    WATERMARK FOR ts AS ts - INTERVAL '5' SECOND
) WITH (
  'connector' = 'kafka',
  'topic' = 'shieldflow.decisions',
  'properties.bootstrap.servers' = 'kafka:9092',
  'format' = 'json'
);

INSERT INTO decisions
SELECT
  session_id,
  prompt,
  sf_detect_prompt(prompt) AS detections,
  PROCTIME() AS ts
FROM prompts;
