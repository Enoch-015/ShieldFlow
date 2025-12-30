-- Flink SQL job to consume ShieldFlow detection events from Kafka and write them to the filesystem.
-- Run from inside the Flink jobmanager container, e.g.:
--   docker exec -i shieldflow-flink-jobmanager-1 /opt/flink/bin/sql-client.sh -f /tmp/flink_detection_stream.sql
-- Make sure the Kafka connector jar exists at /opt/flink/lib/flink-sql-connector-kafka-1.18.1.jar in both JM/TM.

SET 'execution.runtime-mode' = 'streaming';
SET 'pipeline.jars' = 'file:///opt/flink/lib/flink-sql-connector-kafka-1.18.1.jar';

CREATE TABLE detections (
  session_id STRING,
  stage STRING,
  action STRING,
  reason STRING,
  trust_score DOUBLE,
  detections ARRAY<MAP<STRING, STRING>>,
  redacted_text STRING,
  original_text STRING
) WITH (
  'connector' = 'kafka',
  'topic-pattern' = 'shieldflow.detections.*',
  'properties.bootstrap.servers' = 'kafka:9092',
  'properties.group.id' = 'sf-flink-sink',
  'format' = 'json',
  'scan.startup.mode' = 'earliest-offset'
);

CREATE TABLE detection_fs_sink (
  session_id STRING,
  stage STRING,
  action STRING,
  reason STRING,
  trust_score DOUBLE,
  redacted_text STRING
) WITH (
  'connector' = 'filesystem',
  'path' = '/tmp/flink/detections',
  'format' = 'json'
);

INSERT INTO detection_fs_sink
SELECT session_id, stage, action, reason, trust_score, redacted_text
FROM detections;
