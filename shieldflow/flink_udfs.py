"""Flink Table API UDF helpers to call ShieldFlow detectors inside SQL jobs.

These functions are lightweight wrappers. Register them in PyFlink like:

>>> from pyflink.table import EnvironmentSettings, TableEnvironment
>>> from shieldflow.flink_udfs import udf_detect_prompt, udf_detect_response
>>> t_env = TableEnvironment.create(EnvironmentSettings.in_streaming_mode())
>>> t_env.create_temporary_system_function("sf_detect_prompt", udf_detect_prompt)

Then in SQL:
    SELECT *, sf_detect_prompt(prompt) AS detections FROM input;

The return type is JSON (string) with detection list. Trust decisions should
run in your stream app using RedisTrustStore; UDFs only emit detections.
"""

import json
from typing import List

from .detectors import DetectorSuite, DetectionResult

# Instantiate once per Python operator
_DETECTORS = DetectorSuite()

try:
    from pyflink.table import DataTypes
    from pyflink.table.udf import udf
except ImportError:  # pragma: no cover - optional dependency
    udf = None  # type: ignore
    DataTypes = None  # type: ignore


def _results_to_json(results: List[DetectionResult]) -> str:
    return json.dumps([r.to_dict() for r in results])


def _detect_prompt_inner(text: str) -> str:
    return _results_to_json(_DETECTORS.detect_prompt(text or ""))


def _detect_response_inner(text: str) -> str:
    return _results_to_json(_DETECTORS.detect_response(text or ""))


if udf and DataTypes:
    udf_detect_prompt = udf(_detect_prompt_inner, result_type=DataTypes.STRING())
    udf_detect_response = udf(_detect_response_inner, result_type=DataTypes.STRING())
else:  # pragma: no cover - pyflink not installed
    udf_detect_prompt = None  # type: ignore
    udf_detect_response = None  # type: ignore
