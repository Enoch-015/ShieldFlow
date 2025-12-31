import json
import logging
import os
import time
from typing import Any, Dict, List, Optional

try:
    import requests
except ImportError:  # pragma: no cover - optional dependency
    requests = None  # type: ignore

logger = logging.getLogger(__name__)


def build_datadog_client_from_env() -> Optional["DatadogClient"]:
    """Auto-create a DatadogClient if DATADOG_API_KEY is set in environment."""
    api_key = os.getenv("DATADOG_API_KEY")
    if not api_key:
        return None
    # Support both DD_SITE (official) and DATADOG_SITE (intuitive)
    site = os.getenv("DD_SITE") or os.getenv("DATADOG_SITE") or "datadoghq.com"
    return DatadogClient(
        api_key=api_key,
        app_key=os.getenv("DATADOG_APP_KEY"),
        site=site,
    )


class DatadogClient:
    """Datadog HTTP client for metrics, events, logs, and incidents.
    
    Supports:
    - Custom metrics (gauges, counts)
    - Events (for audit trail)
    - Log ingestion (structured detection events)
    - Incidents (for critical blocks)
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        app_key: Optional[str] = None,
        site: str = "datadoghq.com",
        enabled: bool = True,
        service: str = "shieldflow",
    ) -> None:
        self.api_key = api_key or os.getenv("DATADOG_API_KEY")
        self.app_key = app_key or os.getenv("DATADOG_APP_KEY")
        self.site = site
        self.service = service
        self.enabled = enabled and bool(self.api_key)
        
        # Track cumulative counts for proper dashboard display
        self._counters: Dict[str, int] = {}

    def _increment_counter(self, name: str, value: int = 1) -> int:
        """Increment and return the cumulative count for a metric."""
        self._counters[name] = self._counters.get(name, 0) + value
        return self._counters[name]

    def _headers(self, include_app_key: bool = False) -> Dict[str, str]:
        headers = {
            "DD-API-KEY": self.api_key or "",
            "Content-Type": "application/json",
        }
        if include_app_key and self.app_key:
            headers["DD-APPLICATION-KEY"] = self.app_key
        return headers

    def send_metric(self, name: str, value: float, tags: Optional[Any] = None, metric_type: str = "gauge") -> bool:
        """Send a custom metric to Datadog.
        
        Args:
            name: Metric name (e.g., 'shieldflow.trust_score')
            value: Metric value
            tags: Dict of tags {'key': 'value'} or list of strings ['key:value']
            metric_type: 'gauge', 'count', or 'rate'
        """
        if not self.enabled or requests is None:
            logger.debug("Datadog disabled or requests missing; skipping metric %s", name)
            return False
        
        # Support both dict and list formats for tags
        if isinstance(tags, dict):
            tag_list = [f"{k}:{v}" for k, v in tags.items()]
        elif isinstance(tags, list):
            tag_list = list(tags)
        else:
            tag_list = []
        tag_list.append(f"service:{self.service}")
        
        # Datadog metric types: 0=unspecified, 1=count, 2=rate, 3=gauge
        # For counters we want type 1 (count) which Datadog sums over the interval
        type_map = {"gauge": 3, "count": 1, "rate": 2}
        dd_type = type_map.get(metric_type, 3)
        
        body = {
            "series": [
                {
                    "metric": name,
                    "type": dd_type,
                    "points": [{"timestamp": int(time.time()), "value": value}],
                    "tags": tag_list,
                }
            ]
        }
        url = f"https://api.{self.site}/api/v2/series"
        try:
            resp = requests.post(url, headers=self._headers(), json=body, timeout=5)
            if resp.status_code >= 300:
                logger.warning("Datadog metric failed %s %s", resp.status_code, resp.text)
                return False
            return True
        except Exception as e:
            logger.warning("Datadog metric error: %s", e)
            return False

    def send_metrics_batch(self, metrics: List[Dict[str, Any]]) -> bool:
        """Send multiple metrics in a single request."""
        if not self.enabled or requests is None:
            return False
        
        series = []
        for m in metrics:
            tags = [f"{k}:{v}" for k, v in m.get("tags", {}).items()]
            tags.append(f"service:{self.service}")
            series.append({
                "metric": m["name"],
                "type": 1,
                "points": [{"timestamp": int(time.time()), "value": m["value"]}],
                "tags": tags,
            })
        
        url = f"https://api.{self.site}/api/v2/series"
        try:
            resp = requests.post(url, headers=self._headers(), json={"series": series}, timeout=5)
            return resp.status_code < 300
        except Exception as e:
            logger.warning("Datadog batch metric error: %s", e)
            return False

    def send_event(self, title: str, text: str, tags: Optional[Dict[str, str]] = None, alert_type: str = "info") -> bool:
        """Send an event to Datadog (appears in Event Stream)."""
        if not self.enabled or requests is None:
            logger.debug("Datadog disabled or requests missing; skipping event %s", title)
            return False
        
        tag_list = [f"{k}:{v}" for k, v in (tags or {}).items()]
        tag_list.append(f"service:{self.service}")
        
        url = f"https://api.{self.site}/api/v1/events"
        payload = {
            "title": title,
            "text": text,
            "tags": tag_list,
            "alert_type": alert_type,  # info, warning, error, success
            "source_type_name": "shieldflow",
        }
        try:
            resp = requests.post(url, headers=self._headers(), json=payload, timeout=5)
            if resp.status_code >= 300:
                logger.warning("Datadog event failed %s %s", resp.status_code, resp.text)
                return False
            return True
        except Exception as e:
            logger.warning("Datadog event error: %s", e)
            return False

    def send_log(self, message: str, level: str = "info", attributes: Optional[Dict[str, Any]] = None, tags: Optional[Dict[str, str]] = None) -> bool:
        """Send a structured log entry to Datadog Logs."""
        if not self.enabled or requests is None:
            return False
        
        tag_list = [f"{k}:{v}" for k, v in (tags or {}).items()]
        tag_list.append(f"service:{self.service}")
        
        log_entry = {
            "message": message,
            "ddsource": "shieldflow",
            "ddtags": ",".join(tag_list),
            "service": self.service,
            "status": level,
            **(attributes or {}),
        }
        
        url = f"https://http-intake.logs.{self.site}/api/v2/logs"
        try:
            resp = requests.post(url, headers=self._headers(), json=[log_entry], timeout=5)
            return resp.status_code < 300
        except Exception as e:
            logger.warning("Datadog log error: %s", e)
            return False

    def send_detection_event(self, event: Dict[str, Any]) -> bool:
        """Send a ShieldFlow detection event as a structured log with metrics."""
        if not self.enabled:
            return False
        
        session_id = event.get("session_id", "unknown")
        stage = event.get("stage", "unknown")
        action = event.get("action", "unknown")
        trust_score = event.get("trust_score", 0)
        detections = event.get("detections", [])
        
        tags = {
            "session_id": session_id,
            "stage": stage,
            "action": action,
        }
        
        # Send trust score as gauge (shows current value)
        self.send_metric("shieldflow.trust_score", trust_score, tags)
        
        # Send cumulative totals as gauges - these will show correctly in query_value widgets
        total_detections = self._increment_counter("total_detections", len(detections))
        self.send_metric("shieldflow.detections.total", total_detections, tags)
        
        if action == "block":
            total_blocks = self._increment_counter("total_blocks")
            self.send_metric("shieldflow.blocks.total", total_blocks, tags)
        elif action == "allow_masked":
            total_masked = self._increment_counter("total_masked")
            self.send_metric("shieldflow.masked.total", total_masked, tags)
        
        # Send cumulative counts by detection type
        for det in detections:
            kind = det.get("kind", "unknown")
            counter_name = f"detection_{kind}"
            total = self._increment_counter(counter_name)
            self.send_metric(f"shieldflow.detection.{kind}.total", total, {**tags, "detection_kind": kind})
        
        # Send structured log with full content for flagged items
        # Only log if there are detections (warning) or if blocked (error)
        if detections or action == "block":
            log_level = "error" if action == "block" else "warning"
            
            # Build detection summary
            detection_types = [d.get("kind", "unknown") for d in detections]
            detection_reasons = [d.get("reason", "") for d in detections]
            
            # Truncate original text for log display
            original_text = event.get("original_text", "")
            display_text = original_text[:500] + "..." if len(original_text) > 500 else original_text
            
            self.send_log(
                message=f"[{stage.upper()}] {action}: {', '.join(detection_types)} | {display_text}",
                level=log_level,
                attributes={
                    "shieldflow": {
                        "session_id": session_id,
                        "stage": stage,
                        "action": action,
                        "reason": event.get("reason", ""),
                        "detection_types": detection_types,
                        "detection_reasons": detection_reasons,
                        "detection_count": len(detections),
                        "trust_score": trust_score,
                        "original_text": display_text,
                        "redacted_text": event.get("redacted_text", ""),
                    },
                },
                tags=tags,
            )
        
        # Open incident for blocks
        if action == "block":
            self.open_incident(
                title=f"ShieldFlow Block: {stage}",
                text=f"Session: {session_id}\nReason: {event.get('reason')}\nOriginal: {event.get('original_text', '')[:500]}",
                severity="SEV-3",
                tags=tags,
            )
        
        return True

    def open_incident(self, title: str, text: str, severity: str = "SEV-3", tags: Optional[Dict[str, str]] = None) -> bool:
        """Create a Datadog incident (requires app key with incidents scope)."""
        if not self.enabled or requests is None or not self.app_key:
            logger.debug("Datadog disabled, requests missing, or no app key; skipping incident %s", title)
            return False
        
        url = f"https://api.{self.site}/api/v2/incidents"
        payload = {
            "data": {
                "type": "incidents",
                "attributes": {
                    "title": title,
                    "customer_impacted": False,
                    "fields": {
                        "severity": {"type": "dropdown", "value": severity},
                        "detection_method": {"type": "dropdown", "value": "monitor"},
                    },
                },
            }
        }
        try:
            resp = requests.post(url, headers=self._headers(include_app_key=True), json=payload, timeout=5)
            if resp.status_code >= 300:
                logger.warning("Datadog incident failed %s %s", resp.status_code, resp.text)
                return False
            return True
        except Exception as e:
            logger.warning("Datadog incident error: %s", e)
            return False
