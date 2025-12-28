import json
import logging
import os
from typing import Dict, Optional

try:
    import requests
except ImportError:  # pragma: no cover - optional dependency
    requests = None  # type: ignore

logger = logging.getLogger(__name__)


class DatadogClient:
    """Tiny Datadog HTTP client for metrics and incidents."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        site: str = "datadoghq.com",
        enabled: bool = True,
    ) -> None:
        self.api_key = api_key or os.getenv("DATADOG_API_KEY")
        self.site = site
        self.enabled = enabled and bool(self.api_key)

    def _headers(self) -> Dict[str, str]:
        return {
            "DD-API-KEY": self.api_key or "",
            "Content-Type": "application/json",
        }

    def send_metric(self, name: str, value: float, tags: Optional[Dict[str, str]] = None) -> None:
        if not self.enabled or requests is None:
            logger.debug("Datadog disabled or requests missing; skipping metric %s", name)
            return
        body = {
            "series": [
                {
                    "metric": name,
                    "points": [[None, value]],
                    "tags": [f"{k}:{v}" for k, v in (tags or {}).items()],
                }
            ]
        }
        url = f"https://api.{self.site}/api/v2/series"
        resp = requests.post(url, headers=self._headers(), data=json.dumps(body), timeout=3)
        if resp.status_code >= 300:
            logger.warning("Datadog metric failed %s %s", resp.status_code, resp.text)

    def send_event(self, title: str, text: str, tags: Optional[Dict[str, str]] = None) -> None:
        if not self.enabled or requests is None:
            logger.debug("Datadog disabled or requests missing; skipping event %s", title)
            return
        url = f"https://api.{self.site}/api/v2/events"
        payload = {
            "title": title,
            "text": text,
            "tags": [f"{k}:{v}" for k, v in (tags or {}).items()],
        }
        resp = requests.post(url, headers=self._headers(), data=json.dumps(payload), timeout=3)
        if resp.status_code >= 300:
            logger.warning("Datadog event failed %s %s", resp.status_code, resp.text)

    def open_incident(self, title: str, text: str, severity: str = "critical", tags: Optional[Dict[str, str]] = None) -> None:
        # Datadog incidents API v2
        if not self.enabled or requests is None:
            logger.debug("Datadog disabled or requests missing; skipping incident %s", title)
            return
        url = f"https://api.{self.site}/api/v2/incidents"
        payload = {
            "data": {
                "type": "incidents",
                "attributes": {
                    "title": title,
                    "severity": severity,
                    "customer_impacted": False,
                    "body": {"type": "incident_bodies", "attributes": {"details": text}},
                },
            }
        }
        resp = requests.post(url, headers=self._headers(), data=json.dumps(payload), timeout=3)
        if resp.status_code >= 300:
            logger.warning("Datadog incident failed %s %s", resp.status_code, resp.text)
