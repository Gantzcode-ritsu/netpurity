"""Discord webhook notifier with rate-limit handling."""

import logging
import re
import time
from typing import Any, Dict, Tuple

import requests

from netpurity.analyzer import Finding, Reason
from netpurity.utils import clean_text, format_timestamp

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 10.0
DEFAULT_RETRY_AFTER_SECONDS = 1.0
MAX_RETRY_AFTER_SECONDS = 30.0

#: Severity label and embed color (RGB integer) for each reason.
SEVERITY_BY_REASON: Dict[Reason, Tuple[str, int]] = {
    Reason.BLACKLISTED: ("critical", 0xE74C3C),
    Reason.BEACONING: ("high", 0xE67E22),
    Reason.HIGH_ENTROPY: ("medium", 0xF1C40F),
    Reason.SUSPICIOUS_TLD: ("low", 0x3498DB),
}

_WEBHOOK_PATH = re.compile(r"/api/webhooks/[^\s'\")?]+")


class DiscordNotifier:
    """Post findings to a Discord webhook as embeds."""

    def __init__(self, webhook_url: str, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> None:
        """Create a notifier for ``webhook_url``.

        Raises:
            ValueError: ``webhook_url`` does not start with https://.
        """
        if not webhook_url.startswith("https://"):
            raise ValueError("Webhook URL must start with https://")
        self._webhook_url = webhook_url
        self._timeout = timeout
        self._session = requests.Session()

    def send(self, finding: Finding) -> bool:
        """Send ``finding`` to Discord and return True on success.

        On HTTP 429 the method waits ``retry_after`` and retries once. It logs
        network and HTTP errors and returns False, so the monitor keeps running.
        """
        payload = self.build_payload(finding)
        try:
            response = self._post(payload)
            if response.status_code == 429:
                delay = self._retry_after_seconds(response)
                logger.warning("Discord rate limit hit, retrying in %.1fs", delay)
                time.sleep(delay)
                response = self._post(payload)
        except requests.RequestException as exc:
            logger.error("Could not reach Discord: %s", self._redact(str(exc)))
            return False

        if response.ok:
            return True
        logger.error(
            "Discord webhook returned HTTP %d: %s",
            response.status_code,
            self._redact(response.text[:200]),
        )
        return False

    def close(self) -> None:
        """Close the HTTP session."""
        self._session.close()

    @staticmethod
    def build_payload(finding: Finding) -> Dict[str, Any]:
        """Build the Discord webhook JSON body for ``finding``."""
        severity, color = SEVERITY_BY_REASON[finding.reason]
        timestamp = format_timestamp(finding.timestamp)
        return {
            "username": "NetPurity",
            # Domains come from the network; an empty parse list blocks @everyone
            # and other mentions.
            "allowed_mentions": {"parse": []},
            "embeds": [
                {
                    "title": f"DNS alert: {finding.reason.value}",
                    "description": clean_text(finding.detail, max_length=1000),
                    "color": color,
                    "timestamp": timestamp,
                    "footer": {"text": f"Severity: {severity}"},
                    "fields": [
                        {
                            "name": "Source IP",
                            "value": f"`{clean_text(finding.src_ip, 64)}`",
                            "inline": True,
                        },
                        {
                            "name": "Domain",
                            "value": f"`{clean_text(finding.domain, 253)}`",
                            "inline": True,
                        },
                        {
                            "name": "Entropy Score",
                            "value": f"{finding.entropy:.3f}",
                            "inline": True,
                        },
                        {
                            "name": "Reason",
                            "value": finding.reason.value,
                            "inline": True,
                        },
                        {"name": "Timestamp", "value": timestamp, "inline": True},
                    ],
                }
            ],
        }

    def _post(self, payload: Dict[str, Any]) -> requests.Response:
        """POST ``payload`` to the webhook with the configured timeout."""
        return self._session.post(self._webhook_url, json=payload, timeout=self._timeout)

    @staticmethod
    def _retry_after_seconds(response: requests.Response) -> float:
        """Read the wait time from the 429 body or header, capped at the maximum."""
        candidates = []
        try:
            body = response.json()
            if isinstance(body, dict):
                candidates.append(body.get("retry_after"))
        except ValueError:
            logger.debug("429 response had no JSON body")
        candidates.append(response.headers.get("Retry-After"))

        for value in candidates:
            try:
                seconds = float(value)
            except (TypeError, ValueError):
                continue
            if seconds >= 0:
                return min(seconds, MAX_RETRY_AFTER_SECONDS)
        return DEFAULT_RETRY_AFTER_SECONDS

    def _redact(self, text: str) -> str:
        """Strip the webhook URL and its secret token from text that goes to the logs."""
        text = text.replace(self._webhook_url, "<webhook-url>")
        return _WEBHOOK_PATH.sub("/api/webhooks/<redacted>", text)
