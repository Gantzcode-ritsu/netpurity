"""Domain analysis: blacklist, suspicious TLD, entropy and beaconing detection."""

import logging
from collections import deque
from dataclasses import dataclass
from enum import Enum
from typing import Deque, Dict, FrozenSet, Iterable, List, Optional, Set, Tuple

from netpurity.utils import (
    extract_second_level_label,
    extract_tld,
    normalize_domain,
    normalize_tld,
    shannon_entropy,
)

logger = logging.getLogger(__name__)

DEFAULT_SUSPICIOUS_TLDS: FrozenSet[str] = frozenset(
    {".tk", ".xyz", ".top", ".gq", ".ml", ".cf", ".ga"}
)


class Reason(str, Enum):
    """The check that flagged a domain. Read ``.value`` for the plain string."""

    BLACKLISTED = "BLACKLISTED"
    SUSPICIOUS_TLD = "SUSPICIOUS_TLD"
    HIGH_ENTROPY = "HIGH_ENTROPY"
    BEACONING = "BEACONING"


@dataclass(frozen=True)
class Finding:
    """One suspicious observation that :class:`DomainAnalyzer` produced."""

    reason: Reason
    src_ip: str
    domain: str
    entropy: float
    timestamp: float
    detail: str = ""


class DomainAnalyzer:
    """Flag suspicious DNS queries and rate-limit repeated findings."""

    def __init__(
        self,
        entropy_threshold: float = 3.8,
        min_label_length: int = 12,
        suspicious_tlds: Optional[Iterable[str]] = None,
        blacklist: Optional[Iterable[str]] = None,
        beacon_window_seconds: float = 60,
        beacon_threshold: int = 20,
        cooldown_seconds: float = 300,
    ) -> None:
        """Create an analyzer.

        Args:
            entropy_threshold: minimum label entropy (bits per character) to flag.
            min_label_length: shortest label that gets an entropy check.
            suspicious_tlds: TLDs to flag. Defaults to DEFAULT_SUSPICIOUS_TLDS.
            blacklist: exact domains to flag on each query.
            beacon_window_seconds: length of the beaconing sliding window.
            beacon_threshold: number of queries from one source to one domain
                inside the window that counts as beaconing.
            cooldown_seconds: minimum gap between two identical findings for
                the same (src_ip, domain, reason).

        Raises:
            ValueError: a numeric setting is out of range.
        """
        if beacon_threshold < 1:
            raise ValueError("beacon_threshold must be at least 1")
        if beacon_window_seconds <= 0:
            raise ValueError("beacon_window_seconds must be greater than 0")
        if cooldown_seconds < 0:
            raise ValueError("cooldown_seconds must not be negative")

        self.entropy_threshold = entropy_threshold
        self.min_label_length = min_label_length
        self.beacon_window_seconds = beacon_window_seconds
        self.beacon_threshold = beacon_threshold
        self.cooldown_seconds = cooldown_seconds

        tlds = DEFAULT_SUSPICIOUS_TLDS if suspicious_tlds is None else suspicious_tlds
        self.suspicious_tlds: Set[str] = {
            tld for tld in (normalize_tld(item) for item in tlds) if tld
        }
        self.blacklist: Set[str] = {
            name
            for name in (normalize_domain(item) for item in (blacklist or ()))
            if name
        }

        # Last N query timestamps per (src_ip, domain); N equals the beacon threshold.
        self._beacon_hits: Dict[Tuple[str, str], Deque[float]] = {}
        # Time of the last finding per (src_ip, domain, reason).
        self._last_alert: Dict[Tuple[str, str, Reason], float] = {}
        self._last_sweep: Optional[float] = None

    def analyze(self, src_ip: str, domain: str, timestamp: float) -> List[Finding]:
        """Analyze one DNS query and return the findings to report.

        Pass ``timestamp`` as Unix seconds. The caller supplies it, so results
        stay deterministic. The analyzer drops a finding that falls inside its
        cooldown, so the returned list can be empty.
        """
        domain = normalize_domain(domain)
        if not domain:
            return []

        self._sweep(timestamp)
        label = extract_second_level_label(domain)
        entropy = shannon_entropy(label)

        candidates: List[Tuple[Reason, str]] = []

        if domain in self.blacklist:
            candidates.append((Reason.BLACKLISTED, "Domain is on the blacklist"))

        tld = extract_tld(domain)
        if tld and tld in self.suspicious_tlds:
            candidates.append(
                (Reason.SUSPICIOUS_TLD, f"{tld} is a suspicious top-level domain")
            )

        if len(label) >= self.min_label_length and entropy >= self.entropy_threshold:
            candidates.append(
                (
                    Reason.HIGH_ENTROPY,
                    f"Label {label!r} has entropy {entropy:.2f} bits/char "
                    f"(threshold {self.entropy_threshold}, length {len(label)})",
                )
            )

        hit_count = self._record_hit(src_ip, domain, timestamp)
        if hit_count >= self.beacon_threshold:
            candidates.append(
                (
                    Reason.BEACONING,
                    f"{hit_count} queries within {self.beacon_window_seconds:g}s "
                    f"(threshold {self.beacon_threshold})",
                )
            )

        findings: List[Finding] = []
        for reason, detail in candidates:
            if self._in_cooldown(src_ip, domain, reason, timestamp):
                continue
            self._last_alert[(src_ip, domain, reason)] = timestamp
            findings.append(Finding(reason, src_ip, domain, entropy, timestamp, detail))
        return findings

    def _record_hit(self, src_ip: str, domain: str, timestamp: float) -> int:
        """Add the query to its sliding window and return the hit count inside it."""
        key = (src_ip, domain)
        hits = self._beacon_hits.get(key)
        if hits is None:
            # maxlen caps memory for a single noisy (src_ip, domain) pair.
            hits = deque(maxlen=self.beacon_threshold)
            self._beacon_hits[key] = hits
        self._purge(hits, timestamp)
        hits.append(timestamp)
        return len(hits)

    def _purge(self, hits: Deque[float], now: float) -> None:
        """Drop timestamps older than the window that ends at ``now``."""
        while hits and now - hits[0] > self.beacon_window_seconds:
            hits.popleft()

    def _in_cooldown(
        self, src_ip: str, domain: str, reason: Reason, timestamp: float
    ) -> bool:
        """Return True if the same finding went out less than ``cooldown_seconds`` ago."""
        last = self._last_alert.get((src_ip, domain, reason))
        return last is not None and (timestamp - last) < self.cooldown_seconds

    def _sweep(self, now: float) -> None:
        """Delete idle windows and expired cooldowns, at most once per window."""
        if self._last_sweep is None:
            self._last_sweep = now
            return
        if now - self._last_sweep < self.beacon_window_seconds:
            return
        self._last_sweep = now

        for key in list(self._beacon_hits):
            hits = self._beacon_hits[key]
            self._purge(hits, now)
            if not hits:
                del self._beacon_hits[key]

        expired = [
            key
            for key, last in self._last_alert.items()
            if now - last >= self.cooldown_seconds
        ]
        for key in expired:
            del self._last_alert[key]
        logger.debug(
            "Sweep done: %d beacon windows and %d cooldowns tracked",
            len(self._beacon_hits),
            len(self._last_alert),
        )
