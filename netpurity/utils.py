"""Shared helpers for NetPurity: entropy, domain parsing, timestamps and text cleaning."""

import math
import re
from collections import Counter
from datetime import datetime, timezone
from typing import List, Union

# Labels such as "co" in "example.co.uk" belong to the public suffix when a
# two-letter country-code TLD follows them.
_COUNTRY_SECOND_LEVELS = frozenset({"co", "com", "org", "net", "gov", "edu", "ac"})

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def shannon_entropy(text: str) -> float:
    """Return the Shannon entropy of ``text`` in bits per character, or 0.0 if empty."""
    if not text:
        return 0.0
    total = len(text)
    entropy = -sum(
        (count / total) * math.log2(count / total) for count in Counter(text).values()
    )
    # max() converts the -0.0 that single-symbol strings produce into 0.0.
    return max(0.0, entropy)


def normalize_domain(domain: str) -> str:
    """Lowercase ``domain``, trim whitespace and strip trailing dots."""
    return domain.strip().lower().rstrip(".")


def split_labels(domain: str) -> List[str]:
    """Return the non-empty labels of ``domain`` after normalizing it."""
    return [label for label in normalize_domain(domain).split(".") if label]


def normalize_tld(tld: str) -> str:
    """Return ``tld`` in lowercase with one leading dot, or "" if nothing remains."""
    bare = tld.strip().lower().lstrip(".")
    return f".{bare}" if bare else ""


def extract_tld(domain: str) -> str:
    """Return the TLD of ``domain`` with a leading dot, or "" for a single-label name."""
    labels = split_labels(domain)
    if len(labels) < 2:
        return ""
    return f".{labels[-1]}"


def extract_second_level_label(domain: str) -> str:
    """Return the label that the entropy check measures: the one left of the TLD.

    ``mail.example.com`` and ``example.co.uk`` both give ``example``; the
    function treats suffixes such as ``co.uk`` as one TLD. It returns a
    single-label name unchanged and returns "" for an empty domain.
    """
    labels = split_labels(domain)
    if not labels:
        return ""
    if len(labels) == 1:
        return labels[0]
    if (
        len(labels) >= 3
        and len(labels[-1]) == 2
        and labels[-2] in _COUNTRY_SECOND_LEVELS
    ):
        return labels[-3]
    return labels[-2]


def format_timestamp(timestamp: float) -> str:
    """Format a Unix ``timestamp`` as UTC ISO 8601, for example 2024-01-31T12:00:00Z."""
    moment = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    return moment.isoformat(timespec="seconds").replace("+00:00", "Z")


def decode_qname(raw: Union[bytes, str]) -> str:
    """Decode a DNS qname (bytes or str) into a normalized domain string."""
    text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw
    return normalize_domain(text)


def clean_text(text: str, max_length: int = 200) -> str:
    """Sanitize network-supplied ``text`` for the console and for Discord.

    Strip control characters and swap backticks for apostrophes, because
    backticks break inline code formatting. Truncate the result to
    ``max_length`` characters.
    """
    cleaned = _CONTROL_CHARS.sub("", text).replace("`", "'")
    if len(cleaned) > max_length:
        cleaned = cleaned[: max_length - 1] + "\u2026"
    return cleaned
