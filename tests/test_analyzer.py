"""Unit tests for netpurity.utils and netpurity.analyzer.

The tests open no sockets, sniff no packets and make no network calls. Each
test passes its timestamps as arguments, so results stay deterministic.
"""

import pytest

from netpurity.analyzer import DomainAnalyzer, Finding, Reason
from netpurity.utils import (
    extract_second_level_label,
    extract_tld,
    normalize_domain,
    shannon_entropy,
)

SRC_IP = "192.168.1.10"
OTHER_IP = "192.168.1.11"
T0 = 1_700_000_000.0

# 18 distinct characters give an entropy of log2(18), about 4.17 bits per character.
RANDOM_LABEL = "x7k2m9qz4w8jp3vn5b"


def reasons(findings):
    """Return the set of reasons in ``findings``."""
    return {finding.reason for finding in findings}


# --- shannon_entropy -------------------------------------------------------


def test_entropy_of_empty_string_is_zero():
    assert shannon_entropy("") == 0.0


def test_entropy_of_repeated_character_is_zero():
    assert shannon_entropy("aaaaaaaa") == 0.0


def test_entropy_of_abcd_is_two_bits():
    # Four symbols with equal probability: -4 * (1/4 * log2(1/4)) = 2.0
    assert shannon_entropy("abcd") == pytest.approx(2.0)


def test_entropy_of_aabb_is_one_bit():
    # Two symbols with equal probability: -2 * (1/2 * log2(1/2)) = 1.0
    assert shannon_entropy("aabb") == pytest.approx(1.0)


# --- domain helpers --------------------------------------------------------


def test_normalize_domain_lowercases_and_strips_trailing_dot():
    assert normalize_domain("  WWW.Example.COM. ") == "www.example.com"


@pytest.mark.parametrize(
    "domain, expected_label, expected_tld",
    [
        ("google.com", "google", ".com"),
        ("mail.google.com.", "google", ".com"),
        ("example.co.uk", "example", ".uk"),
        ("localhost", "localhost", ""),
        ("", "", ""),
    ],
)
def test_label_and_tld_extraction(domain, expected_label, expected_tld):
    assert extract_second_level_label(domain) == expected_label
    assert extract_tld(domain) == expected_tld


# --- DomainAnalyzer: configuration ----------------------------------------


def test_default_configuration_matches_specification():
    analyzer = DomainAnalyzer()
    assert analyzer.entropy_threshold == 3.8
    assert analyzer.min_label_length == 12
    assert {".tk", ".xyz", ".top", ".gq", ".ml", ".cf", ".ga"} <= analyzer.suspicious_tlds
    assert analyzer.blacklist == set()
    assert analyzer.beacon_window_seconds == 60
    assert analyzer.beacon_threshold == 20
    assert analyzer.cooldown_seconds == 300


@pytest.mark.parametrize(
    "kwargs",
    [
        {"beacon_threshold": 0},
        {"beacon_window_seconds": 0},
        {"cooldown_seconds": -1},
    ],
)
def test_invalid_configuration_is_rejected(kwargs):
    with pytest.raises(ValueError):
        DomainAnalyzer(**kwargs)


# --- DomainAnalyzer: entropy, TLD, blacklist -------------------------------


def test_high_entropy_label_is_flagged():
    findings = DomainAnalyzer().analyze(SRC_IP, f"{RANDOM_LABEL}.com", T0)

    assert reasons(findings) == {Reason.HIGH_ENTROPY}
    finding = findings[0]
    assert isinstance(finding, Finding)
    assert finding.src_ip == SRC_IP
    assert finding.domain == f"{RANDOM_LABEL}.com"
    assert finding.entropy > 3.8
    assert finding.timestamp == T0


@pytest.mark.parametrize(
    "domain",
    ["google.com", "www.wikipedia.org", "mail.example.com", "github.com."],
)
def test_normal_domains_are_not_flagged(domain):
    assert DomainAnalyzer().analyze(SRC_IP, domain, T0) == []


def test_short_random_label_is_ignored_below_min_length():
    # The label has high entropy and falls below min_label_length.
    assert DomainAnalyzer().analyze(SRC_IP, "x7k2m9.com", T0) == []


@pytest.mark.parametrize("tld", [".tk", ".xyz", ".top", ".gq", ".ml", ".cf", ".ga"])
def test_suspicious_tld_is_flagged(tld):
    findings = DomainAnalyzer().analyze(SRC_IP, f"example{tld}", T0)
    assert reasons(findings) == {Reason.SUSPICIOUS_TLD}


def test_custom_suspicious_tlds_replace_the_defaults():
    analyzer = DomainAnalyzer(suspicious_tlds=["zip"])
    assert reasons(analyzer.analyze(SRC_IP, "example.zip", T0)) == {Reason.SUSPICIOUS_TLD}
    assert analyzer.analyze(SRC_IP, "example.tk", T0 + 1) == []


def test_blacklisted_domain_is_flagged_after_normalization():
    analyzer = DomainAnalyzer(blacklist={"Evil.Example.com."})

    findings = analyzer.analyze(SRC_IP, "EVIL.example.com.", T0)

    assert reasons(findings) == {Reason.BLACKLISTED}
    assert findings[0].domain == "evil.example.com"
    assert analyzer.analyze(SRC_IP, "good.example.com", T0) == []


# --- DomainAnalyzer: beaconing --------------------------------------------


def test_beaconing_triggers_once_threshold_is_crossed_within_window():
    analyzer = DomainAnalyzer(beacon_threshold=5, beacon_window_seconds=60)

    results = [analyzer.analyze(SRC_IP, "example.com", T0 + i) for i in range(10)]

    # Requests 1-4 stay below the threshold; request 5 crosses it.
    assert all(result == [] for result in results[:4])
    assert reasons(results[4]) == {Reason.BEACONING}
    # Requests 6-10 keep the count above the threshold; the cooldown drops the repeats.
    assert all(result == [] for result in results[5:])


def test_beaconing_does_not_trigger_when_requests_are_spread_beyond_window():
    analyzer = DomainAnalyzer(beacon_threshold=5, beacon_window_seconds=60)

    # One request per 30 seconds puts at most 3 requests inside a 60-second window.
    for i in range(20):
        assert analyzer.analyze(SRC_IP, "example.com", T0 + i * 30) == []


def test_beaconing_window_resets_after_a_quiet_period():
    analyzer = DomainAnalyzer(beacon_threshold=5, beacon_window_seconds=60)

    for i in range(3):
        assert analyzer.analyze(SRC_IP, "example.com", T0 + i) == []
    # After two minutes of silence, a new burst starts counting from zero.
    for i in range(3):
        assert analyzer.analyze(SRC_IP, "example.com", T0 + 120 + i) == []


def test_beaconing_is_tracked_per_source_and_domain():
    analyzer = DomainAnalyzer(beacon_threshold=4, beacon_window_seconds=60)

    for i in range(3):
        analyzer.analyze(SRC_IP, "example.com", T0 + i)
        analyzer.analyze(OTHER_IP, "example.com", T0 + i)
        analyzer.analyze(SRC_IP, "example.org", T0 + i)

    # Each (src_ip, domain) pair has 3 hits, below the threshold of 4.
    assert analyzer.analyze(OTHER_IP, "example.org", T0 + 3) == []
    # The fourth hit for one pair crosses the threshold.
    assert reasons(analyzer.analyze(SRC_IP, "example.com", T0 + 3)) == {Reason.BEACONING}


def test_idle_beacon_windows_are_purged_to_bound_memory():
    analyzer = DomainAnalyzer(beacon_threshold=5, beacon_window_seconds=60)

    for i in range(50):
        analyzer.analyze(SRC_IP, f"host{i}.example.com", T0 + i * 0.1)
    assert len(analyzer._beacon_hits) == 50  # White-box check of internal state.

    # A query after the window has passed triggers the cleanup.
    analyzer.analyze(SRC_IP, "later.example.com", T0 + 600)
    assert len(analyzer._beacon_hits) == 1


# --- DomainAnalyzer: cooldown ---------------------------------------------


def test_cooldown_suppresses_duplicate_findings():
    analyzer = DomainAnalyzer(blacklist={"evil.example.com"}, cooldown_seconds=300)

    assert len(analyzer.analyze(SRC_IP, "evil.example.com", T0)) == 1
    assert analyzer.analyze(SRC_IP, "evil.example.com", T0 + 10) == []
    assert analyzer.analyze(SRC_IP, "evil.example.com", T0 + 299) == []
    # After the cooldown elapses, the same finding goes out a second time.
    assert len(analyzer.analyze(SRC_IP, "evil.example.com", T0 + 301)) == 1


def test_cooldown_is_scoped_to_source_ip_and_reason():
    analyzer = DomainAnalyzer(blacklist={"evil.tk"}, cooldown_seconds=300)

    first = analyzer.analyze(SRC_IP, "evil.tk", T0)
    assert reasons(first) == {Reason.BLACKLISTED, Reason.SUSPICIOUS_TLD}

    # A different source forms a different (src_ip, domain, reason) key.
    other = analyzer.analyze(OTHER_IP, "evil.tk", T0 + 1)
    assert reasons(other) == {Reason.BLACKLISTED, Reason.SUSPICIOUS_TLD}
    # The first source stays silenced.
    assert analyzer.analyze(SRC_IP, "evil.tk", T0 + 2) == []
