from __future__ import annotations

import importlib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from threading import Barrier
from typing import Any, cast

import pytest
from secureedge.config import SecuritySettings
from secureedge.contracts import DetectionEvent
from secureedge.security import (
    EventSecurityConfigurationError,
    EventSecurityDecision,
    EventSecurityReason,
    EventSecurityRejection,
    ReplayFreshnessPolicy,
)

NOW = datetime(2026, 9, 14, 1, 0, tzinfo=UTC)


def _settings(*, skew: int = 30, ttl: int = 300) -> SecuritySettings:
    return SecuritySettings(
        max_clock_skew_seconds=skew,
        nonce_ttl_seconds=ttl,
        max_request_bytes=262_144,
    )


def _event(
    *,
    timestamp: datetime = NOW,
    event_id: str = "event-1",
    node_id: str = "edge-1",
    nonce: str = "nonce-1",
) -> DetectionEvent:
    data: dict[str, Any] = {
        "schema_version": "1.0",
        "event_id": event_id,
        "node_id": node_id,
        "camera_id": "camera-1",
        "timestamp_utc": timestamp,
        "nonce": nonce,
        "frame_seq": 1,
        "job_id": None,
        "mode": "privacy",
        "model": {"name": "yolo26n.pt", "sha256": "a" * 64},
        "frame": {"width": 640, "height": 480},
        "detections": [],
        "performance": {"decode_ms": 1.0, "inference_ms": 2.0, "postprocess_ms": 0.5},
    }
    return DetectionEvent.model_validate(data)


@dataclass
class MutableClock:
    current: object

    def __call__(self) -> datetime:
        return cast(datetime, self.current)


@pytest.mark.parametrize("offset_seconds", [-30, 0, 30])
def test_accepts_inclusive_timestamp_boundaries(offset_seconds: int) -> None:
    policy = ReplayFreshnessPolicy(_settings(), clock=lambda: NOW)
    event = _event(timestamp=NOW + timedelta(seconds=offset_seconds))

    decision = policy.accept_verified_event(event)

    assert isinstance(decision, EventSecurityDecision)
    assert decision.accepted_at_utc == NOW
    assert decision.replay_protected_until_utc >= NOW + timedelta(seconds=300)


@pytest.mark.parametrize(
    ("timestamp", "reason"),
    [
        (NOW - timedelta(seconds=30, microseconds=1), EventSecurityReason.STALE_TIMESTAMP),
        (NOW + timedelta(seconds=30, microseconds=1), EventSecurityReason.FUTURE_TIMESTAMP),
    ],
)
def test_rejects_timestamps_outside_window_with_stable_reasons(
    timestamp: datetime,
    reason: EventSecurityReason,
) -> None:
    policy = ReplayFreshnessPolicy(_settings(), clock=lambda: NOW)
    event = _event(timestamp=timestamp)

    with pytest.raises(EventSecurityRejection) as exc_info:
        policy.accept_verified_event(event)

    assert exc_info.value.reason is reason
    assert event.event_id not in str(exc_info.value)
    assert event.nonce not in str(exc_info.value)


@pytest.mark.parametrize(
    "timestamp",
    [NOW - timedelta(minutes=1), NOW + timedelta(minutes=1)],
)
def test_invalid_time_does_not_reserve_identifiers(timestamp: datetime) -> None:
    clock = MutableClock(NOW)
    policy = ReplayFreshnessPolicy(_settings(), clock=clock)

    with pytest.raises(EventSecurityRejection):
        policy.accept_verified_event(_event(timestamp=timestamp))

    policy.accept_verified_event(_event(timestamp=NOW))


def test_rejects_node_scoped_event_and_nonce_reuse_without_partial_reservation() -> None:
    policy = ReplayFreshnessPolicy(_settings(), clock=lambda: NOW)
    policy.accept_verified_event(_event())

    with pytest.raises(EventSecurityRejection) as exact_replay:
        policy.accept_verified_event(_event())
    assert exact_replay.value.reason is EventSecurityReason.REPLAYED_EVENT_ID

    with pytest.raises(EventSecurityRejection) as event_replay:
        policy.accept_verified_event(_event(nonce="unused-nonce"))
    assert event_replay.value.reason is EventSecurityReason.REPLAYED_EVENT_ID
    policy.accept_verified_event(_event(event_id="event-2", nonce="unused-nonce"))

    with pytest.raises(EventSecurityRejection) as nonce_replay:
        policy.accept_verified_event(_event(event_id="unused-event"))
    assert nonce_replay.value.reason is EventSecurityReason.REPLAYED_NONCE
    policy.accept_verified_event(_event(event_id="unused-event", nonce="nonce-3"))


def test_same_identifiers_are_isolated_between_nodes() -> None:
    policy = ReplayFreshnessPolicy(_settings(), clock=lambda: NOW)

    policy.accept_verified_event(_event(node_id="edge-1"))
    policy.accept_verified_event(_event(node_id="edge-2"))


def test_expired_identifiers_can_be_reused_after_the_inclusive_horizon() -> None:
    clock = MutableClock(NOW)
    policy = ReplayFreshnessPolicy(_settings(skew=1, ttl=5), clock=clock)
    policy.accept_verified_event(_event())

    clock.current = NOW + timedelta(seconds=5)
    with pytest.raises(EventSecurityRejection) as at_boundary:
        policy.accept_verified_event(_event(timestamp=cast(datetime, clock.current)))
    assert at_boundary.value.reason is EventSecurityReason.REPLAYED_EVENT_ID

    clock.current = NOW + timedelta(seconds=5, microseconds=1)
    policy.accept_verified_event(_event(timestamp=cast(datetime, clock.current)))


def test_pruning_removes_only_expired_identifiers() -> None:
    clock = MutableClock(NOW)
    policy = ReplayFreshnessPolicy(_settings(skew=60, ttl=1), clock=clock)
    policy.accept_verified_event(_event(event_id="short-event", nonce="short-nonce"))
    policy.accept_verified_event(
        _event(
            timestamp=NOW + timedelta(seconds=60),
            event_id="long-event",
            nonce="long-nonce",
        )
    )

    clock.current = NOW + timedelta(seconds=60, microseconds=1)
    current = cast(datetime, clock.current)
    policy.accept_verified_event(
        _event(timestamp=current, event_id="pruning-event", nonce="pruning-nonce")
    )

    with pytest.raises(EventSecurityRejection) as unexpired:
        policy.accept_verified_event(
            _event(timestamp=current, event_id="long-event", nonce="long-nonce")
        )
    assert unexpired.value.reason is EventSecurityReason.REPLAYED_EVENT_ID

    policy.accept_verified_event(
        _event(timestamp=current, event_id="short-event", nonce="short-nonce")
    )


@pytest.mark.parametrize(
    ("skew", "ttl"),
    [
        (60, 1),
        (60, 120),
        (60, 300),
        (3_600, 1),
        (1, 86_400),
    ],
)
def test_ttl_cannot_create_a_gap_across_allowed_setting_relationships(
    skew: int,
    ttl: int,
) -> None:
    clock = MutableClock(NOW)
    policy = ReplayFreshnessPolicy(_settings(skew=skew, ttl=ttl), clock=clock)
    future_event = _event(timestamp=NOW + timedelta(seconds=skew))
    expected_horizon = NOW + timedelta(seconds=max(ttl, 2 * skew))

    decision = policy.accept_verified_event(future_event)
    assert decision.replay_protected_until_utc == expected_horizon

    clock.current = expected_horizon
    with pytest.raises(EventSecurityRejection) as at_freshness_boundary:
        policy.accept_verified_event(_event(timestamp=expected_horizon))
    assert at_freshness_boundary.value.reason is EventSecurityReason.REPLAYED_EVENT_ID

    clock.current = expected_horizon + timedelta(microseconds=1)
    policy.accept_verified_event(_event(timestamp=cast(datetime, clock.current)))


def test_replay_state_is_owned_by_each_policy_instance() -> None:
    first = ReplayFreshnessPolicy(_settings(), clock=lambda: NOW)
    second = ReplayFreshnessPolicy(_settings(), clock=lambda: NOW)

    first.accept_verified_event(_event())
    second.accept_verified_event(_event())


@pytest.mark.parametrize(
    "invalid_now",
    [
        "not-a-datetime",
        datetime(2026, 9, 14, 1, 0),
        datetime(2026, 9, 14, 6, 0, tzinfo=timezone(timedelta(hours=5))),
    ],
)
def test_invalid_clock_fails_closed_without_reserving_event(invalid_now: object) -> None:
    clock = MutableClock(invalid_now)
    policy = ReplayFreshnessPolicy(_settings(), clock=clock)

    with pytest.raises(EventSecurityConfigurationError, match="clock"):
        policy.accept_verified_event(_event())

    clock.current = NOW
    policy.accept_verified_event(_event())


def test_clock_failure_and_invalid_event_do_not_leak_values_or_mutate_state() -> None:
    private_detail = "camera-secret-value"

    def failed_clock() -> datetime:
        raise RuntimeError(private_detail)

    failed_policy = ReplayFreshnessPolicy(_settings(), clock=failed_clock)
    with pytest.raises(EventSecurityConfigurationError) as clock_error:
        failed_policy.accept_verified_event(_event())
    assert private_detail not in str(clock_error.value)
    assert clock_error.value.__cause__ is None

    policy = ReplayFreshnessPolicy(_settings(), clock=lambda: NOW)
    invalid_event = _event().model_copy(update={"timestamp_utc": datetime(2026, 9, 14, 1, 0)})
    with pytest.raises(EventSecurityConfigurationError, match="validated DetectionEvent"):
        policy.accept_verified_event(invalid_event)
    policy.accept_verified_event(_event())


def test_bypass_constructed_malformed_event_fails_without_reservation() -> None:
    policy = ReplayFreshnessPolicy(_settings(), clock=lambda: NOW)
    malformed = _event().model_copy(update={"node_id": ["not", "an", "identifier"]})

    with pytest.raises(EventSecurityConfigurationError, match="validated DetectionEvent"):
        policy.accept_verified_event(malformed)

    policy.accept_verified_event(_event())


def test_unsupported_datetime_arithmetic_fails_without_reservation() -> None:
    clock = MutableClock(datetime.max.replace(tzinfo=UTC))
    policy = ReplayFreshnessPolicy(_settings(), clock=clock)

    with pytest.raises(EventSecurityConfigurationError, match="supported range"):
        policy.accept_verified_event(_event(timestamp=datetime.max.replace(tzinfo=UTC)))

    clock.current = NOW
    policy.accept_verified_event(_event())


def test_constructor_revalidates_settings_and_does_not_read_clock() -> None:
    calls = 0

    def clock() -> datetime:
        nonlocal calls
        calls += 1
        return NOW

    policy = ReplayFreshnessPolicy(_settings(), clock=clock)
    assert calls == 0
    policy.accept_verified_event(_event())
    assert calls == 1

    invalid = SecuritySettings.model_construct(
        max_clock_skew_seconds=0,
        nonce_ttl_seconds=300,
        max_request_bytes=262_144,
    )
    with pytest.raises(EventSecurityConfigurationError, match="settings"):
        ReplayFreshnessPolicy(invalid)


def test_concurrent_duplicate_check_and_record_is_atomic() -> None:
    worker_count = 16
    barrier = Barrier(worker_count)
    policy = ReplayFreshnessPolicy(_settings(), clock=lambda: NOW)
    event = _event()

    def attempt() -> EventSecurityReason | None:
        barrier.wait()
        try:
            policy.accept_verified_event(event)
        except EventSecurityRejection as exc:
            return exc.reason
        return None

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        results = list(executor.map(lambda _: attempt(), range(worker_count)))

    assert results.count(None) == 1
    assert results.count(EventSecurityReason.REPLAYED_EVENT_ID) == worker_count - 1


def test_security_import_has_no_io_service_or_thread_side_effects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import os
    import pathlib
    import socket
    import sqlite3
    import threading

    def fail(*args: object, **kwargs: object) -> None:
        raise AssertionError("security import performed an external side effect")

    monkeypatch.setattr(pathlib.Path, "read_text", fail)
    monkeypatch.setattr(pathlib.Path, "write_text", fail)
    monkeypatch.setattr(os, "open", fail)
    monkeypatch.setattr(os, "getenv", fail)
    monkeypatch.setattr(socket, "socket", fail)
    monkeypatch.setattr(sqlite3, "connect", fail)
    monkeypatch.setattr(threading.Thread, "start", fail)

    module = importlib.import_module("secureedge.security")
    importlib.reload(module)
