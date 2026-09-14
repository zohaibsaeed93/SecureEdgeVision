"""Process-local replay and timestamp policy for authenticated detection events."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from threading import Lock

from secureedge.config import SecuritySettings
from secureedge.contracts import DetectionEvent

Clock = Callable[[], datetime]
_ReplayKey = tuple[str, str, str]


class EventSecurityReason(StrEnum):
    """Stable reasons for rejecting an otherwise authenticated event."""

    STALE_TIMESTAMP = "stale_timestamp"
    FUTURE_TIMESTAMP = "future_timestamp"
    REPLAYED_EVENT_ID = "replayed_event_id"
    REPLAYED_NONCE = "replayed_nonce"


def _rejection_message(reason: EventSecurityReason) -> str:
    if reason is EventSecurityReason.STALE_TIMESTAMP:
        return "authenticated event timestamp is stale"
    if reason is EventSecurityReason.FUTURE_TIMESTAMP:
        return "authenticated event timestamp is too far in the future"
    if reason is EventSecurityReason.REPLAYED_EVENT_ID:
        return "authenticated event ID has already been accepted for this node"
    return "authenticated event nonce has already been accepted for this node"


class EventSecurityRejection(ValueError):
    """Fail-closed policy rejection with a stable, non-sensitive reason."""

    def __init__(self, reason: EventSecurityReason) -> None:
        self.reason = reason
        super().__init__(_rejection_message(reason))


class EventSecurityConfigurationError(ValueError):
    """Raised when policy settings, inputs, or the injected clock are invalid."""


@dataclass(frozen=True, slots=True)
class EventSecurityDecision:
    """Metadata describing an accepted event's process-local replay reservation."""

    accepted_at_utc: datetime
    replay_protected_until_utc: datetime


def _system_utc_now() -> datetime:
    return datetime.now(UTC)


def _validated_settings(settings: SecuritySettings) -> SecuritySettings:
    if not isinstance(settings, SecuritySettings):
        raise EventSecurityConfigurationError("security settings must be validated")

    try:
        return SecuritySettings.model_validate(
            {
                "max_clock_skew_seconds": settings.max_clock_skew_seconds,
                "nonce_ttl_seconds": settings.nonce_ttl_seconds,
                "max_request_bytes": settings.max_request_bytes,
            },
            strict=True,
        )
    except Exception:
        raise EventSecurityConfigurationError("security settings must be valid") from None


def _require_utc_datetime(value: object, *, source: str) -> datetime:
    if not isinstance(value, datetime):
        raise EventSecurityConfigurationError(f"{source} must provide a UTC datetime")
    try:
        tzinfo = value.tzinfo
        offset = value.utcoffset()
        is_utc = tzinfo is not None and offset is not None and offset == timedelta(0)
        if is_utc:
            normalized = datetime(
                value.year,
                value.month,
                value.day,
                value.hour,
                value.minute,
                value.second,
                value.microsecond,
                tzinfo=UTC,
                fold=value.fold,
            )
    except Exception:
        raise EventSecurityConfigurationError(f"{source} must provide a UTC datetime") from None
    if not is_utc:
        raise EventSecurityConfigurationError(f"{source} must provide a UTC datetime")
    return normalized


def _validated_event(event: DetectionEvent) -> DetectionEvent:
    if not isinstance(event, DetectionEvent):
        raise EventSecurityConfigurationError("event must be a validated DetectionEvent")
    try:
        event_data = event.model_dump(mode="python", warnings="error")
        return DetectionEvent.model_validate(event_data, strict=True)
    except Exception:
        raise EventSecurityConfigurationError(
            "event must be a validated DetectionEvent"
        ) from None


class ReplayFreshnessPolicy:
    """Atomically enforce freshness and node-scoped replay protection.

    Callers must validate the wire contract and verify its Ed25519 signature before
    invoking :meth:`accept_verified_event`. Each instance owns its replay state;
    there is no shared module state or background cleanup thread.
    """

    def __init__(self, settings: SecuritySettings, *, clock: Clock | None = None) -> None:
        self._settings = _validated_settings(settings)
        if clock is not None and not callable(clock):
            raise EventSecurityConfigurationError("security clock must be callable")
        self._clock = clock or _system_utc_now
        self._seen: dict[_ReplayKey, datetime] = {}
        self._latest_accepted_at_utc: datetime | None = None
        self._lock = Lock()

    def accept_verified_event(self, event: DetectionEvent) -> EventSecurityDecision:
        """Accept one verified event or raise a deterministic policy rejection.

        Timestamp bounds are inclusive. Replay identifiers stay reserved through
        the later of their configured TTL and the last instant at which the signed
        timestamp could still pass the freshness window.
        """

        validated_event = _validated_event(event)

        try:
            current_time = self._clock()
        except Exception:
            raise EventSecurityConfigurationError("security clock failed") from None

        now = _require_utc_datetime(current_time, source="security clock")
        event_time = _require_utc_datetime(
            validated_event.timestamp_utc,
            source="event timestamp",
        )
        skew = timedelta(seconds=self._settings.max_clock_skew_seconds)

        try:
            earliest = now - skew
            latest = now + skew
        except OverflowError:
            raise EventSecurityConfigurationError(
                "security time value is outside the supported range"
            ) from None

        if event_time < earliest:
            raise EventSecurityRejection(EventSecurityReason.STALE_TIMESTAMP)
        if event_time > latest:
            raise EventSecurityRejection(EventSecurityReason.FUTURE_TIMESTAMP)

        try:
            ttl_expiry = now + timedelta(seconds=self._settings.nonce_ttl_seconds)
            freshness_expiry = event_time + skew
        except OverflowError:
            raise EventSecurityConfigurationError(
                "security time value is outside the supported range"
            ) from None
        replay_expiry = max(ttl_expiry, freshness_expiry)
        event_key: _ReplayKey = (
            "event_id",
            validated_event.node_id,
            validated_event.event_id,
        )
        nonce_key: _ReplayKey = (
            "nonce",
            validated_event.node_id,
            validated_event.nonce,
        )
        decision = EventSecurityDecision(
            accepted_at_utc=now,
            replay_protected_until_utc=replay_expiry,
        )

        with self._lock:
            if (
                self._latest_accepted_at_utc is not None
                and now < self._latest_accepted_at_utc
            ):
                raise EventSecurityConfigurationError("security clock moved backwards")

            retained = {
                key: expires_at
                for key, expires_at in self._seen.items()
                if expires_at >= now
            }
            if event_key in retained:
                raise EventSecurityRejection(EventSecurityReason.REPLAYED_EVENT_ID)
            if nonce_key in retained:
                raise EventSecurityRejection(EventSecurityReason.REPLAYED_NONCE)

            # Build the replacement mapping before publishing it so allocation
            # failures cannot leave only one identifier reserved.
            retained.update({event_key: replay_expiry, nonce_key: replay_expiry})
            self._seen = retained
            self._latest_accepted_at_utc = now

        return decision


__all__ = [
    "Clock",
    "EventSecurityConfigurationError",
    "EventSecurityDecision",
    "EventSecurityReason",
    "EventSecurityRejection",
    "ReplayFreshnessPolicy",
]
