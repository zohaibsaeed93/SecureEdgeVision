"""Authenticated, metadata-only detection ingestion for the aggregator.

This module owns the application-layer ordering for one accepted event. It is
deliberately independent from FastAPI and performs no work at import time.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import NoReturn
from uuid import uuid4

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from secureedge.contracts import SignedDetectionEnvelope
from secureedge.crypto import KeyMaterialError, load_public_key, verify_detection_envelope
from secureedge.persistence import (
    DetectionEventRecord,
    NodeRecord,
    PersistenceError,
    SecurityAlert,
    SecurityAlertRecord,
    SessionFactory,
)
from secureedge.security import (
    EventSecurityConfigurationError,
    EventSecurityReason,
    EventSecurityRejection,
    ReplayFreshnessPolicy,
)


class IngestionReason(StrEnum):
    """Stable, non-sensitive outcomes exposed to the HTTP adapter."""

    UNKNOWN_NODE = "unknown_node"
    INVALID_SIGNATURE = "invalid_signature"
    STALE_TIMESTAMP = "stale_timestamp"
    FUTURE_TIMESTAMP = "future_timestamp"
    REPLAYED_EVENT_ID = "replayed_event_id"
    REPLAYED_NONCE = "replayed_nonce"
    SERVICE_UNAVAILABLE = "service_unavailable"


_SECURITY_REASON_MAP = {
    EventSecurityReason.STALE_TIMESTAMP: IngestionReason.STALE_TIMESTAMP,
    EventSecurityReason.FUTURE_TIMESTAMP: IngestionReason.FUTURE_TIMESTAMP,
    EventSecurityReason.REPLAYED_EVENT_ID: IngestionReason.REPLAYED_EVENT_ID,
    EventSecurityReason.REPLAYED_NONCE: IngestionReason.REPLAYED_NONCE,
}

_ALERT_CATEGORY_BY_REASON = {
    IngestionReason.UNKNOWN_NODE: "identity",
    IngestionReason.INVALID_SIGNATURE: "integrity",
    IngestionReason.STALE_TIMESTAMP: "freshness",
    IngestionReason.FUTURE_TIMESTAMP: "freshness",
    IngestionReason.REPLAYED_EVENT_ID: "replay",
    IngestionReason.REPLAYED_NONCE: "replay",
}

AlertClock = Callable[[], datetime]
AlertIdFactory = Callable[[], str]


def _system_utc_now() -> datetime:
    return datetime.now(UTC)


def _new_alert_id() -> str:
    return uuid4().hex


class IngestionRejection(RuntimeError):
    """An authenticated-ingestion rejection safe to map to a client status."""

    def __init__(self, reason: IngestionReason) -> None:
        self.reason = reason
        super().__init__(reason.value)


class IngestionServiceError(RuntimeError):
    """A sanitized dependency or configuration failure."""

    reason = IngestionReason.SERVICE_UNAVAILABLE

    def __init__(self) -> None:
        super().__init__(self.reason.value)


@dataclass(frozen=True, slots=True)
class IngestionAcceptance:
    """Non-payload metadata proving that the durable write completed."""

    record_id: int


class DetectionEventIngestor:
    """Verify, replay-check, and durably store one signed detection event.

    The caller owns both dependencies. In particular, one policy instance must
    be retained for the lifetime of one aggregator process while sessions remain
    request scoped.
    """

    def __init__(
        self,
        session_factory: SessionFactory,
        replay_policy: ReplayFreshnessPolicy,
        *,
        alert_clock: AlertClock | None = None,
        alert_id_factory: AlertIdFactory | None = None,
    ) -> None:
        if not callable(session_factory):
            raise TypeError("session factory must be callable")
        if not isinstance(replay_policy, ReplayFreshnessPolicy):
            raise TypeError("replay policy must be a ReplayFreshnessPolicy")
        if alert_clock is not None and not callable(alert_clock):
            raise TypeError("alert clock must be callable")
        if alert_id_factory is not None and not callable(alert_id_factory):
            raise TypeError("alert ID factory must be callable")
        self._session_factory = session_factory
        self._replay_policy = replay_policy
        self._alert_clock = alert_clock or _system_utc_now
        self._alert_id_factory = alert_id_factory or _new_alert_id

    def ingest(self, envelope: SignedDetectionEnvelope) -> IngestionAcceptance:
        """Accept a strict envelope or raise one sanitized typed failure.

        Signature verification intentionally precedes the process-local replay
        reservation. Once reserved, identifiers remain reserved if the later
        database outcome is uncertain; that fail-closed choice trades temporary
        availability for replay safety until the configured TTL expires.
        """

        if not isinstance(envelope, SignedDetectionEnvelope):
            raise TypeError("envelope must be a SignedDetectionEnvelope")

        session = self._session_factory()
        try:
            node = session.get(NodeRecord, envelope.body.node_id)
            if node is None:
                self._record_rejection(session, envelope, IngestionReason.UNKNOWN_NODE)

            try:
                registration = node.to_registration()
                public_key = load_public_key(registration.public_key_b64)
                signature_is_valid = verify_detection_envelope(envelope, public_key)
            except (KeyMaterialError, PersistenceError, TypeError, ValueError) as exc:
                raise IngestionServiceError() from exc

            if not signature_is_valid:
                self._record_rejection(session, envelope, IngestionReason.INVALID_SIGNATURE)

            try:
                decision = self._replay_policy.accept_verified_event(envelope.body)
            except EventSecurityRejection as exc:
                reason = _SECURITY_REASON_MAP.get(exc.reason)
                if reason is None:
                    raise IngestionServiceError() from exc
                self._record_rejection(session, envelope, reason, cause=exc)
            except EventSecurityConfigurationError as exc:
                raise IngestionServiceError() from exc

            record = DetectionEventRecord.from_event(
                envelope.body,
                accepted_at_utc=decision.accepted_at_utc,
            )
            session.add(record)
            session.commit()
            if record.record_id is None:
                raise IngestionServiceError()
            return IngestionAcceptance(record_id=record.record_id)
        except IngestionRejection:
            session.rollback()
            raise
        except IngestionServiceError:
            session.rollback()
            raise
        except (PersistenceError, SQLAlchemyError, TypeError, ValueError) as exc:
            session.rollback()
            raise IngestionServiceError() from exc
        except Exception as exc:
            session.rollback()
            raise IngestionServiceError() from exc
        finally:
            session.close()

    def _record_rejection(
        self,
        session: Session,
        envelope: SignedDetectionEnvelope,
        reason: IngestionReason,
        *,
        cause: Exception | None = None,
    ) -> NoReturn:
        """Commit one sanitized alert before exposing a security rejection."""

        category = _ALERT_CATEGORY_BY_REASON.get(reason)
        if category is None:
            raise IngestionServiceError() from cause
        alert = SecurityAlert(
            alert_id=self._alert_id_factory(),
            occurred_at_utc=self._alert_clock(),
            category=category,
            reason=reason.value,
            node_id=envelope.body.node_id,
            event_id=envelope.body.event_id,
            nonce=envelope.body.nonce,
        )
        try:
            session.add(SecurityAlertRecord.from_alert(alert))
            session.commit()
        except Exception as exc:
            raise IngestionServiceError() from exc
        rejection = IngestionRejection(reason)
        if cause is None:
            raise rejection
        raise rejection from cause


__all__ = [
    "AlertClock",
    "AlertIdFactory",
    "DetectionEventIngestor",
    "IngestionAcceptance",
    "IngestionReason",
    "IngestionRejection",
    "IngestionServiceError",
]
