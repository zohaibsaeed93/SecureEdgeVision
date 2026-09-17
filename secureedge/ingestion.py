"""Authenticated, metadata-only detection ingestion for the aggregator.

This module owns the application-layer ordering for one accepted event. It is
deliberately independent from FastAPI and performs no work at import time.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from sqlalchemy.exc import SQLAlchemyError

from secureedge.contracts import SignedDetectionEnvelope
from secureedge.crypto import KeyMaterialError, load_public_key, verify_detection_envelope
from secureedge.persistence import (
    DetectionEventRecord,
    NodeRecord,
    PersistenceError,
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
    ) -> None:
        if not callable(session_factory):
            raise TypeError("session factory must be callable")
        if not isinstance(replay_policy, ReplayFreshnessPolicy):
            raise TypeError("replay policy must be a ReplayFreshnessPolicy")
        self._session_factory = session_factory
        self._replay_policy = replay_policy

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
                raise IngestionRejection(IngestionReason.UNKNOWN_NODE)

            try:
                registration = node.to_registration()
                public_key = load_public_key(registration.public_key_b64)
                signature_is_valid = verify_detection_envelope(envelope, public_key)
            except (KeyMaterialError, PersistenceError, TypeError, ValueError) as exc:
                raise IngestionServiceError() from exc

            if not signature_is_valid:
                raise IngestionRejection(IngestionReason.INVALID_SIGNATURE)

            try:
                decision = self._replay_policy.accept_verified_event(envelope.body)
            except EventSecurityRejection as exc:
                reason = _SECURITY_REASON_MAP.get(exc.reason)
                if reason is None:
                    raise IngestionServiceError() from exc
                raise IngestionRejection(reason) from exc
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


__all__ = [
    "DetectionEventIngestor",
    "IngestionAcceptance",
    "IngestionReason",
    "IngestionRejection",
    "IngestionServiceError",
]
