"""Reusable, metadata-only monitoring services for the Milestone 1 aggregator.

This module deliberately contains no FastAPI or process-startup behavior. Callers
provide validated settings, a session factory, and (where relevant) a trusted UTC
clock. Heartbeats are advisory local-demo liveness, not authenticated security
claims.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, ValidationError
from sqlalchemy import func, or_, select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from secureedge.config import SecuritySettings
from secureedge.contracts import DetectionEvent, NodeHeartbeat, SafeIdentifier, UtcTimestamp
from secureedge.persistence import (
    DetectionEventRecord,
    NodeRecord,
    PersistenceError,
    SecurityAlertRecord,
    SessionFactory,
)

DEFAULT_MONITORING_QUERY_LIMIT = 50
MAX_MONITORING_QUERY_LIMIT = 100

HeartbeatClock = Callable[[], datetime]


class _MonitoringModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class AggregatorHealth(_MonitoringModel):
    """Safe readiness and row-count summary for the supervisor view."""

    status: Literal["healthy"] = "healthy"
    database: Literal["ready"] = "ready"
    registered_nodes: int
    accepted_events: int
    security_alerts: int


class NodeHealth(_MonitoringModel):
    """Public-key-free node registration and advisory heartbeat state."""

    node_id: SafeIdentifier
    registered_at_utc: UtcTimestamp
    last_seen_at_utc: UtcTimestamp | None
    health_status: Literal["healthy", "degraded", "unhealthy"] | None


class RecentDetectionEvent(_MonitoringModel):
    """One accepted metadata-only event plus its trusted acceptance time."""

    accepted_at_utc: UtcTimestamp
    event: DetectionEvent


class HeartbeatReason(StrEnum):
    """Stable, non-sensitive outcomes exposed by the heartbeat adapter."""

    UNKNOWN_NODE = "unknown_node"
    STALE_TIMESTAMP = "stale_timestamp"
    FUTURE_TIMESTAMP = "future_timestamp"
    OUT_OF_ORDER_HEARTBEAT = "out_of_order_heartbeat"
    SERVICE_UNAVAILABLE = "service_unavailable"


class HeartbeatRejection(RuntimeError):
    """A policy rejection safe to map to a client status."""

    def __init__(self, reason: HeartbeatReason) -> None:
        self.reason = reason
        super().__init__(reason.value)


class MonitoringServiceError(RuntimeError):
    """A sanitized monitoring dependency or configuration failure."""

    reason = HeartbeatReason.SERVICE_UNAVAILABLE

    def __init__(self) -> None:
        super().__init__(self.reason.value)


def _system_utc_now() -> datetime:
    return datetime.now(UTC)


def _validated_settings(settings: SecuritySettings) -> SecuritySettings:
    settings_type = type(settings)
    if not (
        isinstance(settings, SecuritySettings)
        or (
            settings_type.__module__ == SecuritySettings.__module__
            and settings_type.__qualname__ == SecuritySettings.__qualname__
        )
    ):
        raise TypeError("security settings must be validated")
    try:
        return SecuritySettings.model_validate(
            settings.model_dump(mode="python", warnings="error"),
            strict=True,
        )
    except (AttributeError, TypeError, ValidationError, ValueError):
        raise TypeError("security settings must be validated") from None


def _validated_heartbeat(heartbeat: NodeHeartbeat) -> NodeHeartbeat:
    if not isinstance(heartbeat, NodeHeartbeat):
        raise TypeError("heartbeat must be a NodeHeartbeat")
    try:
        return NodeHeartbeat.model_validate(
            heartbeat.model_dump(mode="python", warnings="error"),
            strict=True,
        )
    except (AttributeError, TypeError, ValidationError, ValueError):
        raise TypeError("heartbeat must be a NodeHeartbeat") from None


def _require_utc(value: object) -> datetime:
    if not isinstance(value, datetime):
        raise MonitoringServiceError()
    try:
        if (
            value.tzinfo is None
            or value.utcoffset() is None
            or value.utcoffset() != timedelta(0)
        ):
            raise MonitoringServiceError()
        return value.astimezone(UTC)
    except MonitoringServiceError:
        raise
    except Exception:
        raise MonitoringServiceError() from None


def _rollback(session: Session) -> None:
    try:
        session.rollback()
    except Exception as exc:
        raise MonitoringServiceError() from exc


def _close(session: Session) -> None:
    try:
        session.close()
    except Exception as exc:
        raise MonitoringServiceError() from exc


class HeartbeatService:
    """Transactionally apply an unsigned advisory heartbeat for a known node."""

    def __init__(
        self,
        session_factory: SessionFactory,
        settings: SecuritySettings,
        *,
        clock: HeartbeatClock | None = None,
    ) -> None:
        if not callable(session_factory):
            raise TypeError("session factory must be callable")
        if clock is not None and not callable(clock):
            raise TypeError("heartbeat clock must be callable")
        self._session_factory = session_factory
        self._settings = _validated_settings(settings)
        self._clock = clock or _system_utc_now

    def record(self, heartbeat: NodeHeartbeat) -> None:
        """Commit one fresh heartbeat without permitting state regression."""

        validated = _validated_heartbeat(heartbeat)
        try:
            session = self._session_factory()
        except Exception as exc:
            raise MonitoringServiceError() from exc

        try:
            if session.get(NodeRecord, validated.node_id) is None:
                raise HeartbeatRejection(HeartbeatReason.UNKNOWN_NODE)

            now = _require_utc(self._clock())
            timestamp = _require_utc(validated.timestamp_utc)
            skew = timedelta(seconds=self._settings.max_clock_skew_seconds)
            earliest = now - skew
            latest = now + skew
            if timestamp < earliest:
                raise HeartbeatRejection(HeartbeatReason.STALE_TIMESTAMP)
            if timestamp > latest:
                raise HeartbeatRejection(HeartbeatReason.FUTURE_TIMESTAMP)

            result = session.execute(
                update(NodeRecord)
                .where(
                    NodeRecord.node_id == validated.node_id,
                    or_(
                        NodeRecord.last_seen_at_utc.is_(None),
                        NodeRecord.last_seen_at_utc < timestamp,
                    ),
                )
                .values(
                    last_seen_at_utc=timestamp,
                    health_status=validated.status,
                )
                .execution_options(synchronize_session=False)
            )
            if getattr(result, "rowcount", None) != 1:
                raise HeartbeatRejection(HeartbeatReason.OUT_OF_ORDER_HEARTBEAT)
            session.commit()
        except HeartbeatRejection:
            _rollback(session)
            raise
        except MonitoringServiceError:
            _rollback(session)
            raise
        except (PersistenceError, SQLAlchemyError, TypeError, ValueError) as exc:
            _rollback(session)
            raise MonitoringServiceError() from exc
        except Exception as exc:
            _rollback(session)
            raise MonitoringServiceError() from exc
        finally:
            _close(session)


def _validate_limit(limit: int) -> None:
    if (
        isinstance(limit, bool)
        or not isinstance(limit, int)
        or not 1 <= limit <= MAX_MONITORING_QUERY_LIMIT
    ):
        raise MonitoringServiceError()


def _open_session(factory: SessionFactory) -> Session:
    if not callable(factory):
        raise MonitoringServiceError()
    try:
        return factory()
    except Exception as exc:
        raise MonitoringServiceError() from exc


def get_aggregator_health(factory: SessionFactory) -> AggregatorHealth:
    """Confirm database readiness and return only safe aggregate counts."""

    session = _open_session(factory)
    try:
        return AggregatorHealth(
            registered_nodes=session.scalar(select(func.count()).select_from(NodeRecord)) or 0,
            accepted_events=(
                session.scalar(select(func.count()).select_from(DetectionEventRecord)) or 0
            ),
            security_alerts=(
                session.scalar(select(func.count()).select_from(SecurityAlertRecord)) or 0
            ),
        )
    except (PersistenceError, SQLAlchemyError, TypeError, ValidationError, ValueError) as exc:
        _rollback(session)
        raise MonitoringServiceError() from exc
    except Exception as exc:
        _rollback(session)
        raise MonitoringServiceError() from exc
    finally:
        _close(session)


def list_node_health(
    factory: SessionFactory,
    *,
    limit: int = DEFAULT_MONITORING_QUERY_LIMIT,
) -> list[NodeHealth]:
    """Return a bounded deterministic view without public or private key data."""

    _validate_limit(limit)
    session = _open_session(factory)
    try:
        records = session.scalars(
            select(NodeRecord).order_by(NodeRecord.node_id.asc()).limit(limit)
        ).all()
        result: list[NodeHealth] = []
        for record in records:
            registration = record.to_registration()
            heartbeat = record.to_heartbeat()
            result.append(
                NodeHealth(
                    node_id=registration.node_id,
                    registered_at_utc=record.registered_at_utc,
                    last_seen_at_utc=(
                        heartbeat.timestamp_utc if heartbeat is not None else None
                    ),
                    health_status=heartbeat.status if heartbeat is not None else None,
                )
            )
        return result
    except (PersistenceError, SQLAlchemyError, TypeError, ValidationError, ValueError) as exc:
        _rollback(session)
        raise MonitoringServiceError() from exc
    except Exception as exc:
        _rollback(session)
        raise MonitoringServiceError() from exc
    finally:
        _close(session)


def list_recent_events(
    factory: SessionFactory,
    *,
    limit: int = DEFAULT_MONITORING_QUERY_LIMIT,
) -> list[RecentDetectionEvent]:
    """Return accepted metadata newest-first with an internal stable tie-breaker."""

    _validate_limit(limit)
    session = _open_session(factory)
    try:
        records = session.scalars(
            select(DetectionEventRecord)
            .order_by(
                DetectionEventRecord.accepted_at_utc.desc(),
                DetectionEventRecord.record_id.desc(),
            )
            .limit(limit)
        ).all()
        return [
            RecentDetectionEvent(
                accepted_at_utc=record.accepted_at_utc,
                event=record.to_event(),
            )
            for record in records
        ]
    except (PersistenceError, SQLAlchemyError, TypeError, ValidationError, ValueError) as exc:
        _rollback(session)
        raise MonitoringServiceError() from exc
    except Exception as exc:
        _rollback(session)
        raise MonitoringServiceError() from exc
    finally:
        _close(session)


__all__ = [
    "AggregatorHealth",
    "DEFAULT_MONITORING_QUERY_LIMIT",
    "HeartbeatClock",
    "HeartbeatReason",
    "HeartbeatRejection",
    "HeartbeatService",
    "MAX_MONITORING_QUERY_LIMIT",
    "MonitoringServiceError",
    "NodeHealth",
    "RecentDetectionEvent",
    "get_aggregator_health",
    "list_node_health",
    "list_recent_events",
]
