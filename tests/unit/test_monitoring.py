from __future__ import annotations

import base64
import json
import pathlib
import subprocess
import sys
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from apps.aggregator.api import (
    EVENTS_PATH,
    HEALTH_PATH,
    NODE_HEARTBEAT_PATH,
    NODES_PATH,
    create_app,
)
from pydantic import ValidationError
from secureedge.config import SecuritySettings
from secureedge.contracts import DetectionEvent, NodeHeartbeat, NodeRegistration
from secureedge.monitoring import (
    AggregatorHealth,
    HeartbeatReason,
    HeartbeatRejection,
    HeartbeatService,
    MonitoringServiceError,
    NodeHealth,
    RecentDetectionEvent,
    get_aggregator_health,
    list_node_health,
    list_recent_events,
)
from secureedge.persistence import (
    DetectionEventRecord,
    NodeRecord,
    SecurityAlert,
    SecurityAlertRecord,
    create_session_factory,
    create_sqlite_engine,
    initialize_database,
    seed_node_registry,
    session_scope,
)
from secureedge.security import ReplayFreshnessPolicy
from sqlalchemy import Engine, func, select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

NOW = datetime(2026, 9, 18, 2, 0, tzinfo=UTC)


@pytest.fixture
def settings() -> SecuritySettings:
    return SecuritySettings(
        max_clock_skew_seconds=30,
        nonce_ttl_seconds=300,
        max_request_bytes=1024,
    )


@pytest.fixture
def engine(tmp_path: pathlib.Path) -> Iterator[Engine]:
    value = create_sqlite_engine(f"sqlite:///{tmp_path / 'monitoring.sqlite3'}")
    initialize_database(value)
    yield value
    value.dispose()


@pytest.fixture
def factory(engine: Engine) -> sessionmaker[Session]:
    return create_session_factory(engine)


def _registration(node_id: str = "edge-1", fill: bytes = b"a") -> NodeRegistration:
    return NodeRegistration(
        node_id=node_id,
        public_key_b64=base64.b64encode(fill * 32).decode("ascii"),
    )


def _event(
    *,
    event_id: str = "event-1",
    nonce: str = "nonce-1",
    timestamp: datetime = NOW,
) -> DetectionEvent:
    return DetectionEvent.model_validate(
        {
            "schema_version": "1.0",
            "event_id": event_id,
            "node_id": "edge-1",
            "camera_id": "cam-1",
            "timestamp_utc": timestamp,
            "nonce": nonce,
            "frame_seq": 7,
            "job_id": None,
            "mode": "privacy",
            "model": {"name": "yolo26n.pt", "sha256": "a" * 64},
            "frame": {"width": 1280, "height": 720},
            "detections": [
                {
                    "class_id": 0,
                    "class_name": "person",
                    "confidence": 0.91,
                    "bbox_xyxy_norm": [0.1, 0.2, 0.7, 0.9],
                    "track_id": None,
                }
            ],
            "performance": {
                "decode_ms": 1.0,
                "inference_ms": 9.5,
                "postprocess_ms": 0.5,
            },
        }
    )


def _heartbeat(
    *,
    node_id: str = "edge-1",
    timestamp: datetime = NOW,
    status: str = "healthy",
) -> NodeHeartbeat:
    return NodeHeartbeat.model_validate(
        {
            "node_id": node_id,
            "timestamp_utc": timestamp,
            "status": status,
        }
    )


def _app(
    settings: SecuritySettings,
    factory: Callable[[], Session],
    *,
    clock: Callable[[], datetime] = lambda: NOW,
) -> Any:
    def heartbeat_factory(value: Any, security: SecuritySettings) -> HeartbeatService:
        return HeartbeatService(value, security, clock=clock)

    return create_app(
        security_settings=settings,
        session_factory=factory,  # type: ignore[arg-type]
        replay_policy=ReplayFreshnessPolicy(settings, clock=clock),
        heartbeat_service_factory=heartbeat_factory,
    )


async def _post_heartbeat(
    app: Any,
    content: bytes,
    *,
    path: str = NODE_HEARTBEAT_PATH,
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    actual_headers = {"content-type": "application/json"}
    if headers:
        actual_headers.update(headers)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        return await client.post(path, content=content, headers=actual_headers)


async def _get(app: Any, path: str) -> httpx.Response:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        return await client.get(path)


def _alert_count(factory: Callable[[], Session]) -> int:
    with factory() as session:
        return session.scalar(select(func.count()).select_from(SecurityAlertRecord)) or 0


def test_heartbeat_service_commits_only_advisory_health_state(
    settings: SecuritySettings,
    factory: sessionmaker[Session],
) -> None:
    registration = _registration()
    seed_node_registry(factory, [registration], registered_at_utc=NOW - timedelta(minutes=1))
    heartbeat = _heartbeat(status="degraded")

    HeartbeatService(factory, settings, clock=lambda: NOW).record(heartbeat)

    with factory() as session:
        record = session.get(NodeRecord, "edge-1")
        assert record is not None
        assert record.to_registration() == registration
        assert record.registered_at_utc == NOW - timedelta(minutes=1)
        assert record.to_heartbeat() == heartbeat
    assert _alert_count(factory) == 0


@pytest.mark.parametrize(
    ("heartbeat", "reason"),
    [
        (_heartbeat(node_id="unknown"), HeartbeatReason.UNKNOWN_NODE),
        (
            _heartbeat(timestamp=NOW - timedelta(seconds=31)),
            HeartbeatReason.STALE_TIMESTAMP,
        ),
        (
            _heartbeat(timestamp=NOW + timedelta(seconds=31)),
            HeartbeatReason.FUTURE_TIMESTAMP,
        ),
    ],
)
def test_heartbeat_rejections_are_stable_and_do_not_mutate_or_audit(
    settings: SecuritySettings,
    factory: sessionmaker[Session],
    heartbeat: NodeHeartbeat,
    reason: HeartbeatReason,
) -> None:
    seed_node_registry(factory, [_registration()], registered_at_utc=NOW)

    with pytest.raises(HeartbeatRejection) as captured:
        HeartbeatService(factory, settings, clock=lambda: NOW).record(heartbeat)

    assert captured.value.reason is reason
    with factory() as session:
        assert session.get(NodeRecord, "edge-1").to_heartbeat() is None  # type: ignore[union-attr]
    assert _alert_count(factory) == 0


@pytest.mark.parametrize("seconds", [0, -1])
def test_equal_or_older_heartbeat_cannot_overwrite_newer_state(
    settings: SecuritySettings,
    factory: sessionmaker[Session],
    seconds: int,
) -> None:
    seed_node_registry(factory, [_registration()], registered_at_utc=NOW)
    service = HeartbeatService(factory, settings, clock=lambda: NOW)
    newest = _heartbeat(timestamp=NOW, status="healthy")
    service.record(newest)

    with pytest.raises(HeartbeatRejection) as captured:
        service.record(
            _heartbeat(
                timestamp=NOW + timedelta(seconds=seconds),
                status="unhealthy",
            )
        )

    assert captured.value.reason is HeartbeatReason.OUT_OF_ORDER_HEARTBEAT
    with factory() as session:
        assert session.get(NodeRecord, "edge-1").to_heartbeat() == newest  # type: ignore[union-attr]
    assert _alert_count(factory) == 0


class _FailingCommitSession:
    def __init__(self, session: Session) -> None:
        self._session = session
        self.rollback_calls = 0
        self.closed = False

    def get(self, *args: Any, **kwargs: Any) -> Any:
        return self._session.get(*args, **kwargs)

    def execute(self, *args: Any, **kwargs: Any) -> Any:
        return self._session.execute(*args, **kwargs)

    def commit(self) -> None:
        raise SQLAlchemyError("secret database path")

    def rollback(self) -> None:
        self.rollback_calls += 1
        self._session.rollback()

    def close(self) -> None:
        self.closed = True
        self._session.close()


@pytest.mark.asyncio
async def test_heartbeat_commit_failure_rolls_back_closes_and_returns_sanitized_503(
    settings: SecuritySettings,
    factory: sessionmaker[Session],
) -> None:
    seed_node_registry(factory, [_registration()], registered_at_utc=NOW)
    sessions: list[_FailingCommitSession] = []

    def failing_factory() -> _FailingCommitSession:
        value = _FailingCommitSession(factory())
        sessions.append(value)
        return value

    response = await _post_heartbeat(
        _app(settings, failing_factory),  # type: ignore[arg-type]
        _heartbeat().model_dump_json().encode(),
    )

    assert response.status_code == 503
    assert response.json() == {"detail": {"code": "service_unavailable"}}
    assert "secret" not in response.text
    assert len(sessions) == 1
    assert sessions[0].rollback_calls == 1
    assert sessions[0].closed is True
    with factory() as session:
        assert session.get(NodeRecord, "edge-1").to_heartbeat() is None  # type: ignore[union-attr]


def test_node_view_is_bounded_deterministic_and_public_key_free(
    settings: SecuritySettings,
    factory: sessionmaker[Session],
) -> None:
    registrations = [
        _registration("edge-c", b"c"),
        _registration("edge-a", b"a"),
        _registration("edge-b", b"b"),
    ]
    seed_node_registry(factory, registrations, registered_at_utc=NOW - timedelta(minutes=1))
    HeartbeatService(factory, settings, clock=lambda: NOW).record(
        _heartbeat(node_id="edge-b", status="degraded")
    )

    result = list_node_health(factory, limit=2)

    assert result == [
        NodeHealth(
            node_id="edge-a",
            registered_at_utc=NOW - timedelta(minutes=1),
            last_seen_at_utc=None,
            health_status=None,
        ),
        NodeHealth(
            node_id="edge-b",
            registered_at_utc=NOW - timedelta(minutes=1),
            last_seen_at_utc=NOW,
            health_status="degraded",
        ),
    ]
    payload = json.dumps([item.model_dump(mode="json") for item in result])
    assert "public_key" not in payload
    assert "private_key" not in payload


def test_recent_events_are_metadata_only_newest_first_with_stable_ties(
    factory: sessionmaker[Session],
) -> None:
    seed_node_registry(factory, [_registration()], registered_at_utc=NOW)
    old = _event(event_id="event-old", nonce="nonce-old")
    tie_a = _event(event_id="event-a", nonce="nonce-a")
    tie_b = _event(event_id="event-b", nonce="nonce-b")
    with session_scope(factory) as session:
        session.add_all(
            [
                DetectionEventRecord.from_event(
                    old,
                    accepted_at_utc=NOW - timedelta(seconds=1),
                ),
                DetectionEventRecord.from_event(tie_a, accepted_at_utc=NOW),
                DetectionEventRecord.from_event(tie_b, accepted_at_utc=NOW),
            ]
        )

    result = list_recent_events(factory, limit=2)

    assert result == [
        RecentDetectionEvent(accepted_at_utc=NOW, event=tie_b),
        RecentDetectionEvent(accepted_at_utc=NOW, event=tie_a),
    ]
    payload = json.dumps([item.model_dump(mode="json") for item in result])
    for forbidden in ("raw_frame", "frame_bytes", "crop", "tensor", "signature", "key"):
        assert forbidden not in payload


def test_health_summary_counts_safe_authoritative_rows(
    factory: sessionmaker[Session],
) -> None:
    seed_node_registry(factory, [_registration()], registered_at_utc=NOW)
    with session_scope(factory) as session:
        session.add(DetectionEventRecord.from_event(_event(), accepted_at_utc=NOW))
        session.add(
            SecurityAlertRecord.from_alert(
                SecurityAlert(
                    alert_id="alert-1",
                    occurred_at_utc=NOW,
                    category="identity",
                    reason="unknown_node",
                    node_id="unknown",
                    event_id="event-unknown",
                    nonce="nonce-unknown",
                )
            )
        )

    assert get_aggregator_health(factory) == AggregatorHealth(
        registered_nodes=1,
        accepted_events=1,
        security_alerts=1,
    )


def test_corrupt_stored_node_and_event_rows_fail_closed(
    factory: sessionmaker[Session],
) -> None:
    seed_node_registry(factory, [_registration()], registered_at_utc=NOW)
    with session_scope(factory) as session:
        session.add(DetectionEventRecord.from_event(_event(), accepted_at_utc=NOW))
    with session_scope(factory) as session:
        session.execute(update(NodeRecord).values(public_key_b64="bad"))
        session.execute(
            update(DetectionEventRecord).values(
                detections_json='[{"class_id":0,"raw_frame":"forbidden"}]'
            )
        )

    with pytest.raises(MonitoringServiceError, match="^service_unavailable$"):
        list_node_health(factory)
    with pytest.raises(MonitoringServiceError, match="^service_unavailable$"):
        list_recent_events(factory)


@pytest.mark.parametrize("function", [list_node_health, list_recent_events])
@pytest.mark.parametrize("limit", [0, 101, True, "1"])
def test_domain_queries_reject_invalid_limits_before_opening_a_session(
    function: Callable[..., object],
    limit: Any,
) -> None:
    opened = False

    def factory() -> None:
        nonlocal opened
        opened = True

    with pytest.raises(MonitoringServiceError, match="^service_unavailable$"):
        function(factory, limit=limit)
    assert opened is False


@pytest.mark.asyncio
async def test_heartbeat_api_accepts_known_node_and_exposes_advisory_state(
    settings: SecuritySettings,
    factory: sessionmaker[Session],
) -> None:
    seed_node_registry(factory, [_registration()], registered_at_utc=NOW)
    app = _app(settings, factory)

    accepted = await _post_heartbeat(
        app,
        _heartbeat(status="degraded").model_dump_json().encode(),
    )
    out_of_order = await _post_heartbeat(
        app,
        _heartbeat(status="unhealthy").model_dump_json().encode(),
    )
    nodes = await _get(app, NODES_PATH)

    assert accepted.status_code == 202
    assert accepted.content == b""
    assert out_of_order.status_code == 409
    assert out_of_order.json() == {
        "detail": {"code": "out_of_order_heartbeat"}
    }
    assert nodes.status_code == 200
    assert nodes.json() == [
        {
            "node_id": "edge-1",
            "registered_at_utc": NOW.isoformat().replace("+00:00", "Z"),
            "last_seen_at_utc": NOW.isoformat().replace("+00:00", "Z"),
            "health_status": "degraded",
        }
    ]
    assert _alert_count(factory) == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("heartbeat", "status_code", "code"),
    [
        (_heartbeat(node_id="unknown"), 401, "unknown_node"),
        (_heartbeat(timestamp=NOW - timedelta(seconds=31)), 409, "stale_timestamp"),
        (_heartbeat(timestamp=NOW + timedelta(seconds=31)), 409, "future_timestamp"),
    ],
)
async def test_heartbeat_api_maps_policy_rejections_without_security_alerts(
    settings: SecuritySettings,
    factory: sessionmaker[Session],
    heartbeat: NodeHeartbeat,
    status_code: int,
    code: str,
) -> None:
    seed_node_registry(factory, [_registration()], registered_at_utc=NOW)

    response = await _post_heartbeat(
        _app(settings, factory),
        heartbeat.model_dump_json().encode(),
    )

    assert response.status_code == status_code
    assert response.json() == {"detail": {"code": code}}
    assert _alert_count(factory) == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("content", "path", "headers", "status_code", "code"),
    [
        (b"{", NODE_HEARTBEAT_PATH, None, 422, "invalid_request"),
        (
            b'{"node_id":"edge-1","node_id":"edge-2"}',
            NODE_HEARTBEAT_PATH,
            None,
            422,
            "invalid_request",
        ),
        (b'{"raw_frame":"pixels"}', NODE_HEARTBEAT_PATH, None, 422, "invalid_request"),
        (b"{}", f"{NODE_HEARTBEAT_PATH}?unknown=1", None, 422, "invalid_request"),
        (b"{}", NODE_HEARTBEAT_PATH, {"content-type": "text/plain"}, 422, "invalid_request"),
        (b"x" * 1025, NODE_HEARTBEAT_PATH, None, 413, "request_too_large"),
        (
            b"{}",
            NODE_HEARTBEAT_PATH,
            {"content-length": "9" * 5000},
            413,
            "request_too_large",
        ),
    ],
)
async def test_heartbeat_request_boundary_is_strict_bounded_and_sanitized(
    settings: SecuritySettings,
    factory: sessionmaker[Session],
    content: bytes,
    path: str,
    headers: dict[str, str] | None,
    status_code: int,
    code: str,
) -> None:
    response = await _post_heartbeat(_app(settings, factory), content, path=path, headers=headers)

    assert response.status_code == status_code
    assert response.json() == {"detail": {"code": code}}
    assert "pixels" not in response.text
    assert _alert_count(factory) == 0


@pytest.mark.asyncio
async def test_health_nodes_and_events_api_are_typed_empty_and_query_strict(
    settings: SecuritySettings,
    factory: sessionmaker[Session],
) -> None:
    app = _app(settings, factory)

    health = await _get(app, HEALTH_PATH)
    nodes = await _get(app, NODES_PATH)
    events = await _get(app, EVENTS_PATH)

    assert health.status_code == 200
    assert health.json() == {
        "status": "healthy",
        "database": "ready",
        "registered_nodes": 0,
        "accepted_events": 0,
        "security_alerts": 0,
    }
    assert nodes.status_code == 200 and nodes.json() == []
    assert events.status_code == 200 and events.json() == []

    for path in (NODES_PATH, EVENTS_PATH):
        assert (await _get(app, f"{path}?limit=0001")).status_code == 200
        for query in (
            "limit=0",
            "limit=101",
            "limit=bogus",
            f"limit={'9' * 5000}",
            "limit=1&limit=2",
            "unknown=1",
        ):
            response = await _get(app, f"{path}?{query}")
            assert response.status_code == 422
            assert response.json() == {"detail": {"code": "invalid_request"}}

    unexpected = await _get(app, f"{HEALTH_PATH}?verbose=true")
    assert unexpected.status_code == 422
    assert unexpected.json() == {"detail": {"code": "invalid_request"}}


@pytest.mark.asyncio
async def test_events_api_returns_full_normalized_metadata_without_pixels(
    settings: SecuritySettings,
    factory: sessionmaker[Session],
) -> None:
    seed_node_registry(factory, [_registration()], registered_at_utc=NOW)
    event = _event()
    with session_scope(factory) as session:
        session.add(DetectionEventRecord.from_event(event, accepted_at_utc=NOW))

    response = await _get(_app(settings, factory), EVENTS_PATH)

    assert response.status_code == 200
    assert response.json() == [
        {
            "accepted_at_utc": NOW.isoformat().replace("+00:00", "Z"),
            "event": event.model_dump(mode="json"),
        }
    ]
    for forbidden in ("raw_frame", "frame_bytes", "crop", "tensor", "signature_b64"):
        assert forbidden not in response.text


class _FailingQuerySession:
    def __init__(self) -> None:
        self.rollback_calls = 0
        self.closed = False

    def scalars(self, value: object) -> None:
        del value
        raise SQLAlchemyError("secret database path")

    def scalar(self, value: object) -> None:
        del value
        raise SQLAlchemyError("secret database path")

    def rollback(self) -> None:
        self.rollback_calls += 1

    def close(self) -> None:
        self.closed = True


@pytest.mark.asyncio
@pytest.mark.parametrize("path", [HEALTH_PATH, NODES_PATH, EVENTS_PATH])
async def test_query_failure_returns_sanitized_503_and_closes_session(
    settings: SecuritySettings,
    path: str,
) -> None:
    sessions: list[_FailingQuerySession] = []

    def failing_factory() -> _FailingQuerySession:
        value = _FailingQuerySession()
        sessions.append(value)
        return value

    response = await _get(
        _app(settings, failing_factory),  # type: ignore[arg-type]
        path,
    )

    assert response.status_code == 503
    assert response.json() == {"detail": {"code": "service_unavailable"}}
    assert "secret" not in response.text
    assert len(sessions) == 1
    assert sessions[0].rollback_calls == 1
    assert sessions[0].closed is True


@pytest.mark.asyncio
@pytest.mark.parametrize("path", [NODES_PATH, EVENTS_PATH])
async def test_corrupt_query_rows_map_to_sanitized_503(
    settings: SecuritySettings,
    factory: sessionmaker[Session],
    path: str,
) -> None:
    seed_node_registry(factory, [_registration()], registered_at_utc=NOW)
    with session_scope(factory) as session:
        session.add(DetectionEventRecord.from_event(_event(), accepted_at_utc=NOW))
    with session_scope(factory) as session:
        if path == NODES_PATH:
            session.execute(update(NodeRecord).values(public_key_b64="secret-corruption"))
        else:
            session.execute(
                update(DetectionEventRecord).values(
                    detections_json='[{"class_id":0,"raw_frame":"secret-pixels"}]'
                )
            )

    response = await _get(_app(settings, factory), path)

    assert response.status_code == 503
    assert response.json() == {"detail": {"code": "service_unavailable"}}
    assert "secret" not in response.text


def test_monitoring_models_forbid_undeclared_sensitive_fields() -> None:
    node = NodeHealth(
        node_id="edge-1",
        registered_at_utc=NOW,
        last_seen_at_utc=None,
        health_status=None,
    )
    with pytest.raises(ValidationError):
        NodeHealth.model_validate(node.model_dump() | {"public_key_b64": "forbidden"})


def test_monitoring_import_has_no_external_side_effects() -> None:
    script = """
import os
import pathlib
import socket
import sqlite3
import sqlalchemy

def fail(*args, **kwargs):
    raise AssertionError("monitoring import performed an external side effect")

real_getenv = os.getenv
def guarded_getenv(key, default=None):
    if key.startswith("SEV_"):
        raise AssertionError("monitoring import inspected application environment")
    return real_getenv(key, default)

sqlalchemy.create_engine = fail
pathlib.Path.mkdir = fail
os.getenv = guarded_getenv
socket.socket = fail
sqlite3.connect = fail

import secureedge.monitoring as monitoring
assert monitoring.DEFAULT_MONITORING_QUERY_LIMIT == 50
assert monitoring.MAX_MONITORING_QUERY_LIMIT == 100
"""
    subprocess.run([sys.executable, "-c", script], check=True)
