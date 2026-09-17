from __future__ import annotations

import base64
import pathlib
import subprocess
import sys
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest
from pydantic import ValidationError
from secureedge.contracts import DetectionEvent, NodeHeartbeat, NodeRegistration
from secureedge.persistence import (
    DetectionEventRecord,
    NodeRecord,
    PersistenceBase,
    PersistenceError,
    SecurityAlert,
    SecurityAlertRecord,
    create_session_factory,
    create_sqlite_engine,
    initialize_database,
    seed_node_registry,
    session_scope,
)
from sqlalchemy import Engine, MetaData, UniqueConstraint, inspect, select, text, update
from sqlalchemy.orm import Session, sessionmaker

NOW = datetime(2026, 9, 17, 3, 15, tzinfo=UTC)


@pytest.fixture
def engine(tmp_path: pathlib.Path) -> Iterator[Engine]:
    database = create_sqlite_engine(f"sqlite:///{tmp_path / 'persistence.sqlite3'}")
    initialize_database(database)
    yield database
    database.dispose()


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
    detections: list[dict[str, Any]] | None = None,
    job_id: str | None = None,
) -> DetectionEvent:
    if detections is None:
        detections = [
            {
                "class_id": 0,
                "class_name": "person",
                "confidence": 0.91,
                "bbox_xyxy_norm": [0.1, 0.2, 0.7, 0.9],
                "track_id": 7,
            },
            {
                "class_id": 2,
                "class_name": "car",
                "confidence": 0.72,
                "bbox_xyxy_norm": [0.3, 0.1, 0.8, 0.6],
                "track_id": None,
            },
        ]
    return DetectionEvent.model_validate(
        {
            "schema_version": "1.0",
            "event_id": event_id,
            "node_id": "edge-1",
            "camera_id": "cam-1",
            "timestamp_utc": NOW,
            "nonce": nonce,
            "frame_seq": 42,
            "job_id": job_id,
            "mode": "privacy",
            "model": {"name": "yolo26n.pt", "sha256": "a" * 64},
            "frame": {"width": 1920, "height": 1080},
            "detections": detections,
            "performance": {
                "decode_ms": 1.25,
                "inference_ms": 12.5,
                "postprocess_ms": 0.75,
            },
        }
    )


def test_persistence_import_has_no_external_side_effects() -> None:
    script = """
import os
import pathlib
import socket
import sqlite3
import sqlalchemy

def fail(*args, **kwargs):
    raise AssertionError("persistence import performed an external side effect")

real_getenv = os.getenv
def guarded_getenv(key, default=None):
    if key.startswith("SEV_"):
        raise AssertionError("persistence import inspected application environment")
    return real_getenv(key, default)

sqlalchemy.create_engine = fail
pathlib.Path.mkdir = fail
os.getenv = guarded_getenv
socket.socket = fail
sqlite3.connect = fail

import secureedge.persistence as persistence
assert set(persistence.PersistenceBase.metadata.tables) == {
    "nodes", "detection_events", "security_alerts"
}
"""
    subprocess.run([sys.executable, "-c", script], check=True)


def test_schema_is_exact_metadata_only_and_enforces_foreign_keys(engine: Engine) -> None:
    inspector = inspect(engine)
    assert set(inspector.get_table_names()) == {
        "nodes",
        "detection_events",
        "security_alerts",
    }
    event_columns = {column["name"] for column in inspector.get_columns("detection_events")}
    alert_columns = {column["name"] for column in inspector.get_columns("security_alerts")}
    all_columns = event_columns | alert_columns
    assert {
        "schema_version",
        "event_id",
        "node_id",
        "camera_id",
        "timestamp_utc",
        "nonce",
        "frame_seq",
        "job_id",
        "mode",
        "model_name",
        "model_sha256",
        "frame_width",
        "frame_height",
        "detections_json",
        "decode_ms",
        "inference_ms",
        "postprocess_ms",
        "accepted_at_utc",
    }.issubset(event_columns)
    for forbidden in (
        "frame_bytes",
        "raw_frame",
        "crop",
        "tensor",
        "model_bytes",
        "private_key",
        "credential",
        "payload",
        "signature",
        "exception",
        "response_body",
    ):
        assert forbidden not in all_columns

    indexes = {item["name"]: item for item in inspector.get_indexes("detection_events")}
    assert indexes["ix_detection_events_event_id"]["unique"] == 0
    assert indexes["ix_detection_events_nonce"]["unique"] == 0
    assert inspector.get_unique_constraints("detection_events") == []
    assert inspector.get_foreign_keys("security_alerts") == []
    with engine.connect() as connection:
        assert connection.scalar(text("PRAGMA foreign_keys")) == 1


def test_initializer_is_idempotent_and_preserves_rows(
    engine: Engine,
    factory: sessionmaker[Session],
) -> None:
    assert seed_node_registry(factory, [_registration()], registered_at_utc=NOW) == 1

    initialize_database(engine)

    with factory() as session:
        stored = session.get(NodeRecord, "edge-1")
        assert stored is not None
        assert stored.to_registration() == _registration()


def test_initializer_rejects_partial_schema_without_modifying_it(tmp_path: pathlib.Path) -> None:
    engine = create_sqlite_engine(f"sqlite:///{tmp_path / 'partial.sqlite3'}")
    try:
        with engine.begin() as connection:
            connection.execute(text("CREATE TABLE nodes (node_id VARCHAR(128) PRIMARY KEY)"))

        with pytest.raises(PersistenceError, match="^database schema is incompatible$"):
            initialize_database(engine)

        assert inspect(engine).get_table_names() == ["nodes"]
    finally:
        engine.dispose()


def test_initializer_rejects_same_named_but_incompatible_schema(
    tmp_path: pathlib.Path,
) -> None:
    engine = create_sqlite_engine(f"sqlite:///{tmp_path / 'incompatible.sqlite3'}")
    try:
        PersistenceBase.metadata.create_all(engine)
        with engine.begin() as connection:
            connection.execute(text("DROP INDEX ix_detection_events_event_id"))

        with pytest.raises(PersistenceError, match="^database schema is incompatible$"):
            initialize_database(engine)
    finally:
        engine.dispose()


@pytest.mark.parametrize("column_name", ["event_id", "nonce"])
def test_initializer_rejects_undeclared_replay_unique_constraint_without_modifying_schema(
    tmp_path: pathlib.Path,
    column_name: str,
) -> None:
    engine = create_sqlite_engine(f"sqlite:///{tmp_path / f'unique-{column_name}.sqlite3'}")
    try:
        incompatible_metadata = MetaData()
        for table in PersistenceBase.metadata.sorted_tables:
            table.to_metadata(incompatible_metadata)
        incompatible_metadata.tables["detection_events"].append_constraint(
            UniqueConstraint(column_name, name=f"uq_detection_events_{column_name}")
        )
        incompatible_metadata.create_all(engine)

        with engine.connect() as connection:
            schema_before = [
                tuple(row)
                for row in connection.execute(
                    text(
                        "SELECT type, name, tbl_name, sql "
                        "FROM sqlite_master ORDER BY type, name"
                    )
                )
            ]

        with pytest.raises(PersistenceError, match="^database schema is incompatible$"):
            initialize_database(engine)

        with engine.connect() as connection:
            schema_after = [
                tuple(row)
                for row in connection.execute(
                    text(
                        "SELECT type, name, tbl_name, sql "
                        "FROM sqlite_master ORDER BY type, name"
                    )
                )
            ]
        assert schema_after == schema_before
    finally:
        engine.dispose()


def test_session_scope_commits_rolls_back_and_closes_connections(
    engine: Engine,
    factory: sessionmaker[Session],
) -> None:
    with session_scope(factory) as session:
        session.add(NodeRecord.from_registration(_registration(), registered_at_utc=NOW))

    with pytest.raises(RuntimeError, match="abort"):
        with session_scope(factory) as session:
            session.add(
                NodeRecord.from_registration(
                    _registration("edge-2", b"b"),
                    registered_at_utc=NOW,
                )
            )
            raise RuntimeError("abort")

    with factory() as session:
        assert session.get(NodeRecord, "edge-1") is not None
        assert session.get(NodeRecord, "edge-2") is None
    assert engine.pool.checkedout() == 0  # type: ignore[attr-defined]


def test_node_seed_is_atomic_idempotent_and_rejects_key_rotation(
    factory: sessionmaker[Session],
) -> None:
    original = _registration()
    assert seed_node_registry(factory, [original], registered_at_utc=NOW) == 1
    assert seed_node_registry(factory, [original], registered_at_utc=NOW) == 0

    with pytest.raises(
        PersistenceError,
        match="^node identity conflicts with registered public key$",
    ):
        seed_node_registry(
            factory,
            [_registration("edge-2", b"b"), _registration("edge-1", b"c")],
            registered_at_utc=NOW,
        )

    with factory() as session:
        assert session.get(NodeRecord, "edge-2") is None
        assert session.get(NodeRecord, "edge-1").to_registration() == original  # type: ignore[union-attr]


def test_node_heartbeat_state_reuses_strict_wire_semantics(
    factory: sessionmaker[Session],
) -> None:
    seed_node_registry(factory, [_registration()], registered_at_utc=NOW)
    heartbeat = NodeHeartbeat(
        node_id="edge-1",
        timestamp_utc=NOW + timedelta(seconds=5),
        status="healthy",
    )

    with session_scope(factory) as session:
        record = session.get(NodeRecord, "edge-1")
        assert record is not None
        assert record.to_heartbeat() is None
        record.apply_heartbeat(heartbeat)

    with factory() as session:
        record = session.get(NodeRecord, "edge-1")
        assert record is not None
        assert record.to_heartbeat() == heartbeat


@pytest.mark.parametrize(
    ("detections", "job_id"),
    [([], None), (None, "job-1")],
)
def test_event_record_round_trip_preserves_order_nullability_and_utc(
    factory: sessionmaker[Session],
    detections: list[dict[str, Any]] | None,
    job_id: str | None,
) -> None:
    seed_node_registry(factory, [_registration()], registered_at_utc=NOW)
    event = _event(detections=detections, job_id=job_id)

    with session_scope(factory) as session:
        session.add(
            DetectionEventRecord.from_event(
                event,
                accepted_at_utc=NOW + timedelta(seconds=1),
            )
        )

    with factory() as session:
        record = session.scalar(select(DetectionEventRecord))
        assert record is not None
        assert record.to_event() == event
        assert record.timestamp_utc.tzinfo is UTC
        assert record.accepted_at_utc.tzinfo is UTC
        if event.detections:
            assert [item.class_name for item in record.to_event().detections] == ["person", "car"]


def test_event_ids_and_nonces_are_not_permanently_unique(
    factory: sessionmaker[Session],
) -> None:
    seed_node_registry(factory, [_registration()], registered_at_utc=NOW)
    event = _event()
    with session_scope(factory) as session:
        session.add_all(
            [
                DetectionEventRecord.from_event(event, accepted_at_utc=NOW),
                DetectionEventRecord.from_event(
                    event,
                    accepted_at_utc=NOW + timedelta(seconds=1),
                ),
            ]
        )

    with factory() as session:
        assert len(session.scalars(select(DetectionEventRecord)).all()) == 2


def test_unknown_node_cannot_back_an_accepted_event(factory: sessionmaker[Session]) -> None:
    with pytest.raises(PersistenceError, match="^database transaction failed$"):
        with session_scope(factory) as session:
            session.add(DetectionEventRecord.from_event(_event(), accepted_at_utc=NOW))


def test_malformed_stored_detection_json_fails_closed(
    factory: sessionmaker[Session],
) -> None:
    seed_node_registry(factory, [_registration()], registered_at_utc=NOW)
    with session_scope(factory) as session:
        session.add(DetectionEventRecord.from_event(_event(), accepted_at_utc=NOW))
    with session_scope(factory) as session:
        session.execute(
            update(DetectionEventRecord).values(
                detections_json='[{"class_id":0,"raw_frame":"forbidden"}]'
            )
        )

    with factory() as session:
        record = session.scalar(select(DetectionEventRecord))
        assert record is not None
        with pytest.raises(PersistenceError, match="^stored detection event is invalid$"):
            record.to_event()


def test_alert_round_trip_allows_unknown_node_without_arbitrary_context(
    factory: sessionmaker[Session],
) -> None:
    alert = SecurityAlert(
        alert_id="alert-1",
        occurred_at_utc=NOW,
        category="identity",
        reason="unknown_node",
        node_id="unregistered-node",
        event_id="event-1",
        nonce="nonce-1",
    )
    with session_scope(factory) as session:
        session.add(SecurityAlertRecord.from_alert(alert))

    with factory() as session:
        record = session.get(SecurityAlertRecord, "alert-1")
        assert record is not None
        assert record.to_alert() == alert

    with pytest.raises(ValidationError):
        SecurityAlert.model_validate(alert.model_dump() | {"signature_b64": "forbidden"})


@pytest.mark.parametrize(
    "database_url",
    [
        "postgresql://localhost/secureedge",
        "sqlite://user:password@localhost/state.db",
        "sqlite:///file:state.db",
        "sqlite:///../state.db",
        "sqlite:///state.db?mode=ro",
        "sqlite://",
    ],
)
def test_engine_factory_rejects_unsafe_or_nonlocal_urls(database_url: str) -> None:
    with pytest.raises(
        PersistenceError,
        match="^database URL is not an approved local SQLite URL$",
    ):
        create_sqlite_engine(database_url)


def test_engine_factory_rejects_missing_parent_without_creating_it(
    tmp_path: pathlib.Path,
) -> None:
    missing = tmp_path / "missing" / "state.sqlite3"

    with pytest.raises(PersistenceError, match="^database parent directory does not exist$"):
        create_sqlite_engine(f"sqlite:///{missing}")

    assert not missing.parent.exists()


def test_connection_failure_is_sanitized(tmp_path: pathlib.Path) -> None:
    engine = create_sqlite_engine(f"sqlite:///{tmp_path}")
    try:
        with pytest.raises(PersistenceError) as exc_info:
            initialize_database(engine)
        assert str(exc_info.value) == "database initialization failed"
        assert str(tmp_path) not in str(exc_info.value)
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    "timestamp",
    [
        datetime(2026, 9, 17, 3, 15),
        datetime(2026, 9, 17, 8, 15, tzinfo=timezone(timedelta(hours=5))),
    ],
)
def test_conversion_boundaries_reject_non_utc_times(timestamp: datetime) -> None:
    with pytest.raises(PersistenceError, match="timestamp must be aware UTC"):
        NodeRecord.from_registration(_registration(), registered_at_utc=timestamp)
    with pytest.raises(PersistenceError, match="timestamp must be aware UTC"):
        DetectionEventRecord.from_event(_event(), accepted_at_utc=timestamp)


def test_metadata_boundary_declares_only_three_tables() -> None:
    assert set(PersistenceBase.metadata.tables) == {
        "nodes",
        "detection_events",
        "security_alerts",
    }
