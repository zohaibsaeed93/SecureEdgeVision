"""Explicit SQLAlchemy persistence primitives for the Milestone 1 aggregator.

The module defines schema and conversion boundaries only. Importing it performs no
filesystem or database work; callers must explicitly create an engine, initialize
the schema, and open transactional sessions.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import (
    CheckConstraint,
    Engine,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    create_engine,
    event,
    inspect,
    select,
)
from sqlalchemy.engine import Dialect, make_url
from sqlalchemy.exc import ArgumentError, SQLAlchemyError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.sql.schema import CheckConstraint as SchemaCheckConstraint
from sqlalchemy.types import TypeDecorator

from secureedge.contracts import (
    Detection,
    DetectionEvent,
    FrameMetadata,
    ModelMetadata,
    NodeHeartbeat,
    NodeRegistration,
    PerformanceMetrics,
    SafeIdentifier,
    UtcTimestamp,
)

_LOCAL_SQLITE_DRIVERS = frozenset({"sqlite", "sqlite+pysqlite"})
_SAFE_DATABASE_PATH = re.compile(r"^[A-Za-z0-9_./-]+$")
_MACHINE_CODE_PATTERN = r"^[a-z][a-z0-9_.:-]*$"


class PersistenceError(RuntimeError):
    """Stable, sanitized failure raised by the persistence boundary."""


class PersistenceBase(DeclarativeBase):
    """Single declarative metadata boundary for Milestone 1 persistence."""


class _UtcTimestampType(TypeDecorator[datetime]):
    """Store UTC instants as deterministic ISO-8601 text in SQLite."""

    impl = String(32)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> str | None:
        del dialect
        if value is None:
            return None
        normalized = _require_utc(value, message="timestamp must be aware UTC")
        return normalized.isoformat(timespec="microseconds").replace("+00:00", "Z")

    def process_result_value(self, value: str | None, dialect: Dialect) -> datetime | None:
        del dialect
        if value is None:
            return None
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except (TypeError, ValueError) as exc:
            raise PersistenceError("stored timestamp is invalid") from exc
        return _require_utc(parsed, message="stored timestamp is invalid")


class NodeRecord(PersistenceBase):
    """Registered public node identity plus minimal heartbeat state."""

    __tablename__ = "nodes"
    __table_args__ = (
        CheckConstraint(
            "health_status IS NULL OR health_status IN ('healthy', 'degraded', 'unhealthy')",
            name="ck_nodes_health_status",
        ),
        Index("ix_nodes_last_seen_at_utc", "last_seen_at_utc"),
    )

    node_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    public_key_b64: Mapped[str] = mapped_column(String(44), nullable=False)
    registered_at_utc: Mapped[datetime] = mapped_column(_UtcTimestampType(), nullable=False)
    last_seen_at_utc: Mapped[datetime | None] = mapped_column(_UtcTimestampType(), nullable=True)
    health_status: Mapped[str | None] = mapped_column(String(16), nullable=True)

    @classmethod
    def from_registration(
        cls,
        registration: NodeRegistration,
        *,
        registered_at_utc: datetime,
    ) -> NodeRecord:
        """Create a record from already validated public registration material."""

        validated = _validated_registration(registration)
        return cls(
            node_id=validated.node_id,
            public_key_b64=validated.public_key_b64,
            registered_at_utc=_require_utc(
                registered_at_utc,
                message="registration timestamp must be aware UTC",
            ),
        )

    def to_registration(self) -> NodeRegistration:
        """Revalidate stored public identity before returning domain data."""

        try:
            return NodeRegistration(
                node_id=self.node_id,
                public_key_b64=self.public_key_b64,
            )
        except (TypeError, ValidationError, ValueError) as exc:
            raise PersistenceError("stored node record is invalid") from exc

    def apply_heartbeat(self, heartbeat: NodeHeartbeat) -> None:
        """Apply a validated heartbeat without changing registered identity."""

        validated = _validated_heartbeat(heartbeat)
        if validated.node_id != self.node_id:
            raise PersistenceError("heartbeat node does not match stored node")
        self.last_seen_at_utc = validated.timestamp_utc
        self.health_status = validated.status

    def to_heartbeat(self) -> NodeHeartbeat | None:
        """Return the stored heartbeat state, failing closed on a partial state."""

        if self.last_seen_at_utc is None and self.health_status is None:
            return None
        if self.last_seen_at_utc is None or self.health_status is None:
            raise PersistenceError("stored node health state is invalid")
        try:
            return NodeHeartbeat(
                node_id=self.node_id,
                timestamp_utc=self.last_seen_at_utc,
                status=self.health_status,  # type: ignore[arg-type]
            )
        except (TypeError, ValidationError, ValueError) as exc:
            raise PersistenceError("stored node health state is invalid") from exc


class DetectionEventRecord(PersistenceBase):
    """Accepted privacy-mode event metadata; image data has no storage field."""

    __tablename__ = "detection_events"
    __table_args__ = (
        CheckConstraint("schema_version = '1.0'", name="ck_detection_events_schema_version"),
        CheckConstraint("mode = 'privacy'", name="ck_detection_events_mode"),
        CheckConstraint("frame_seq >= 0", name="ck_detection_events_frame_seq"),
        CheckConstraint(
            "frame_width > 0 AND frame_height > 0",
            name="ck_detection_events_frame_dimensions",
        ),
        CheckConstraint(
            "decode_ms >= 0 AND inference_ms >= 0 AND postprocess_ms >= 0",
            name="ck_detection_events_performance",
        ),
        Index("ix_detection_events_event_id", "event_id"),
        Index("ix_detection_events_nonce", "nonce"),
        Index("ix_detection_events_node_timestamp", "node_id", "timestamp_utc"),
        Index("ix_detection_events_accepted_at_utc", "accepted_at_utc"),
    )

    record_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    schema_version: Mapped[str] = mapped_column(String(8), nullable=False)
    event_id: Mapped[str] = mapped_column(String(128), nullable=False)
    node_id: Mapped[str] = mapped_column(
        String(128),
        ForeignKey("nodes.node_id", ondelete="RESTRICT"),
        nullable=False,
    )
    camera_id: Mapped[str] = mapped_column(String(128), nullable=False)
    timestamp_utc: Mapped[datetime] = mapped_column(_UtcTimestampType(), nullable=False)
    nonce: Mapped[str] = mapped_column(String(128), nullable=False)
    frame_seq: Mapped[int] = mapped_column(Integer, nullable=False)
    job_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    mode: Mapped[str] = mapped_column(String(16), nullable=False)
    model_name: Mapped[str] = mapped_column(String(255), nullable=False)
    model_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    frame_width: Mapped[int] = mapped_column(Integer, nullable=False)
    frame_height: Mapped[int] = mapped_column(Integer, nullable=False)
    detections_json: Mapped[str] = mapped_column(Text, nullable=False)
    decode_ms: Mapped[float] = mapped_column(Float, nullable=False)
    inference_ms: Mapped[float] = mapped_column(Float, nullable=False)
    postprocess_ms: Mapped[float] = mapped_column(Float, nullable=False)
    accepted_at_utc: Mapped[datetime] = mapped_column(_UtcTimestampType(), nullable=False)

    @classmethod
    def from_event(
        cls,
        event: DetectionEvent,
        *,
        accepted_at_utc: datetime,
    ) -> DetectionEventRecord:
        """Convert validated domain metadata to a deterministic database record."""

        validated = _validated_event(event)
        return cls(
            schema_version=validated.schema_version,
            event_id=validated.event_id,
            node_id=validated.node_id,
            camera_id=validated.camera_id,
            timestamp_utc=validated.timestamp_utc,
            nonce=validated.nonce,
            frame_seq=validated.frame_seq,
            job_id=validated.job_id,
            mode=validated.mode,
            model_name=validated.model.name,
            model_sha256=validated.model.sha256,
            frame_width=validated.frame.width,
            frame_height=validated.frame.height,
            detections_json=_serialize_detections(validated.detections),
            decode_ms=validated.performance.decode_ms,
            inference_ms=validated.performance.inference_ms,
            postprocess_ms=validated.performance.postprocess_ms,
            accepted_at_utc=_require_utc(
                accepted_at_utc,
                message="acceptance timestamp must be aware UTC",
            ),
        )

    def to_event(self) -> DetectionEvent:
        """Reconstruct and strictly validate authoritative event metadata."""

        try:
            return DetectionEvent(
                schema_version=self.schema_version,  # type: ignore[arg-type]
                event_id=self.event_id,
                node_id=self.node_id,
                camera_id=self.camera_id,
                timestamp_utc=self.timestamp_utc,
                nonce=self.nonce,
                frame_seq=self.frame_seq,
                job_id=self.job_id,
                mode=self.mode,  # type: ignore[arg-type]
                model=ModelMetadata(name=self.model_name, sha256=self.model_sha256),
                frame=FrameMetadata(width=self.frame_width, height=self.frame_height),
                detections=_deserialize_detections(self.detections_json),
                performance=PerformanceMetrics(
                    decode_ms=self.decode_ms,
                    inference_ms=self.inference_ms,
                    postprocess_ms=self.postprocess_ms,
                ),
            )
        except PersistenceError:
            raise
        except (TypeError, ValidationError, ValueError) as exc:
            raise PersistenceError("stored detection event is invalid") from exc


class SecurityAlert(BaseModel):
    """Sanitized metadata allowed in the security-alert table."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    alert_id: SafeIdentifier
    occurred_at_utc: UtcTimestamp
    category: Annotated[str, Field(min_length=1, max_length=64, pattern=_MACHINE_CODE_PATTERN)]
    reason: Annotated[str, Field(min_length=1, max_length=64, pattern=_MACHINE_CODE_PATTERN)]
    node_id: SafeIdentifier | None = None
    event_id: SafeIdentifier | None = None
    nonce: SafeIdentifier | None = None


class SecurityAlertRecord(PersistenceBase):
    """Minimal sanitized audit foundation for a later rejection boundary."""

    __tablename__ = "security_alerts"
    __table_args__ = (
        Index("ix_security_alerts_occurred_at_utc", "occurred_at_utc"),
        Index("ix_security_alerts_node_id", "node_id"),
        Index("ix_security_alerts_category_reason", "category", "reason"),
    )

    alert_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    occurred_at_utc: Mapped[datetime] = mapped_column(_UtcTimestampType(), nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    reason: Mapped[str] = mapped_column(String(64), nullable=False)
    node_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    event_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    nonce: Mapped[str | None] = mapped_column(String(128), nullable=True)

    @classmethod
    def from_alert(cls, alert: SecurityAlert) -> SecurityAlertRecord:
        """Convert already sanitized alert metadata to a record."""

        validated = _validated_alert(alert)
        return cls(**validated.model_dump(mode="python"))

    def to_alert(self) -> SecurityAlert:
        """Revalidate stored alert fields before exposing them as domain data."""

        try:
            return SecurityAlert(
                alert_id=self.alert_id,
                occurred_at_utc=self.occurred_at_utc,
                category=self.category,
                reason=self.reason,
                node_id=self.node_id,
                event_id=self.event_id,
                nonce=self.nonce,
            )
        except (TypeError, ValidationError, ValueError) as exc:
            raise PersistenceError("stored security alert is invalid") from exc


SessionFactory = sessionmaker[Session]


def create_sqlite_engine(database_url: str) -> Engine:
    """Build a caller-owned engine for one approved local SQLite URL.

    Missing parent directories are rejected rather than created implicitly. The
    returned engine is lazy; database connection and DDL occur only on later
    explicit calls.
    """

    _validate_database_url(database_url)
    try:
        url = make_url(database_url)
        if url.database == ":memory:":
            engine = create_engine(
                database_url,
                future=True,
                poolclass=StaticPool,
                connect_args={"check_same_thread": False},
            )
        else:
            engine = create_engine(database_url, future=True)
    except (ArgumentError, TypeError, ValueError) as exc:
        raise PersistenceError("database URL is not an approved local SQLite URL") from exc

    @event.listens_for(engine, "connect")
    def _enable_sqlite_foreign_keys(dbapi_connection: Any, connection_record: Any) -> None:
        del connection_record
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA foreign_keys=ON")
        finally:
            cursor.close()

    return engine


def create_session_factory(engine: Engine) -> SessionFactory:
    """Create an explicit caller-owned SQLAlchemy session factory."""

    _require_sqlite_engine(engine)
    return sessionmaker(bind=engine, class_=Session, expire_on_commit=False)


@contextmanager
def session_scope(factory: SessionFactory) -> Iterator[Session]:
    """Commit one successful unit of work and always roll back/close failures."""

    session = factory()
    try:
        yield session
        session.commit()
    except PersistenceError:
        session.rollback()
        raise
    except SQLAlchemyError as exc:
        session.rollback()
        raise PersistenceError("database transaction failed") from exc
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def initialize_database(engine: Engine) -> None:
    """Create the exact schema once and reject incompatible existing schemas."""

    _require_sqlite_engine(engine)
    required_tables = frozenset(PersistenceBase.metadata.tables)
    try:
        existing_tables = frozenset(inspect(engine).get_table_names())
        if existing_tables and existing_tables != required_tables:
            raise PersistenceError("database schema is incompatible")
        if existing_tables:
            _verify_schema(engine)
            return

        PersistenceBase.metadata.create_all(engine, checkfirst=True)
        _verify_schema(engine)
    except PersistenceError:
        raise
    except (SQLAlchemyError, TypeError, ValueError) as exc:
        raise PersistenceError("database initialization failed") from exc


def seed_node_registry(
    factory: SessionFactory,
    registrations: Iterable[NodeRegistration],
    *,
    registered_at_utc: datetime,
) -> int:
    """Atomically add new public identities and reject silent key replacement.

    Returns the number of newly inserted nodes. Repeating an identical seed is a
    no-op; one conflict rejects the entire batch.
    """

    timestamp = _require_utc(
        registered_at_utc,
        message="registration timestamp must be aware UTC",
    )
    registrations_by_id: dict[str, NodeRegistration] = {}
    for registration in registrations:
        validated = _validated_registration(registration)
        previous = registrations_by_id.get(validated.node_id)
        if previous is not None and previous.public_key_b64 != validated.public_key_b64:
            raise PersistenceError("node identity conflicts with registered public key")
        registrations_by_id[validated.node_id] = validated

    if not registrations_by_id:
        return 0

    inserted = 0
    with session_scope(factory) as session:
        existing = {
            record.node_id: record
            for record in session.scalars(
                select(NodeRecord).where(NodeRecord.node_id.in_(registrations_by_id))
            )
        }
        for node_id, registration in registrations_by_id.items():
            record = existing.get(node_id)
            if record is not None:
                stored = record.to_registration()
                if stored.public_key_b64 != registration.public_key_b64:
                    raise PersistenceError("node identity conflicts with registered public key")
                continue
            session.add(
                NodeRecord.from_registration(
                    registration,
                    registered_at_utc=timestamp,
                )
            )
            inserted += 1
    return inserted


def _validate_database_url(database_url: str) -> None:
    if not isinstance(database_url, str) or not database_url:
        raise PersistenceError("database URL is not an approved local SQLite URL")
    try:
        url = make_url(database_url)
    except (ArgumentError, TypeError, ValueError) as exc:
        raise PersistenceError("database URL is not an approved local SQLite URL") from exc

    if (
        url.drivername not in _LOCAL_SQLITE_DRIVERS
        or url.username is not None
        or url.password is not None
        or url.host is not None
        or url.port is not None
        or bool(url.query)
        or not url.database
    ):
        raise PersistenceError("database URL is not an approved local SQLite URL")

    database = url.database
    if database == ":memory:":
        return
    if (
        database.startswith(("file:", "~"))
        or "\\" in database
        or not _SAFE_DATABASE_PATH.fullmatch(database)
        or ".." in Path(database).parts
    ):
        raise PersistenceError("database URL is not an approved local SQLite URL")

    parent = Path(database).parent
    if not parent.exists() or not parent.is_dir():
        raise PersistenceError("database parent directory does not exist")


def _require_sqlite_engine(engine: Engine) -> None:
    if not isinstance(engine, Engine) or engine.dialect.name != "sqlite":
        raise PersistenceError("engine must use approved local SQLite")


def _verify_schema(engine: Engine) -> None:
    inspector = inspect(engine)
    required_tables = frozenset(PersistenceBase.metadata.tables)
    if frozenset(inspector.get_table_names()) != required_tables:
        raise PersistenceError("database schema is incompatible")

    for table_name, table in PersistenceBase.metadata.tables.items():
        reflected_columns = {column["name"]: column for column in inspector.get_columns(table_name)}
        if set(reflected_columns) != {column.name for column in table.columns}:
            raise PersistenceError("database schema is incompatible")
        for column in table.columns:
            reflected = reflected_columns[column.name]
            if (
                bool(reflected["nullable"]) != bool(column.nullable)
                or _type_signature(reflected["type"]) != _type_signature(column.type)
            ):
                raise PersistenceError("database schema is incompatible")

        reflected_primary_key = inspector.get_pk_constraint(table_name).get(
            "constrained_columns", []
        )
        expected_primary_key = [column.name for column in table.primary_key.columns]
        if reflected_primary_key != expected_primary_key:
            raise PersistenceError("database schema is incompatible")

        reflected_foreign_keys = {
            (
                tuple(item.get("constrained_columns") or ()),
                item.get("referred_table"),
                tuple(item.get("referred_columns") or ()),
                (item.get("options") or {}).get("ondelete"),
            )
            for item in inspector.get_foreign_keys(table_name)
        }
        expected_foreign_keys = {
            (
                (foreign_key.parent.name,),
                foreign_key.column.table.name,
                (foreign_key.column.name,),
                foreign_key.ondelete,
            )
            for foreign_key in table.foreign_keys
        }
        if reflected_foreign_keys != expected_foreign_keys:
            raise PersistenceError("database schema is incompatible")

        reflected_indexes = {
            (
                item["name"],
                tuple(item.get("column_names") or ()),
                bool(item.get("unique")),
            )
            for item in inspector.get_indexes(table_name)
        }
        expected_indexes = {
            (index.name, tuple(column.name for column in index.columns), bool(index.unique))
            for index in table.indexes
        }
        if reflected_indexes != expected_indexes:
            raise PersistenceError("database schema is incompatible")

        reflected_checks = {
            item.get("name"): _normalize_sql(item.get("sqltext"))
            for item in inspector.get_check_constraints(table_name)
        }
        expected_checks = {
            constraint.name: _normalize_sql(str(constraint.sqltext))
            for constraint in table.constraints
            if isinstance(constraint, SchemaCheckConstraint)
        }
        if reflected_checks != expected_checks:
            raise PersistenceError("database schema is incompatible")


def _type_signature(column_type: Any) -> tuple[str, int | None]:
    implementation = getattr(column_type, "impl", column_type)
    if isinstance(implementation, Integer):
        return ("integer", None)
    if isinstance(implementation, Float):
        return ("float", None)
    if isinstance(implementation, Text):
        return ("text", None)
    if isinstance(implementation, String):
        return ("string", implementation.length)
    return (type(implementation).__name__.lower(), None)


def _normalize_sql(value: object) -> str:
    if not isinstance(value, str):
        return ""
    return "".join(value.lower().split())


def _require_utc(value: datetime, *, message: str) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
        or value.utcoffset() != timedelta(0)
    ):
        raise PersistenceError(message)
    return value.astimezone(UTC)


def _validated_registration(registration: NodeRegistration) -> NodeRegistration:
    if not isinstance(registration, NodeRegistration):
        raise PersistenceError("node registration is invalid")
    try:
        return NodeRegistration.model_validate(registration.model_dump(mode="python"))
    except (TypeError, ValidationError, ValueError) as exc:
        raise PersistenceError("node registration is invalid") from exc


def _validated_heartbeat(heartbeat: NodeHeartbeat) -> NodeHeartbeat:
    if not isinstance(heartbeat, NodeHeartbeat):
        raise PersistenceError("node heartbeat is invalid")
    try:
        return NodeHeartbeat.model_validate(heartbeat.model_dump(mode="python"))
    except (TypeError, ValidationError, ValueError) as exc:
        raise PersistenceError("node heartbeat is invalid") from exc


def _validated_event(event: DetectionEvent) -> DetectionEvent:
    if not isinstance(event, DetectionEvent):
        raise PersistenceError("detection event is invalid")
    try:
        return DetectionEvent.model_validate(event.model_dump(mode="python"))
    except (TypeError, ValidationError, ValueError) as exc:
        raise PersistenceError("detection event is invalid") from exc


def _validated_alert(alert: SecurityAlert) -> SecurityAlert:
    if not isinstance(alert, SecurityAlert):
        raise PersistenceError("security alert is invalid")
    try:
        return SecurityAlert.model_validate(alert.model_dump(mode="python"))
    except (TypeError, ValidationError, ValueError) as exc:
        raise PersistenceError("security alert is invalid") from exc


def _serialize_detections(detections: list[Detection]) -> str:
    try:
        payload = [detection.model_dump(mode="json") for detection in detections]
        return json.dumps(
            payload,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise PersistenceError("detection metadata is invalid") from exc


def _deserialize_detections(value: str) -> list[Detection]:
    try:
        payload = json.loads(value)
        if not isinstance(payload, list):
            raise ValueError("detections must be a list")
        return [Detection.model_validate(item) for item in payload]
    except (json.JSONDecodeError, TypeError, ValidationError, ValueError) as exc:
        raise PersistenceError("stored detection event is invalid") from exc


__all__ = [
    "DetectionEventRecord",
    "NodeRecord",
    "PersistenceBase",
    "PersistenceError",
    "SecurityAlert",
    "SecurityAlertRecord",
    "SessionFactory",
    "create_session_factory",
    "create_sqlite_engine",
    "initialize_database",
    "seed_node_registry",
    "session_scope",
]
