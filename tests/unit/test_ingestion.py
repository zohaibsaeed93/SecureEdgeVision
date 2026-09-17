from __future__ import annotations

import asyncio
import base64
import json
import pathlib
import subprocess
import sys
from collections.abc import AsyncIterator, Callable, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from apps.aggregator import main as aggregator_main
from apps.aggregator.api import (
    DETECTION_INGEST_PATH,
    _read_bounded_body,
    _RequestFailure,
    create_app,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import Request
from secureedge.canonical import canonical_event_bytes
from secureedge.config import SecuritySettings
from secureedge.contracts import DetectionEvent, NodeRegistration, SignedDetectionEnvelope
from secureedge.crypto import encode_public_key
from secureedge.ingestion import DetectionEventIngestor
from secureedge.persistence import (
    DetectionEventRecord,
    NodeRecord,
    SecurityAlertRecord,
    create_session_factory,
    create_sqlite_engine,
    initialize_database,
    seed_node_registry,
)
from secureedge.security import ReplayFreshnessPolicy
from sqlalchemy import Engine, func, select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

NOW = datetime(2026, 9, 17, 11, 0, tzinfo=UTC)


@pytest.fixture
def private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture
def settings() -> SecuritySettings:
    return SecuritySettings(
        max_clock_skew_seconds=30,
        nonce_ttl_seconds=300,
        max_request_bytes=1024,
    )


@pytest.fixture
def engine(tmp_path: pathlib.Path) -> Iterator[Engine]:
    value = create_sqlite_engine(f"sqlite:///{tmp_path / 'ingestion.sqlite3'}")
    initialize_database(value)
    yield value
    value.dispose()


@pytest.fixture
def session_factory(engine: Engine) -> Callable[[], Session]:
    return create_session_factory(engine)


def _registration(
    private_key: Ed25519PrivateKey,
    *,
    node_id: str = "edge-1",
) -> NodeRegistration:
    return NodeRegistration(
        node_id=node_id,
        public_key_b64=encode_public_key(private_key.public_key()),
    )


def _event(
    *,
    node_id: str = "edge-1",
    event_id: str = "event-1",
    nonce: str = "nonce-1",
    timestamp: datetime = NOW,
    detections: list[dict[str, Any]] | None = None,
    job_id: str | None = "job-1",
) -> DetectionEvent:
    if detections is None:
        detections = [
            {
                "class_id": 0,
                "class_name": "person",
                "confidence": 0.91,
                "bbox_xyxy_norm": [0.1, 0.2, 0.7, 0.9],
                "track_id": None,
            }
        ]
    return DetectionEvent.model_validate(
        {
            "schema_version": "1.0",
            "event_id": event_id,
            "node_id": node_id,
            "camera_id": "cam-1",
            "timestamp_utc": timestamp,
            "nonce": nonce,
            "frame_seq": 7,
            "job_id": job_id,
            "mode": "privacy",
            "model": {"name": "yolo26n.pt", "sha256": "a" * 64},
            "frame": {"width": 1280, "height": 720},
            "detections": detections,
            "performance": {
                "decode_ms": 1.0,
                "inference_ms": 9.5,
                "postprocess_ms": 0.5,
            },
        }
    )


def _body(envelope: SignedDetectionEnvelope) -> bytes:
    return envelope.model_dump_json().encode("utf-8")


def _sign(
    event: DetectionEvent,
    private_key: Ed25519PrivateKey,
) -> SignedDetectionEnvelope:
    signature = private_key.sign(canonical_event_bytes(event))
    return SignedDetectionEnvelope(
        body=event,
        signature_algorithm="ed25519",
        signature_b64=base64.b64encode(signature).decode("ascii"),
    )


def _app(
    settings: SecuritySettings,
    session_factory: Callable[[], Session],
    *,
    clock: Callable[[], datetime] = lambda: NOW,
) -> Any:
    policy = ReplayFreshnessPolicy(settings, clock=clock)
    return create_app(
        security_settings=settings,
        session_factory=session_factory,  # type: ignore[arg-type]
        replay_policy=policy,
    )


async def _post(app: Any, content: bytes, headers: dict[str, str] | None = None) -> httpx.Response:
    actual_headers = {"content-type": "application/json"}
    if headers:
        actual_headers.update(headers)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        return await client.post(DETECTION_INGEST_PATH, content=content, headers=actual_headers)


def _row_counts(session_factory: Callable[[], Session]) -> tuple[int, int]:
    with session_factory() as session:
        return (
            session.scalar(select(func.count()).select_from(DetectionEventRecord)) or 0,
            session.scalar(select(func.count()).select_from(SecurityAlertRecord)) or 0,
        )


@pytest.mark.asyncio
async def test_valid_event_returns_empty_202_after_lossless_commit(
    private_key: Ed25519PrivateKey,
    settings: SecuritySettings,
    session_factory: Callable[[], Session],
) -> None:
    seed_node_registry(
        session_factory,  # type: ignore[arg-type]
        [_registration(private_key)],
        registered_at_utc=NOW,
    )
    event = _event()
    response = await _post(
        _app(settings, session_factory),
        _body(_sign(event, private_key)),
    )

    assert response.status_code == 202
    assert response.content == b""
    with session_factory() as session:
        record = session.scalar(select(DetectionEventRecord))
        assert record is not None
        assert record.to_event() == event
        assert record.accepted_at_utc == NOW
    assert _row_counts(session_factory) == (1, 0)


@pytest.mark.asyncio
async def test_empty_detections_and_nullable_job_are_accepted(
    private_key: Ed25519PrivateKey,
    settings: SecuritySettings,
    session_factory: Callable[[], Session],
) -> None:
    seed_node_registry(
        session_factory,  # type: ignore[arg-type]
        [_registration(private_key)],
        registered_at_utc=NOW,
    )
    event = _event(detections=[], job_id=None)
    response = await _post(
        _app(settings, session_factory),
        _body(_sign(event, private_key)),
    )
    assert response.status_code == 202
    with session_factory() as session:
        assert session.scalar(select(DetectionEventRecord)).to_event() == event  # type: ignore[union-attr]


@pytest.mark.asyncio
async def test_unknown_node_and_tampered_signature_fail_without_rows(
    private_key: Ed25519PrivateKey,
    settings: SecuritySettings,
    session_factory: Callable[[], Session],
) -> None:
    app = _app(settings, session_factory)
    unknown = _sign(_event(), private_key)
    response = await _post(app, _body(unknown))
    assert response.status_code == 401
    assert response.json() == {"detail": {"code": "unknown_node"}}

    seed_node_registry(
        session_factory,  # type: ignore[arg-type]
        [_registration(private_key)],
        registered_at_utc=NOW,
    )
    signed = _sign(_event(), private_key)
    tampered = signed.model_copy(
        update={"body": signed.body.model_copy(update={"frame_seq": 8})}
    )
    response = await _post(app, _body(tampered))
    assert response.status_code == 401
    assert response.json() == {"detail": {"code": "invalid_signature"}}
    assert _row_counts(session_factory) == (0, 0)


@pytest.mark.asyncio
async def test_invalid_signature_does_not_reserve_replay_identifiers(
    private_key: Ed25519PrivateKey,
    settings: SecuritySettings,
    session_factory: Callable[[], Session],
) -> None:
    seed_node_registry(
        session_factory,  # type: ignore[arg-type]
        [_registration(private_key)],
        registered_at_utc=NOW,
    )
    event = _event()
    valid = _sign(event, private_key)
    other_key = Ed25519PrivateKey.generate()
    invalid = _sign(event, other_key)
    app = _app(settings, session_factory)

    assert (await _post(app, _body(invalid))).status_code == 401
    assert (await _post(app, _body(valid))).status_code == 202
    assert _row_counts(session_factory) == (1, 0)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("second", "reason"),
    [
        (_event(nonce="nonce-2"), "replayed_event_id"),
        (_event(event_id="event-2"), "replayed_nonce"),
    ],
)
async def test_replay_is_node_scoped_and_returns_409(
    private_key: Ed25519PrivateKey,
    settings: SecuritySettings,
    session_factory: Callable[[], Session],
    second: DetectionEvent,
    reason: str,
) -> None:
    seed_node_registry(
        session_factory,  # type: ignore[arg-type]
        [_registration(private_key)],
        registered_at_utc=NOW,
    )
    app = _app(settings, session_factory)
    assert (await _post(app, _body(_sign(_event(), private_key)))).status_code == 202
    response = await _post(app, _body(_sign(second, private_key)))
    assert response.status_code == 409
    assert response.json() == {"detail": {"code": reason}}
    assert _row_counts(session_factory) == (1, 0)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("timestamp", "reason"),
    [
        (NOW - timedelta(seconds=31), "stale_timestamp"),
        (NOW + timedelta(seconds=31), "future_timestamp"),
    ],
)
async def test_freshness_failures_return_409(
    private_key: Ed25519PrivateKey,
    settings: SecuritySettings,
    session_factory: Callable[[], Session],
    timestamp: datetime,
    reason: str,
) -> None:
    seed_node_registry(
        session_factory,  # type: ignore[arg-type]
        [_registration(private_key)],
        registered_at_utc=NOW,
    )
    response = await _post(
        _app(settings, session_factory),
        _body(_sign(_event(timestamp=timestamp), private_key)),
    )
    assert response.status_code == 409
    assert response.json() == {"detail": {"code": reason}}
    assert _row_counts(session_factory) == (0, 0)


@pytest.mark.asyncio
async def test_same_replay_identifiers_are_allowed_for_different_nodes(
    private_key: Ed25519PrivateKey,
    settings: SecuritySettings,
    session_factory: Callable[[], Session],
) -> None:
    second_key = Ed25519PrivateKey.generate()
    seed_node_registry(
        session_factory,  # type: ignore[arg-type]
        [_registration(private_key), _registration(second_key, node_id="edge-2")],
        registered_at_utc=NOW,
    )
    app = _app(settings, session_factory)
    first = _sign(_event(), private_key)
    second = _sign(_event(node_id="edge-2"), second_key)
    assert (await _post(app, _body(first))).status_code == 202
    assert (await _post(app, _body(second))).status_code == 202
    assert _row_counts(session_factory) == (2, 0)


@pytest.mark.asyncio
async def test_concurrent_duplicates_commit_at_most_once(
    private_key: Ed25519PrivateKey,
    settings: SecuritySettings,
    session_factory: Callable[[], Session],
) -> None:
    seed_node_registry(
        session_factory,  # type: ignore[arg-type]
        [_registration(private_key)],
        registered_at_utc=NOW,
    )
    app = _app(settings, session_factory)
    payload = _body(_sign(_event(), private_key))
    responses = await asyncio.gather(_post(app, payload), _post(app, payload))
    assert sorted(response.status_code for response in responses) == [202, 409]
    assert _row_counts(session_factory) == (1, 0)


@pytest.mark.asyncio
async def test_declared_and_streamed_oversize_return_413_without_rows(
    private_key: Ed25519PrivateKey,
    settings: SecuritySettings,
    session_factory: Callable[[], Session],
) -> None:
    seed_node_registry(
        session_factory,  # type: ignore[arg-type]
        [_registration(private_key)],
        registered_at_utc=NOW,
    )
    app = _app(settings, session_factory)
    declared = await _post(app, b"{}", {"content-length": "1025"})
    streamed = await _post(app, b"{" + b"x" * 1024, {"content-length": "1"})
    assert declared.status_code == 413
    assert streamed.status_code == 413
    assert declared.json() == {"detail": {"code": "request_too_large"}}
    assert _row_counts(session_factory) == (0, 0)


@pytest.mark.asyncio
async def test_pathological_content_length_is_bounded_without_large_int_conversion(
    settings: SecuritySettings,
    session_factory: Callable[[], Session],
) -> None:
    app = _app(settings, session_factory)
    excessive_digits = await _post(app, b"{}", {"content-length": "9" * 5000})
    leading_zero_oversize = await _post(
        app,
        b"{}",
        {"content-length": ("0" * 5000) + "1025"},
    )
    leading_zero_match = await _post(
        app,
        b"{}",
        {"content-length": ("0" * 5000) + "2"},
    )

    assert excessive_digits.status_code == 413
    assert leading_zero_oversize.status_code == 413
    assert leading_zero_match.status_code == 422
    assert excessive_digits.json() == {"detail": {"code": "request_too_large"}}
    assert leading_zero_oversize.json() == {"detail": {"code": "request_too_large"}}
    assert leading_zero_match.json() == {"detail": {"code": "invalid_request"}}
    assert _row_counts(session_factory) == (0, 0)


@pytest.mark.asyncio
async def test_bounded_reader_stops_requesting_chunks_after_limit() -> None:
    chunks = iter([b"a" * 600, b"b" * 600, b"must-not-be-read"])
    calls = 0

    async def receive() -> dict[str, Any]:
        nonlocal calls
        calls += 1
        chunk = next(chunks)
        return {"type": "http.request", "body": chunk, "more_body": True}

    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": DETECTION_INGEST_PATH,
            "headers": [],
        },
        receive,
    )
    with pytest.raises(_RequestFailure) as captured:
        await _read_bounded_body(request, maximum=1024)
    assert captured.value.status_code == 413
    assert calls == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("content", "headers"),
    [
        (b"{", None),
        (b'{"body":{},"body":{}}', None),
        (b'{"value":NaN}', None),
        (b'{"value":1e9999}', None),
        (b"{}", {"content-type": "text/plain"}),
        (b"{}", {"content-length": "bogus"}),
        (b"{}", {"content-length": "1"}),
    ],
)
async def test_malformed_requests_are_sanitized_422(
    settings: SecuritySettings,
    session_factory: Callable[[], Session],
    content: bytes,
    headers: dict[str, str] | None,
) -> None:
    response = await _post(_app(settings, session_factory), content, headers)
    assert response.status_code == 422
    assert response.json() == {"detail": {"code": "invalid_request"}}
    if len(content) > 4:
        assert content.decode("utf-8", errors="ignore") not in response.text
    assert _row_counts(session_factory) == (0, 0)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mutate",),
    [
        (lambda value: value["body"].__setitem__("raw_frame", "pixels"),),
        (lambda value: value["body"].__setitem__("timestamp_utc", "2026-09-17T11:00:00+01:00"),),
        (lambda value: value.__setitem__("signature_b64", "not-base64"),),
        (lambda value: value["body"].__setitem__("mode", "benchmark"),),
    ],
)
async def test_contract_violations_stop_before_authentication(
    private_key: Ed25519PrivateKey,
    settings: SecuritySettings,
    session_factory: Callable[[], Session],
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    seed_node_registry(
        session_factory,  # type: ignore[arg-type]
        [_registration(private_key)],
        registered_at_utc=NOW,
    )
    value = _sign(_event(), private_key).model_dump(mode="json")
    mutate(value)
    response = await _post(
        _app(settings, session_factory),
        json.dumps(value, separators=(",", ":")).encode(),
    )
    assert response.status_code == 422
    assert _row_counts(session_factory) == (0, 0)


@pytest.mark.asyncio
async def test_corrupt_registry_record_returns_sanitized_503(
    private_key: Ed25519PrivateKey,
    settings: SecuritySettings,
    session_factory: Callable[[], Session],
) -> None:
    seed_node_registry(
        session_factory,  # type: ignore[arg-type]
        [_registration(private_key)],
        registered_at_utc=NOW,
    )
    with session_factory() as session:
        session.execute(
            update(NodeRecord).where(NodeRecord.node_id == "edge-1").values(public_key_b64="bad")
        )
        session.commit()

    response = await _post(
        _app(settings, session_factory),
        _body(_sign(_event(), private_key)),
    )
    assert response.status_code == 503
    assert response.json() == {"detail": {"code": "service_unavailable"}}
    assert "bad" not in response.text
    assert _row_counts(session_factory) == (0, 0)


class _FailingCommitSession:
    def __init__(self, session: Session) -> None:
        self._session = session

    def get(self, *args: Any, **kwargs: Any) -> Any:
        return self._session.get(*args, **kwargs)

    def add(self, value: object) -> None:
        self._session.add(value)

    def commit(self) -> None:
        raise SQLAlchemyError("secret database path")

    def rollback(self) -> None:
        self._session.rollback()

    def close(self) -> None:
        self._session.close()


@pytest.mark.asyncio
async def test_commit_failure_is_sanitized_and_keeps_replay_reservation(
    private_key: Ed25519PrivateKey,
    settings: SecuritySettings,
    session_factory: Callable[[], Session],
) -> None:
    seed_node_registry(
        session_factory,  # type: ignore[arg-type]
        [_registration(private_key)],
        registered_at_utc=NOW,
    )
    policy = ReplayFreshnessPolicy(settings, clock=lambda: NOW)
    def failing_factory() -> _FailingCommitSession:
        return _FailingCommitSession(session_factory())
    failing_app = create_app(
        security_settings=settings,
        session_factory=failing_factory,  # type: ignore[arg-type]
        replay_policy=policy,
    )
    payload = _body(_sign(_event(), private_key))

    failure = await _post(failing_app, payload)
    assert failure.status_code == 503
    assert failure.json() == {"detail": {"code": "service_unavailable"}}
    assert "secret" not in failure.text
    assert _row_counts(session_factory) == (0, 0)

    healthy_app = create_app(
        security_settings=settings,
        session_factory=session_factory,  # type: ignore[arg-type]
        replay_policy=policy,
    )
    replay = await _post(healthy_app, payload)
    assert replay.status_code == 409
    assert replay.json() == {"detail": {"code": "replayed_event_id"}}
    assert _row_counts(session_factory) == (0, 0)


def test_app_has_one_route_and_one_process_owned_policy(
    settings: SecuritySettings,
    session_factory: Callable[[], Session],
) -> None:
    app = _app(settings, session_factory)
    assert [(route.path, sorted(route.methods or [])) for route in app.routes] == [
        (DETECTION_INGEST_PATH, ["POST"])
    ]
    assert isinstance(app.state.replay_policy, ReplayFreshnessPolicy)
    assert isinstance(app.state.ingestor, DetectionEventIngestor)


def test_aggregator_imports_have_no_runtime_side_effects() -> None:
    script = """
import os
import importlib
import pathlib
import socket
import sqlalchemy
import sys
import uvicorn

import apps.aggregator.api
import apps.aggregator.main

def fail(*args, **kwargs):
    raise AssertionError("aggregator import performed a runtime side effect")

real_getenv = os.getenv
def guarded_getenv(key, default=None):
    if key.startswith("SEV_"):
        raise AssertionError("aggregator import inspected application environment")
    return real_getenv(key, default)

os.getenv = guarded_getenv
pathlib.Path.read_text = fail
socket.socket = fail
sqlalchemy.create_engine = fail
uvicorn.run = fail

del sys.modules["apps.aggregator.api"]
del sys.modules["apps.aggregator.main"]
importlib.import_module("apps.aggregator.api")
importlib.import_module("apps.aggregator.main")
assert apps.aggregator.api.DETECTION_INGEST_PATH == "/v1/events/detections"
"""
    subprocess.run([sys.executable, "-c", script], check=True)


@pytest.mark.asyncio
async def test_chunked_request_without_length_is_accepted(
    private_key: Ed25519PrivateKey,
    settings: SecuritySettings,
    session_factory: Callable[[], Session],
) -> None:
    seed_node_registry(
        session_factory,  # type: ignore[arg-type]
        [_registration(private_key)],
        registered_at_utc=NOW,
    )
    payload = _body(_sign(_event(), private_key))

    async def pieces() -> AsyncIterator[bytes]:
        yield payload[:50]
        yield payload[50:]

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_app(settings, session_factory)),
        base_url="http://test",
    ) as client:
        response = await client.post(
            DETECTION_INGEST_PATH,
            content=pieces(),
            headers={"content-type": "application/json"},
        )
    assert response.status_code == 202


def test_runtime_explicitly_initializes_and_seeds_public_registry(
    tmp_path: pathlib.Path,
    private_key: Ed25519PrivateKey,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_path = tmp_path / "runtime.sqlite3"
    calls: list[tuple[Any, str, int, int]] = []

    def fake_run(app: Any, *, host: str, port: int, workers: int) -> None:
        calls.append((app, host, port, workers))

    monkeypatch.setattr(aggregator_main.uvicorn, "run", fake_run)
    public_key = encode_public_key(private_key.public_key())
    result = aggregator_main.main(
        [
            "--config",
            "config/system.yaml",
            "--database-url",
            f"sqlite:///{database_path}",
            "--node-public-key",
            f"edge-1={public_key}",
        ]
    )

    assert result == 0
    assert len(calls) == 1
    app, host, port, workers = calls[0]
    assert host == "0.0.0.0"
    assert port == 8000
    assert workers == 1
    assert isinstance(app.state.replay_policy, ReplayFreshnessPolicy)

    runtime_engine = create_sqlite_engine(f"sqlite:///{database_path}")
    try:
        with create_session_factory(runtime_engine)() as session:
            assert session.get(NodeRecord, "edge-1").to_registration() == _registration(  # type: ignore[union-attr]
                private_key
            )
    finally:
        runtime_engine.dispose()


def test_runtime_failure_is_sanitized(
    tmp_path: pathlib.Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    result = aggregator_main.main(
        [
            "--config",
            "config/system.yaml",
            "--database-url",
            f"sqlite:///{tmp_path / 'missing' / 'secret.sqlite3'}",
        ]
    )
    assert result == 2
    assert capsys.readouterr().out == "SecureEdgeVision aggregator startup failed.\n"
