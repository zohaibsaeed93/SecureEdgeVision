from __future__ import annotations

import importlib
import json
import pathlib
import socket
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from secureedge.contracts import DetectionEvent, NodeHeartbeat, SignedDetectionEnvelope
from secureedge.crypto import generate_private_key, verify_detection_envelope
from secureedge.transport import (
    DETECTION_PATH,
    HEARTBEAT_PATH,
    HeartbeatError,
    SignedWorkerTransport,
    TransportError,
    WorkerHeartbeatLifecycle,
)


def _event() -> DetectionEvent:
    return DetectionEvent.model_validate(
        {
            "schema_version": "1.0",
            "event_id": "event-transport-1",
            "node_id": "edge-1",
            "camera_id": "cam-1",
            "timestamp_utc": datetime(2026, 9, 16, 6, 0, tzinfo=UTC),
            "nonce": "nonce-transport-1",
            "frame_seq": 0,
            "job_id": None,
            "mode": "privacy",
            "model": {"name": "yolo26n.pt", "sha256": "a" * 64},
            "frame": {"width": 20, "height": 10},
            "detections": [
                {
                    "class_id": 0,
                    "class_name": "person",
                    "confidence": 0.9,
                    "bbox_xyxy_norm": [0.1, 0.2, 0.8, 0.9],
                    "track_id": None,
                }
            ],
            "performance": {
                "decode_ms": 1.0,
                "inference_ms": 2.0,
                "postprocess_ms": 0.5,
            },
        }
    )


def test_transport_signs_exact_event_and_sends_only_wire_metadata() -> None:
    private_key = generate_private_key()
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(202, request=request)

    client = SignedWorkerTransport(
        "http://aggregator:8000",
        5.0,
        private_key,
        transport=httpx.MockTransport(handler),
    )
    heartbeat = NodeHeartbeat(
        node_id="edge-1",
        timestamp_utc=datetime(2026, 9, 16, 6, 0, 10, tzinfo=UTC),
        status="healthy",
    )

    with client:
        client.send_detection(_event())
        client.send_heartbeat(heartbeat)

    assert [(request.method, request.url.path) for request in requests] == [
        ("POST", DETECTION_PATH),
        ("POST", HEARTBEAT_PATH),
    ]
    envelope_payload = json.loads(requests[0].content)
    envelope = SignedDetectionEnvelope.model_validate(envelope_payload)
    assert envelope.body == _event()
    assert verify_detection_envelope(envelope, private_key.public_key()) is True
    assert json.loads(requests[1].content) == heartbeat.model_dump(mode="json")

    serialized = b"".join(request.content for request in requests).lower()
    for forbidden in (
        b"pixels",
        b"image_bytes",
        b"crop",
        b"tensor",
        b"private key",
        b"public_key",
        b"source_path",
    ):
        assert forbidden not in serialized


@pytest.mark.parametrize("mode", ["unexpected", "redirect", "connect", "timeout"])
def test_transport_fails_closed_once_without_leaking_response_or_exception(
    mode: str,
) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if mode == "connect":
            raise httpx.ConnectError("secret-host-detail", request=request)
        if mode == "timeout":
            raise httpx.ReadTimeout("secret-timeout-detail", request=request)
        if mode == "redirect":
            return httpx.Response(
                307,
                headers={"location": "https://secret.example.test/redirect"},
                request=request,
            )
        return httpx.Response(500, text="secret response body", request=request)

    transport = SignedWorkerTransport(
        "http://aggregator:8000/",
        2.0,
        generate_private_key(),
        transport=httpx.MockTransport(handler),
    )

    with transport, pytest.raises(TransportError) as exc_info:
        transport.send_detection(_event())

    assert len(requests) == 1
    assert str(exc_info.value) == "detection delivery failed"
    assert "secret" not in str(exc_info.value)


def test_transport_requires_explicit_open_and_rejects_unsafe_origin() -> None:
    transport = SignedWorkerTransport(
        "http://aggregator:8000",
        1.0,
        generate_private_key(),
        transport=httpx.MockTransport(lambda request: httpx.Response(202, request=request)),
    )
    with pytest.raises(TransportError, match="not open"):
        transport.send_detection(_event())

    for url in (
        "http://user:secret@aggregator:8000",
        "http://aggregator:8000/base",
        "http://aggregator:8000?token=secret",
        "ftp://aggregator",
    ):
        with pytest.raises(TransportError, match="origin"):
            SignedWorkerTransport(url, 1.0, generate_private_key())


class RecordingHeartbeatTransport:
    def __init__(self, *, fail_after: int | None = None) -> None:
        self.heartbeats: list[NodeHeartbeat] = []
        self.fail_after = fail_after

    def send_heartbeat(self, heartbeat: NodeHeartbeat) -> None:
        self.heartbeats.append(heartbeat)
        if self.fail_after is not None and len(self.heartbeats) >= self.fail_after:
            raise TransportError("sensitive heartbeat failure")


class InlineThread:
    def __init__(self, target: Callable[[], None]) -> None:
        self._target = target

    def start(self) -> None:
        self._target()

    def join(self, timeout: float | None = None) -> None:
        return None


class WaitSequence:
    def __init__(self, values: list[bool]) -> None:
        self._values = iter(values)
        self.intervals: list[float] = []

    def __call__(self, interval: float) -> bool:
        self.intervals.append(interval)
        return next(self._values)


class MonotonicSequence:
    def __init__(self, values: list[float]) -> None:
        self._values = iter(values)

    def __call__(self) -> float:
        return next(self._values)


def test_heartbeat_initial_and_interval_delivery_need_no_sleep_or_detection() -> None:
    transport = RecordingHeartbeatTransport()
    timestamps = iter(
        [
            datetime(2026, 9, 16, 6, 0, tzinfo=UTC),
            datetime(2026, 9, 16, 6, 0, 10, tzinfo=UTC),
        ]
    )
    waits = WaitSequence([False, True])
    lifecycle = WorkerHeartbeatLifecycle(
        transport,  # type: ignore[arg-type]
        "edge-1",
        10.0,
        utc_clock=lambda: next(timestamps),
        monotonic_clock=MonotonicSequence([0.0, 10.0]),
        wait_function=waits,
        thread_factory=InlineThread,
    )

    with lifecycle:
        lifecycle.check()

    assert [item.status for item in transport.heartbeats] == ["healthy", "healthy"]
    assert [item.timestamp_utc.second for item in transport.heartbeats] == [0, 10]
    assert waits.intervals == [10.0, 10.0]


def test_degraded_heartbeat_is_best_effort_and_sent_at_most_once() -> None:
    transport = RecordingHeartbeatTransport()
    lifecycle = WorkerHeartbeatLifecycle(
        transport,  # type: ignore[arg-type]
        "edge-1",
        10.0,
        utc_clock=lambda: datetime(2026, 9, 16, 6, 0, tzinfo=UTC),
        monotonic_clock=MonotonicSequence([0.0]),
        wait_function=WaitSequence([True]),
        thread_factory=InlineThread,
    )

    with lifecycle:
        pass
    lifecycle.best_effort_degraded()
    lifecycle.best_effort_degraded()

    assert [item.status for item in transport.heartbeats] == ["healthy", "degraded"]


def test_heartbeat_failure_is_sanitized_and_stops_processing() -> None:
    transport = RecordingHeartbeatTransport(fail_after=2)
    waits = WaitSequence([False])
    lifecycle = WorkerHeartbeatLifecycle(
        transport,  # type: ignore[arg-type]
        "edge-1",
        5.0,
        utc_clock=lambda: datetime(2026, 9, 16, 6, 0, tzinfo=UTC),
        monotonic_clock=MonotonicSequence([0.0, 5.0]),
        wait_function=waits,
        thread_factory=InlineThread,
    )

    with pytest.raises(HeartbeatError) as exc_info:
        lifecycle.__enter__()

    assert str(exc_info.value) == "heartbeat activity failed"
    assert "sensitive" not in str(exc_info.value)
    assert len(transport.heartbeats) == 2


def test_transport_import_has_no_runtime_side_effects(monkeypatch: pytest.MonkeyPatch) -> None:
    module = importlib.import_module("secureedge.transport")

    def fail(*_args: object, **_kwargs: object) -> Any:
        raise AssertionError("transport import performed a runtime side effect")

    monkeypatch.setattr(pathlib.Path, "read_bytes", fail)
    monkeypatch.setattr(socket, "socket", fail)
    monkeypatch.setattr(httpx.Client, "__init__", fail)
    monkeypatch.setattr(threading.Thread, "start", fail)

    module = importlib.reload(module)

    assert module.__name__ == "secureedge.transport"
