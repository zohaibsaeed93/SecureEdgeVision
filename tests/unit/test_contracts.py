from __future__ import annotations

import base64
import importlib
from copy import deepcopy
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest
from pydantic import ValidationError
from secureedge.contracts import (
    DetectionEvent,
    NodeHeartbeat,
    NodeRegistration,
    SignedDetectionEnvelope,
)


def _event_data() -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "event_id": "event-0001",
        "node_id": "edge-1",
        "camera_id": "cam-1",
        "timestamp_utc": datetime(2026, 9, 13, 3, 15, tzinfo=UTC),
        "nonce": "nonce_0001",
        "frame_seq": 42,
        "job_id": None,
        "mode": "privacy",
        "model": {
            "name": "yolo26n.pt",
            "sha256": "a" * 64,
        },
        "frame": {"width": 1920, "height": 1080},
        "detections": [
            {
                "class_id": 0,
                "class_name": "person",
                "confidence": 0.91,
                "bbox_xyxy_norm": [0.1, 0.2, 0.7, 0.9],
                "track_id": 7,
            }
        ],
        "performance": {
            "decode_ms": 1.25,
            "inference_ms": 12.5,
            "postprocess_ms": 0.75,
        },
    }


def _assert_error_at(
    exc_info: pytest.ExceptionInfo[ValidationError], location: tuple[str, ...]
) -> None:
    locations = {tuple(str(part) for part in error["loc"]) for error in exc_info.value.errors()}
    assert any(candidate[: len(location)] == location for candidate in locations)


def test_detection_event_validates_and_round_trips_as_json() -> None:
    data = _event_data()
    data["timestamp_utc"] = "2026-09-13T03:15:00Z"
    event = DetectionEvent.model_validate(data)
    restored = DetectionEvent.model_validate_json(event.model_dump_json())

    assert restored == event
    assert set(event.model_dump()) == {
        "schema_version",
        "event_id",
        "node_id",
        "camera_id",
        "timestamp_utc",
        "nonce",
        "frame_seq",
        "job_id",
        "mode",
        "model",
        "frame",
        "detections",
        "performance",
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("event_id", ""),
        ("node_id", "edge node"),
        ("camera_id", "cam/1"),
        ("nonce", " nonce"),
        ("job_id", "job/unsafe"),
    ],
)
def test_rejects_blank_or_unsafe_identifiers(field: str, value: str) -> None:
    data = _event_data()
    data[field] = value

    with pytest.raises(ValidationError) as exc_info:
        DetectionEvent.model_validate(data)

    _assert_error_at(exc_info, (field,))


def test_rejects_missing_unknown_and_wrong_typed_fields() -> None:
    missing = _event_data()
    del missing["nonce"]
    with pytest.raises(ValidationError) as exc_info:
        DetectionEvent.model_validate(missing)
    _assert_error_at(exc_info, ("nonce",))

    unknown = _event_data()
    unknown["raw_frame"] = "not-allowed"
    with pytest.raises(ValidationError) as exc_info:
        DetectionEvent.model_validate(unknown)
    _assert_error_at(exc_info, ("raw_frame",))

    wrong_type = _event_data()
    wrong_type["frame_seq"] = "42"
    with pytest.raises(ValidationError) as exc_info:
        DetectionEvent.model_validate(wrong_type)
    _assert_error_at(exc_info, ("frame_seq",))


@pytest.mark.parametrize(
    "timestamp",
    [
        datetime(2026, 9, 13, 3, 15),
        datetime(2026, 9, 13, 8, 15, tzinfo=timezone(timedelta(hours=5))),
    ],
)
def test_rejects_naive_and_non_utc_event_timestamps(timestamp: datetime) -> None:
    data = _event_data()
    data["timestamp_utc"] = timestamp

    with pytest.raises(ValidationError) as exc_info:
        DetectionEvent.model_validate(data)

    _assert_error_at(exc_info, ("timestamp_utc",))


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("schema_version",), "2.0"),
        (("mode",), "benchmark"),
        (("frame_seq",), -1),
        (("model", "name"), "   "),
        (("model", "sha256"), "not-a-sha256"),
        (("frame", "width"), 0),
        (("frame", "height"), -1),
        (("performance", "decode_ms"), -0.1),
        (("performance", "inference_ms"), float("inf")),
        (("detections", "0", "class_id"), -1),
        (("detections", "0", "class_name"), "  "),
        (("detections", "0", "confidence"), 1.01),
        (("detections", "0", "track_id"), -1),
    ],
)
def test_rejects_invalid_event_boundaries(path: tuple[str, ...], value: object) -> None:
    data = deepcopy(_event_data())
    target: Any = data
    for part in path[:-1]:
        target = target[int(part)] if isinstance(target, list) else target[part]
    target[path[-1]] = value

    with pytest.raises(ValidationError) as exc_info:
        DetectionEvent.model_validate(data)

    _assert_error_at(exc_info, path)


@pytest.mark.parametrize(
    "box",
    [
        [0.1, 0.2, 0.7],
        [0.1, 0.2, 0.7, 0.9, 1.0],
        [-0.1, 0.2, 0.7, 0.9],
        [0.1, 0.2, 1.1, 0.9],
        [0.7, 0.2, 0.7, 0.9],
        [0.8, 0.2, 0.7, 0.9],
        [0.1, 0.9, 0.7, 0.9],
        [0.1, 0.95, 0.7, 0.9],
    ],
)
def test_rejects_invalid_normalized_boxes(box: list[float]) -> None:
    data = _event_data()
    data["detections"][0]["bbox_xyxy_norm"] = box

    with pytest.raises(ValidationError) as exc_info:
        DetectionEvent.model_validate(data)

    _assert_error_at(exc_info, ("detections", "0", "bbox_xyxy_norm"))


def test_node_registration_accepts_only_public_identity_material() -> None:
    public_key_b64 = base64.b64encode(b"p" * 32).decode("ascii")
    registration = NodeRegistration(node_id="edge-1", public_key_b64=public_key_b64)

    assert registration.model_dump() == {
        "node_id": "edge-1",
        "public_key_b64": public_key_b64,
    }

    with pytest.raises(ValidationError) as exc_info:
        NodeRegistration.model_validate(
            {
                "node_id": "edge-1",
                "public_key_b64": public_key_b64,
                "private_key_b64": "forbidden",
            }
        )
    _assert_error_at(exc_info, ("private_key_b64",))


@pytest.mark.parametrize(
    "public_key_b64",
    ["not base64", base64.b64encode(b"short").decode("ascii"), "A" * 42 + "B="],
)
def test_node_registration_rejects_malformed_public_keys(public_key_b64: str) -> None:
    with pytest.raises(ValidationError) as exc_info:
        NodeRegistration(node_id="edge-1", public_key_b64=public_key_b64)

    _assert_error_at(exc_info, ("public_key_b64",))


@pytest.mark.parametrize("status", ["healthy", "degraded", "unhealthy"])
def test_heartbeat_has_minimal_typed_health_shape(status: str) -> None:
    heartbeat = NodeHeartbeat(
        node_id="edge-1",
        timestamp_utc="2026-09-13T03:15:00Z",  # type: ignore[arg-type]
        status=status,  # type: ignore[arg-type]
    )

    assert set(heartbeat.model_dump()) == {"node_id", "timestamp_utc", "status"}


def test_heartbeat_rejects_invalid_status_timestamp_and_raw_data() -> None:
    valid = {
        "node_id": "edge-1",
        "timestamp_utc": datetime(2026, 9, 13, 3, 15, tzinfo=UTC),
        "status": "healthy",
    }
    for field, value in (
        ("status", "offline"),
        ("timestamp_utc", datetime(2026, 9, 13, 3, 15)),
        ("image_bytes", "forbidden"),
    ):
        data = valid | {field: value}
        with pytest.raises(ValidationError) as exc_info:
            NodeHeartbeat.model_validate(data)
        _assert_error_at(exc_info, (field,))


def test_signed_envelope_validates_exact_shape_and_round_trips() -> None:
    signature_b64 = base64.b64encode(b"s" * 64).decode("ascii")
    envelope = SignedDetectionEnvelope.model_validate(
        {
            "body": _event_data(),
            "signature_algorithm": "ed25519",
            "signature_b64": signature_b64,
        }
    )

    restored = SignedDetectionEnvelope.model_validate_json(envelope.model_dump_json())
    assert restored == envelope
    assert set(envelope.model_dump()) == {
        "body",
        "signature_algorithm",
        "signature_b64",
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("signature_algorithm", "rsa"),
        ("signature_b64", "not base64"),
        ("signature_b64", base64.b64encode(b"short").decode("ascii")),
    ],
)
def test_signed_envelope_rejects_invalid_algorithm_or_signature(field: str, value: str) -> None:
    data = {
        "body": _event_data(),
        "signature_algorithm": "ed25519",
        "signature_b64": base64.b64encode(b"s" * 64).decode("ascii"),
    }
    data[field] = value

    with pytest.raises(ValidationError) as exc_info:
        SignedDetectionEnvelope.model_validate(data)

    _assert_error_at(exc_info, (field,))


def test_contract_import_has_no_service_or_io_side_effects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import os
    import pathlib
    import socket
    import sqlite3
    import sys

    def fail(*args: object, **kwargs: object) -> None:
        raise AssertionError("contract import performed an external side effect")

    real_getenv = os.getenv

    def guarded_getenv(key: str, default: str | None = None) -> str | None:
        if key.startswith("SEV_"):
            raise AssertionError("contract import inspected SecureEdgeVision environment state")
        return real_getenv(key, default)

    unloaded = {name for name in ("cv2", "sqlalchemy", "ultralytics") if name not in sys.modules}
    monkeypatch.setattr(pathlib.Path, "read_text", fail)
    monkeypatch.setattr(os, "getenv", guarded_getenv)
    monkeypatch.setattr(socket, "socket", fail)
    monkeypatch.setattr(sqlite3, "connect", fail)

    module = importlib.import_module("secureedge.contracts")
    importlib.reload(module)

    assert unloaded.isdisjoint(sys.modules)
