from __future__ import annotations

import base64
import importlib
import json
from copy import deepcopy
from datetime import UTC, datetime
from typing import Any

import pytest
from secureedge.canonical import canonical_event_bytes
from secureedge.contracts import DetectionEvent, SignedDetectionEnvelope

GOLDEN_EVENT_BYTES = (
    b'{"camera_id":"cam-1","detections":[{"bbox_xyxy_norm":[0.1,0.2,0.7,0.9],'
    b'"class_id":0,"class_name":"person","confidence":0.91,"track_id":7}],'
    b'"event_id":"event-0001","frame":{"height":1080,"width":1920},"frame_seq":42,'
    b'"job_id":null,"mode":"privacy","model":{"name":"yolo26n.pt","sha256":"'
    b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},'
    b'"node_id":"edge-1","nonce":"nonce_0001","performance":{"decode_ms":1.25,'
    b'"inference_ms":12.5,"postprocess_ms":0.75},"schema_version":"1.0",'
    b'"timestamp_utc":"2026-09-13T03:15:00Z"}'
)


def _event_data(timestamp: object = "2026-09-13T03:15:00Z") -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "event_id": "event-0001",
        "node_id": "edge-1",
        "camera_id": "cam-1",
        "timestamp_utc": timestamp,
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


def _reverse_mapping_order(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _reverse_mapping_order(value[key]) for key in reversed(value)}
    if isinstance(value, list):
        return [_reverse_mapping_order(item) for item in value]
    return value


def _assert_keys_sorted(value: Any) -> None:
    if isinstance(value, dict):
        assert list(value) == sorted(value)
        for nested in value.values():
            _assert_keys_sorted(nested)
    elif isinstance(value, list):
        for nested in value:
            _assert_keys_sorted(nested)


def test_canonical_event_bytes_matches_golden_fixture() -> None:
    event = DetectionEvent.model_validate(_event_data())

    assert canonical_event_bytes(event) == GOLDEN_EVENT_BYTES


def test_canonical_output_is_recursive_sorted_compact_utf8() -> None:
    canonical = canonical_event_bytes(DetectionEvent.model_validate(_event_data()))
    decoded = json.loads(canonical.decode("utf-8"))

    _assert_keys_sorted(decoded)
    assert not canonical.startswith(b"\xef\xbb\xbf")
    assert not canonical.endswith(b"\n")
    assert b": " not in canonical
    assert b", " not in canonical


def test_equivalent_input_order_and_utc_forms_are_byte_identical() -> None:
    variants = [
        _event_data("2026-09-13T03:15:00Z"),
        _event_data("2026-09-13T03:15:00+00:00"),
        _event_data(datetime(2026, 9, 13, 3, 15, tzinfo=UTC)),
        _reverse_mapping_order(_event_data()),
    ]

    canonical_variants = {
        canonical_event_bytes(DetectionEvent.model_validate(value)) for value in variants
    }

    assert canonical_variants == {GOLDEN_EVENT_BYTES}


def test_detection_array_order_is_preserved_and_changes_signed_content() -> None:
    data = _event_data()
    second_detection = deepcopy(data["detections"][0])
    second_detection.update({"class_id": 2, "class_name": "car", "track_id": 8})
    data["detections"].append(second_detection)
    forward = canonical_event_bytes(DetectionEvent.model_validate(data))

    reversed_data = deepcopy(data)
    reversed_data["detections"].reverse()
    reversed_bytes = canonical_event_bytes(DetectionEvent.model_validate(reversed_data))

    assert forward.index(b'"person"') < forward.index(b'"car"')
    assert reversed_bytes.index(b'"car"') < reversed_bytes.index(b'"person"')
    assert forward != reversed_bytes


def test_exact_unicode_code_points_are_encoded_directly_as_utf8() -> None:
    composed = _event_data()
    composed["detections"][0]["class_name"] = "café"
    composed_bytes = canonical_event_bytes(DetectionEvent.model_validate(composed))

    decomposed = deepcopy(composed)
    decomposed["detections"][0]["class_name"] = "cafe\u0301"
    decomposed_bytes = canonical_event_bytes(DetectionEvent.model_validate(decomposed))

    assert "café".encode() in composed_bytes
    assert b"\\u00e9" not in composed_bytes
    assert composed_bytes != decomposed_bytes


def test_material_body_change_changes_canonical_bytes_without_mutation() -> None:
    event = DetectionEvent.model_validate(_event_data())
    before = event.model_dump(mode="python")
    first = canonical_event_bytes(event)
    second = canonical_event_bytes(event)

    changed_data = _event_data()
    changed_data["frame_seq"] = 43
    changed = canonical_event_bytes(DetectionEvent.model_validate(changed_data))

    assert first == second
    assert changed != first
    assert event.model_dump(mode="python") == before


def test_envelope_and_signature_fields_are_excluded_by_construction() -> None:
    event = DetectionEvent.model_validate(_event_data())
    first_signature = base64.b64encode(b"a" * 64).decode("ascii")
    second_signature = base64.b64encode(b"b" * 64).decode("ascii")
    first_envelope = SignedDetectionEnvelope(
        body=event,
        signature_algorithm="ed25519",
        signature_b64=first_signature,
    )
    second_envelope = SignedDetectionEnvelope(
        body=event,
        signature_algorithm="ed25519",
        signature_b64=second_signature,
    )

    first = canonical_event_bytes(first_envelope.body)
    second = canonical_event_bytes(second_envelope.body)

    assert first == second == GOLDEN_EVENT_BYTES
    assert b"signature" not in first
    assert b"ed25519" not in first
    assert first_signature.encode() not in first
    assert second_signature.encode() not in first

    with pytest.raises(TypeError, match="event must be a DetectionEvent"):
        canonical_event_bytes(first_envelope)  # type: ignore[arg-type]


def test_subclass_fields_cannot_extend_the_signed_body() -> None:
    class ExtendedDetectionEvent(DetectionEvent):
        signature_b64: str

    event = ExtendedDetectionEvent.model_validate(
        {**_event_data(), "signature_b64": "attacker-controlled"}
    )

    canonical = canonical_event_bytes(event)

    assert canonical == GOLDEN_EVENT_BYTES
    assert b"signature_b64" not in canonical
    assert b"attacker-controlled" not in canonical


@pytest.mark.parametrize("non_finite", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_values_fail_closed(non_finite: float) -> None:
    event = DetectionEvent.model_validate(_event_data())
    invalid_performance = event.performance.model_copy(update={"inference_ms": non_finite})
    invalid_event = event.model_copy(update={"performance": invalid_performance})

    with pytest.raises(
        ValueError,
        match="event contains a value that cannot be canonically serialized",
    ):
        canonical_event_bytes(invalid_event)


def test_unsupported_input_fails_closed() -> None:
    with pytest.raises(TypeError, match="event must be a DetectionEvent"):
        canonical_event_bytes(_event_data())  # type: ignore[arg-type]


def test_canonical_import_has_no_service_or_io_side_effects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import os
    import pathlib
    import socket
    import sqlite3
    import sys

    def fail(*args: object, **kwargs: object) -> None:
        raise AssertionError("canonical import performed an external side effect")

    real_getenv = os.getenv

    def guarded_getenv(key: str, default: str | None = None) -> str | None:
        if key.startswith("SEV_"):
            raise AssertionError("canonical import inspected SecureEdgeVision environment state")
        return real_getenv(key, default)

    unloaded = {name for name in ("cv2", "sqlalchemy", "ultralytics") if name not in sys.modules}
    monkeypatch.setattr(pathlib.Path, "read_text", fail)
    monkeypatch.setattr(os, "getenv", guarded_getenv)
    monkeypatch.setattr(socket, "socket", fail)
    monkeypatch.setattr(sqlite3, "connect", fail)

    module = importlib.import_module("secureedge.canonical")
    importlib.reload(module)

    assert unloaded.isdisjoint(sys.modules)
