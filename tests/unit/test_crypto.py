from __future__ import annotations

import base64
from datetime import UTC, datetime
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat
from secureedge.contracts import DetectionEvent, SignedDetectionEnvelope
from secureedge.crypto import (
    KeyMaterialError,
    encode_public_key,
    generate_private_key,
    load_private_key,
    load_public_key,
    serialize_private_key,
    sign_detection_event,
    verify_detection_envelope,
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
        "model": {"name": "yolo26n.pt", "sha256": "a" * 64},
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
        "performance": {"decode_ms": 1.25, "inference_ms": 12.5, "postprocess_ms": 0.75},
    }


def _event() -> DetectionEvent:
    return DetectionEvent.model_validate(_event_data())


def test_public_key_round_trip_has_exact_raw_base64_shape() -> None:
    private_key = generate_private_key()
    public_key_b64 = encode_public_key(private_key.public_key())

    assert len(public_key_b64) == 44
    assert base64.b64decode(public_key_b64, validate=True) == private_key.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )
    restored = load_public_key(public_key_b64)
    assert restored.public_bytes(Encoding.Raw, PublicFormat.Raw) == base64.b64decode(
        public_key_b64, validate=True
    )


@pytest.mark.parametrize(
    "public_key_b64",
    [
        "not base64",
        base64.b64encode(b"short").decode("ascii"),
        base64.b64encode(b"p" * 32).decode("ascii").rstrip("=") + "==",
    ],
)
def test_public_key_loader_rejects_malformed_or_noncanonical_base64(public_key_b64: str) -> None:
    with pytest.raises(KeyMaterialError, match="public key"):
        load_public_key(public_key_b64)


def test_private_key_round_trip_uses_unencrypted_pkcs8_pem() -> None:
    private_key = generate_private_key()
    pem = serialize_private_key(private_key)

    assert pem.startswith(b"-----BEGIN PRIVATE KEY-----")
    restored = load_private_key(pem)
    assert restored.private_bytes(
        Encoding.Raw, PrivateFormat.Raw, serialization.NoEncryption()
    ) == private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, serialization.NoEncryption())


@pytest.mark.parametrize(
    "pem_data",
    [b"not a private key", b"-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----"],
)
def test_private_key_loader_fails_closed_without_leaking_material(pem_data: bytes) -> None:
    with pytest.raises(KeyMaterialError, match="private key material") as exc_info:
        load_private_key(pem_data)
    assert "not a private key" not in str(exc_info.value)


def test_private_key_loader_rejects_wrong_algorithm_and_encrypted_pem() -> None:
    ec_key = ec.generate_private_key(ec.SECP256R1())
    ec_pem = ec_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, serialization.NoEncryption())
    with pytest.raises(KeyMaterialError, match="Ed25519"):
        load_private_key(ec_pem)

    encrypted_pem = generate_private_key().private_bytes(
        Encoding.PEM,
        PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"test-password"),
    )
    with pytest.raises(KeyMaterialError, match="private key material"):
        load_private_key(encrypted_pem)


def test_signing_is_deterministic_and_verification_accepts_the_exact_body() -> None:
    private_key = generate_private_key()
    event = _event()

    first = sign_detection_event(event, private_key)
    second = sign_detection_event(event, private_key)

    assert first == second
    assert first.signature_algorithm == "ed25519"
    assert len(base64.b64decode(first.signature_b64, validate=True)) == 64
    assert verify_detection_envelope(first, private_key.public_key()) is True
    assert b"PRIVATE KEY" not in first.model_dump_json().encode("utf-8")


def test_wrong_key_tampered_body_and_changed_signature_are_rejected() -> None:
    private_key = generate_private_key()
    envelope = sign_detection_event(_event(), private_key)

    assert verify_detection_envelope(envelope, generate_private_key().public_key()) is False

    changed_event = _event().model_copy(update={"frame_seq": 43})
    changed_body = envelope.model_copy(update={"body": changed_event})
    assert verify_detection_envelope(changed_body, private_key.public_key()) is False

    signature = bytearray(base64.b64decode(envelope.signature_b64, validate=True))
    signature[-1] ^= 1
    changed_signature = envelope.model_copy(
        update={"signature_b64": base64.b64encode(signature).decode("ascii")}
    )
    assert verify_detection_envelope(changed_signature, private_key.public_key()) is False


def test_signing_reuses_the_authoritative_canonical_event_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import secureedge.crypto as crypto

    event = _event()
    private_key = generate_private_key()
    calls: list[DetectionEvent] = []
    real_canonical_event_bytes = crypto.canonical_event_bytes

    def spy(value: DetectionEvent) -> bytes:
        calls.append(value)
        return real_canonical_event_bytes(value)

    monkeypatch.setattr(crypto, "canonical_event_bytes", spy)
    sign_detection_event(event, private_key)

    assert calls == [event]


def test_malformed_input_and_wrong_algorithm_fail_closed() -> None:
    private_key = generate_private_key()
    envelope = sign_detection_event(_event(), private_key)

    with pytest.raises(KeyMaterialError, match="envelope"):
        verify_detection_envelope(envelope.model_dump(), private_key.public_key())  # type: ignore[arg-type]
    with pytest.raises(KeyMaterialError, match="public key"):
        verify_detection_envelope(envelope, private_key)  # type: ignore[arg-type]

    invalid_algorithm = SignedDetectionEnvelope.model_construct(
        body=envelope.body,
        signature_algorithm="rsa",
        signature_b64=envelope.signature_b64,
    )
    with pytest.raises(KeyMaterialError, match="algorithm"):
        verify_detection_envelope(invalid_algorithm, private_key.public_key())

    invalid_signature = SignedDetectionEnvelope.model_construct(
        body=envelope.body,
        signature_algorithm="ed25519",
        signature_b64="not base64",
    )
    with pytest.raises(KeyMaterialError, match="signature"):
        verify_detection_envelope(invalid_signature, private_key.public_key())


def test_crypto_import_does_not_touch_files_or_services(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import importlib
    import os
    import pathlib
    import socket
    import sqlite3

    def fail(*args: object, **kwargs: object) -> None:
        raise AssertionError("crypto import performed an external side effect")

    monkeypatch.setattr(pathlib.Path, "read_text", fail)
    monkeypatch.setattr(pathlib.Path, "write_text", fail)
    monkeypatch.setattr(os, "open", fail)
    monkeypatch.setattr(socket, "socket", fail)
    monkeypatch.setattr(sqlite3, "connect", fail)

    module = importlib.import_module("secureedge.crypto")
    importlib.reload(module)
