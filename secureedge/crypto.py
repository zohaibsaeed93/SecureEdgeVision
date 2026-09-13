"""Ed25519 key and signed-event primitives for the Milestone 1 privacy path."""

from __future__ import annotations

import base64
import binascii

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from secureedge.canonical import canonical_event_bytes
from secureedge.contracts import DetectionEvent, SignedDetectionEnvelope

_PKCS8_PEM_BEGIN = b"-----BEGIN PRIVATE KEY-----"
_PKCS8_PEM_END = b"-----END PRIVATE KEY-----"
_PEM_BOUNDARY_WHITESPACE = b" \t\r\n"


class KeyMaterialError(ValueError):
    """Raised when supplied key or signature material is not supported."""


def generate_private_key() -> Ed25519PrivateKey:
    """Generate a fresh Ed25519 private key using cryptography's OS randomness."""

    return Ed25519PrivateKey.generate()


def encode_public_key(public_key: Ed25519PublicKey) -> str:
    """Encode a raw Ed25519 public key as canonical standard base64."""

    if not isinstance(public_key, Ed25519PublicKey):
        raise KeyMaterialError("public key must be an Ed25519 public key")

    raw_key = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw_key).decode("ascii")


def load_public_key(public_key_b64: str) -> Ed25519PublicKey:
    """Load a canonical raw Ed25519 public key from standard base64."""

    raw_key = _decode_canonical_base64(
        public_key_b64,
        label="public key",
        byte_length=32,
    )
    try:
        return Ed25519PublicKey.from_public_bytes(raw_key)
    except (TypeError, ValueError, UnsupportedAlgorithm) as exc:
        raise KeyMaterialError("public key material is not supported") from exc


def serialize_private_key(private_key: Ed25519PrivateKey) -> bytes:
    """Serialize an Ed25519 private key as unencrypted PKCS#8 PEM."""

    if not isinstance(private_key, Ed25519PrivateKey):
        raise KeyMaterialError("private key must be an Ed25519 private key")

    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def load_private_key(pem_data: bytes) -> Ed25519PrivateKey:
    """Load an unencrypted Ed25519 private key from PKCS#8 PEM."""

    if not isinstance(pem_data, bytes):
        raise KeyMaterialError("private key material must be PKCS#8 PEM bytes")

    _require_single_pkcs8_pem(pem_data)
    try:
        loaded_key = serialization.load_pem_private_key(pem_data, password=None)
    except (TypeError, ValueError, UnsupportedAlgorithm) as exc:
        raise KeyMaterialError("private key material is invalid or unsupported") from exc

    if not isinstance(loaded_key, Ed25519PrivateKey):
        raise KeyMaterialError("private key must be an Ed25519 private key")
    return loaded_key


def sign_detection_event(
    event: DetectionEvent,
    private_key: Ed25519PrivateKey,
) -> SignedDetectionEnvelope:
    """Sign exactly the authoritative canonical bytes of a detection event."""

    if not isinstance(private_key, Ed25519PrivateKey):
        raise KeyMaterialError("private key must be an Ed25519 private key")

    signature = private_key.sign(canonical_event_bytes(event))
    return SignedDetectionEnvelope(
        body=event,
        signature_algorithm="ed25519",
        signature_b64=base64.b64encode(signature).decode("ascii"),
    )


def verify_detection_envelope(
    envelope: SignedDetectionEnvelope,
    public_key: Ed25519PublicKey,
) -> bool:
    """Verify a signed event body, returning false for an invalid signature."""

    if not isinstance(envelope, SignedDetectionEnvelope):
        raise KeyMaterialError("envelope must be a signed detection envelope")
    if not isinstance(public_key, Ed25519PublicKey):
        raise KeyMaterialError("public key must be an Ed25519 public key")
    if envelope.signature_algorithm != "ed25519":
        raise KeyMaterialError("signature algorithm must be ed25519")

    signature = _decode_canonical_base64(
        envelope.signature_b64,
        label="signature",
        byte_length=64,
    )
    try:
        public_key.verify(signature, canonical_event_bytes(envelope.body))
    except InvalidSignature:
        return False
    except (TypeError, ValueError) as exc:
        raise KeyMaterialError("signed envelope body is invalid") from exc
    return True


def _require_single_pkcs8_pem(pem_data: bytes) -> None:
    stripped = pem_data.strip(_PEM_BOUNDARY_WHITESPACE)
    if (
        not stripped.startswith(_PKCS8_PEM_BEGIN)
        or not stripped.endswith(_PKCS8_PEM_END)
        or stripped.count(_PKCS8_PEM_BEGIN) != 1
        or stripped.count(_PKCS8_PEM_END) != 1
    ):
        raise KeyMaterialError("private key material is invalid or unsupported")


def _decode_canonical_base64(value: object, *, label: str, byte_length: int) -> bytes:
    if not isinstance(value, str):
        raise KeyMaterialError(f"{label} must be canonical standard base64")

    try:
        decoded = base64.b64decode(value, validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError, TypeError) as exc:
        raise KeyMaterialError(f"{label} must be canonical standard base64") from exc

    if len(decoded) != byte_length:
        raise KeyMaterialError(f"{label} must encode exactly {byte_length} bytes")
    if base64.b64encode(decoded).decode("ascii") != value:
        raise KeyMaterialError(f"{label} must be canonical standard base64")
    return decoded


__all__ = [
    "KeyMaterialError",
    "encode_public_key",
    "generate_private_key",
    "load_private_key",
    "load_public_key",
    "serialize_private_key",
    "sign_detection_event",
    "verify_detection_envelope",
]
