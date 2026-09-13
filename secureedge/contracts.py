"""Strict, side-effect-free wire contracts for the Milestone 1 privacy path."""

from __future__ import annotations

import base64
import binascii
from datetime import datetime, timedelta
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, BeforeValidator, ConfigDict, Field, field_validator


def _parse_wire_timestamp(value: object) -> datetime:
    """Accept the datetime object or ISO-8601 string forms used by JSON requests."""

    if isinstance(value, datetime):
        return value
    if not isinstance(value, str):
        raise ValueError("must be an ISO-8601 timestamp string")
    try:
        return datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError("must be a valid ISO-8601 timestamp string") from exc


def _require_utc(value: datetime) -> datetime:
    """Reject naive timestamps and aware timestamps outside UTC."""

    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("must be timezone-aware UTC")
    if value.utcoffset() != timedelta(0):
        raise ValueError("must use UTC (offset +00:00 or Z)")
    return value


def _decode_canonical_base64(value: str, *, field_name: str, byte_length: int) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{field_name} must be valid standard base64") from exc

    if len(decoded) != byte_length:
        raise ValueError(f"{field_name} must encode exactly {byte_length} bytes")
    if base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError(f"{field_name} must use canonical standard base64")
    return decoded


SafeIdentifier = Annotated[
    str,
    Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
    ),
]
UtcTimestamp = Annotated[
    datetime,
    BeforeValidator(_parse_wire_timestamp),
    AfterValidator(_require_utc),
]
NonNegativeInt = Annotated[int, Field(ge=0)]
PositiveInt = Annotated[int, Field(gt=0)]
NonNegativeFloat = Annotated[float, Field(ge=0.0)]
NormalizedCoordinate = Annotated[float, Field(ge=0.0, le=1.0)]
NormalizedBoundingBox = Annotated[
    list[NormalizedCoordinate],
    Field(min_length=4, max_length=4),
]


class WireModel(BaseModel):
    """Base for frozen, strict contracts that fail closed on unknown fields."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        allow_inf_nan=False,
    )


class ModelMetadata(WireModel):
    """Detector identity attached to a detection event."""

    name: str = Field(min_length=1, max_length=255)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("name")
    @classmethod
    def reject_blank_name(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be blank")
        return value


class FrameMetadata(WireModel):
    """Non-pixel frame dimensions retained as event metadata."""

    width: PositiveInt
    height: PositiveInt


class Detection(WireModel):
    """One normalized object detection; it never contains image data."""

    class_id: NonNegativeInt
    class_name: str = Field(min_length=1, max_length=255)
    confidence: NormalizedCoordinate
    bbox_xyxy_norm: NormalizedBoundingBox
    track_id: NonNegativeInt | None = None

    @field_validator("class_name")
    @classmethod
    def reject_blank_class_name(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be blank")
        return value

    @field_validator("bbox_xyxy_norm")
    @classmethod
    def require_ordered_box(cls, value: list[float]) -> list[float]:
        x_min, y_min, x_max, y_max = value
        if x_min >= x_max:
            raise ValueError("must satisfy x_min < x_max")
        if y_min >= y_max:
            raise ValueError("must satisfy y_min < y_max")
        return value


class PerformanceMetrics(WireModel):
    """Per-frame worker timing metadata in milliseconds."""

    decode_ms: NonNegativeFloat
    inference_ms: NonNegativeFloat
    postprocess_ms: NonNegativeFloat


class DetectionEvent(WireModel):
    """Authoritative Milestone 1 privacy-mode detection metadata."""

    schema_version: Literal["1.0"]
    event_id: SafeIdentifier
    node_id: SafeIdentifier
    camera_id: SafeIdentifier
    timestamp_utc: UtcTimestamp
    nonce: SafeIdentifier
    frame_seq: NonNegativeInt
    job_id: SafeIdentifier | None
    mode: Literal["privacy"]
    model: ModelMetadata
    frame: FrameMetadata
    detections: list[Detection]
    performance: PerformanceMetrics


class NodeRegistration(WireModel):
    """Public identity material supplied when registering a worker node."""

    node_id: SafeIdentifier
    public_key_b64: str

    @field_validator("public_key_b64")
    @classmethod
    def validate_public_key_b64(cls, value: str) -> str:
        _decode_canonical_base64(value, field_name="public_key_b64", byte_length=32)
        return value


class NodeHeartbeat(WireModel):
    """Minimal node health metadata for the Milestone 1 supervisor view."""

    node_id: SafeIdentifier
    timestamp_utc: UtcTimestamp
    status: Literal["healthy", "degraded", "unhealthy"]


class SignedDetectionEnvelope(WireModel):
    """Detection metadata plus an Ed25519 signature representation."""

    body: DetectionEvent
    signature_algorithm: Literal["ed25519"]
    signature_b64: str

    @field_validator("signature_b64")
    @classmethod
    def validate_signature_b64(cls, value: str) -> str:
        _decode_canonical_base64(value, field_name="signature_b64", byte_length=64)
        return value


__all__ = [
    "Detection",
    "DetectionEvent",
    "FrameMetadata",
    "ModelMetadata",
    "NodeHeartbeat",
    "NodeRegistration",
    "PerformanceMetrics",
    "SignedDetectionEnvelope",
]
