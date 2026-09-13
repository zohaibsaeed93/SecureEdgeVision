"""Typed, side-effect-free loading for SecureEdgeVision system settings."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Annotated, Any, Literal

import yaml  # type: ignore[import-untyped]
from pydantic import AnyHttpUrl, BaseModel, ConfigDict, Field, ValidationError, field_validator


class ConfigurationError(ValueError):
    """Raised when system configuration cannot be loaded or validated."""


PositiveClockSkew = Annotated[int, Field(ge=1, le=3_600)]
PositiveNonceTtl = Annotated[int, Field(ge=1, le=86_400)]
RequestSize = Annotated[int, Field(ge=1_024, le=16_777_216)]
ImageSize = Annotated[int, Field(ge=32, le=4_096)]
Probability = Annotated[float, Field(ge=0.0, le=1.0)]
PositiveProbability = Annotated[float, Field(gt=0.0, le=1.0)]
SampleFps = Annotated[float, Field(gt=0.0, le=120.0)]


class StrictSettingsModel(BaseModel):
    """Base model that rejects unknown fields and mutation."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class SecuritySettings(StrictSettingsModel):
    max_clock_skew_seconds: PositiveClockSkew
    nonce_ttl_seconds: PositiveNonceTtl
    max_request_bytes: RequestSize


class VisionSettings(StrictSettingsModel):
    model: str = Field(min_length=1, max_length=255)
    device: str = Field(min_length=1, max_length=64)
    image_size: ImageSize
    confidence: PositiveProbability
    frame_sample_fps: SampleFps

    @field_validator("model")
    @classmethod
    def require_nano_weights(cls, value: str) -> str:
        candidate = value.strip()
        if not candidate or not Path(candidate).name.lower().endswith("n.pt"):
            raise ValueError("must name Ultralytics nano weights ending in 'n.pt'")
        return candidate

    @field_validator("device")
    @classmethod
    def normalize_device(cls, value: str) -> str:
        candidate = value.strip()
        if not candidate:
            raise ValueError("must not be blank")
        return candidate


class ConsensusSettings(StrictSettingsModel):
    """Future-only consensus values; no consensus behavior is implemented here."""

    policy: Literal["trust_weighted"]
    iou_threshold: Probability
    accept_threshold: Probability
    alpha: Probability
    trust_min: Probability


class SystemSettings(StrictSettingsModel):
    mode: Literal["privacy"]
    aggregator_url: AnyHttpUrl
    security: SecuritySettings
    vision: VisionSettings
    consensus: ConsensusSettings

    @field_validator("aggregator_url")
    @classmethod
    def reject_url_credentials(cls, value: AnyHttpUrl) -> AnyHttpUrl:
        if value.username is not None or value.password is not None:
            raise ValueError("must not contain credentials")
        return value


_Override = tuple[tuple[str, ...], type[str] | type[int] | type[float]]
_ENV_OVERRIDES: dict[str, _Override] = {
    "SEV_CONFIG__MODE": (("mode",), str),
    "SEV_CONFIG__AGGREGATOR_URL": (("aggregator_url",), str),
    "SEV_CONFIG__SECURITY__MAX_CLOCK_SKEW_SECONDS": (
        ("security", "max_clock_skew_seconds"),
        int,
    ),
    "SEV_CONFIG__SECURITY__NONCE_TTL_SECONDS": (("security", "nonce_ttl_seconds"), int),
    "SEV_CONFIG__SECURITY__MAX_REQUEST_BYTES": (("security", "max_request_bytes"), int),
    "SEV_CONFIG__VISION__MODEL": (("vision", "model"), str),
    "SEV_CONFIG__VISION__DEVICE": (("vision", "device"), str),
    "SEV_CONFIG__VISION__IMAGE_SIZE": (("vision", "image_size"), int),
    "SEV_CONFIG__VISION__CONFIDENCE": (("vision", "confidence"), float),
    "SEV_CONFIG__VISION__FRAME_SAMPLE_FPS": (("vision", "frame_sample_fps"), float),
    "SEV_CONFIG__CONSENSUS__POLICY": (("consensus", "policy"), str),
    "SEV_CONFIG__CONSENSUS__IOU_THRESHOLD": (("consensus", "iou_threshold"), float),
    "SEV_CONFIG__CONSENSUS__ACCEPT_THRESHOLD": (
        ("consensus", "accept_threshold"),
        float,
    ),
    "SEV_CONFIG__CONSENSUS__ALPHA": (("consensus", "alpha"), float),
    "SEV_CONFIG__CONSENSUS__TRUST_MIN": (("consensus", "trust_min"), float),
}


def _format_validation_error(error: ValidationError) -> str:
    details = []
    for item in error.errors(include_url=False):
        location = ".".join(str(part) for part in item["loc"]) or "configuration"
        details.append(f"{location}: {item['msg']}")
    return "invalid system configuration: " + "; ".join(details)


def _apply_environment_overrides(data: dict[str, Any], environ: Mapping[str, str]) -> None:
    unknown = sorted(
        key for key in environ if key.startswith("SEV_CONFIG__") and key not in _ENV_OVERRIDES
    )
    if unknown:
        raise ConfigurationError(
            "unknown configuration environment override(s): " + ", ".join(unknown)
        )

    for name, (path, converter) in _ENV_OVERRIDES.items():
        if name not in environ:
            continue
        raw_value = environ[name]
        try:
            value = converter(raw_value)
        except ValueError as exc:
            field = ".".join(path)
            raise ConfigurationError(
                f"invalid environment override {name} for {field}: {exc}"
            ) from exc

        target = data
        for part in path[:-1]:
            nested = target.get(part)
            if not isinstance(nested, dict):
                raise ConfigurationError(
                    f"cannot apply environment override {name}: {'.'.join(path[:-1])} "
                    "is missing or is not a mapping"
                )
            target = nested
        target[path[-1]] = value


def load_settings(
    path: str | Path,
    environ: Mapping[str, str] | None = None,
) -> SystemSettings:
    """Load and validate YAML settings with explicit, allowlisted overrides.

    The caller supplies ``environ`` deliberately. Passing ``None`` applies no
    overrides, which keeps tests and imports deterministic.
    """

    config_path = Path(path)
    try:
        raw = config_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigurationError(f"cannot read system configuration {config_path}: {exc}") from exc

    try:
        loaded = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise ConfigurationError(
            f"malformed YAML in system configuration {config_path}: {exc}"
        ) from exc

    if not isinstance(loaded, dict):
        raise ConfigurationError(
            f"invalid system configuration {config_path}: top-level value must be a mapping"
        )

    data: dict[str, Any] = loaded
    if environ is not None:
        _apply_environment_overrides(data, environ)

    try:
        return SystemSettings.model_validate(data)
    except ValidationError as exc:
        raise ConfigurationError(_format_validation_error(exc)) from exc
