"""Thin FastAPI adapter for authenticated detection-event ingestion."""

from __future__ import annotations

import json
import math
from collections.abc import Callable
from typing import Any, NoReturn

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from pydantic import ValidationError
from secureedge.config import SecuritySettings
from secureedge.contracts import SignedDetectionEnvelope
from secureedge.ingestion import (
    DetectionEventIngestor,
    IngestionReason,
    IngestionRejection,
    IngestionServiceError,
)
from secureedge.persistence import SessionFactory
from secureedge.security import ReplayFreshnessPolicy

DETECTION_INGEST_PATH = "/v1/events/detections"


class _RequestFailure(Exception):
    def __init__(self, status_code: int, code: str) -> None:
        self.status_code = status_code
        self.code = code
        super().__init__(code)


def _reject_json_constant(value: str) -> NoReturn:
    del value
    raise ValueError("non-finite JSON number")


def _parse_finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("non-finite JSON number")
    return parsed


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def parse_detection_envelope(payload: bytes) -> SignedDetectionEnvelope:
    """Strictly decode one UTF-8 JSON envelope without reflecting failures."""

    try:
        text = payload.decode("utf-8", errors="strict")
        data = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
            parse_float=_parse_finite_float,
        )
        return SignedDetectionEnvelope.model_validate(data, strict=True)
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError, TypeError, ValueError):
        raise _RequestFailure(422, "invalid_request") from None


def _validated_security_settings(settings: SecuritySettings) -> SecuritySettings:
    settings_type = type(settings)
    if not (
        isinstance(settings, SecuritySettings)
        or (
            settings_type.__module__ == SecuritySettings.__module__
            and settings_type.__qualname__ == SecuritySettings.__qualname__
        )
    ):
        raise TypeError("security settings must be validated")
    try:
        return SecuritySettings.model_validate(
            settings.model_dump(mode="python", warnings="error"),
            strict=True,
        )
    except (TypeError, ValidationError, ValueError):
        raise TypeError("security settings must be validated") from None


def _json_error(status_code: int, code: str) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"detail": {"code": code}})


def _content_length(request: Request, *, maximum: int) -> int | None:
    raw = request.headers.get("content-length")
    if raw is None:
        return None
    if not raw.isascii() or not raw.isdecimal():
        raise _RequestFailure(422, "invalid_request")
    normalized = raw.lstrip("0") or "0"
    maximum_decimal = str(maximum)
    if len(normalized) > len(maximum_decimal) or (
        len(normalized) == len(maximum_decimal) and normalized > maximum_decimal
    ):
        raise _RequestFailure(413, "request_too_large")
    return int(normalized)


async def _read_bounded_body(request: Request, *, maximum: int) -> bytes:
    declared = _content_length(request, maximum=maximum)
    chunks: list[bytes] = []
    total = 0
    try:
        async for chunk in request.stream():
            total += len(chunk)
            if total > maximum:
                raise _RequestFailure(413, "request_too_large")
            if chunk:
                chunks.append(chunk)
    except _RequestFailure:
        raise
    except Exception:
        raise _RequestFailure(422, "invalid_request") from None

    if declared is not None and declared != total:
        raise _RequestFailure(422, "invalid_request")
    return b"".join(chunks)


def _require_json(request: Request) -> None:
    media_type = request.headers.get("content-type", "").partition(";")[0].strip().lower()
    if media_type != "application/json":
        raise _RequestFailure(422, "invalid_request")


def create_app(
    *,
    security_settings: SecuritySettings,
    session_factory: SessionFactory,
    replay_policy: ReplayFreshnessPolicy | None = None,
    ingestor_factory: Callable[
        [SessionFactory, ReplayFreshnessPolicy], DetectionEventIngestor
    ] = DetectionEventIngestor,
) -> FastAPI:
    """Create one explicitly configured, side-effect-free aggregator app."""

    settings = _validated_security_settings(security_settings)
    if not callable(session_factory):
        raise TypeError("session factory must be callable")
    policy = replay_policy or ReplayFreshnessPolicy(settings)
    ingestor = ingestor_factory(session_factory, policy)

    app = FastAPI(
        title="SecureEdgeVision Aggregator",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.replay_policy = policy
    app.state.ingestor = ingestor

    @app.post(DETECTION_INGEST_PATH, status_code=202, response_class=Response)
    async def ingest_detection(request: Request) -> Response:
        try:
            _require_json(request)
            payload = await _read_bounded_body(
                request,
                maximum=settings.max_request_bytes,
            )
            envelope = parse_detection_envelope(payload)
            ingestor.ingest(envelope)
        except _RequestFailure as exc:
            return _json_error(exc.status_code, exc.code)
        except IngestionRejection as exc:
            status = 401 if exc.reason in {
                IngestionReason.UNKNOWN_NODE,
                IngestionReason.INVALID_SIGNATURE,
            } else 409
            return _json_error(status, exc.reason.value)
        except IngestionServiceError:
            return _json_error(503, IngestionReason.SERVICE_UNAVAILABLE.value)
        except Exception:
            return _json_error(503, IngestionReason.SERVICE_UNAVAILABLE.value)
        return Response(status_code=202)

    return app


__all__ = ["DETECTION_INGEST_PATH", "create_app", "parse_detection_envelope"]
