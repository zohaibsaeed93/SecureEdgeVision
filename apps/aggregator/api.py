"""Thin FastAPI adapter for authenticated ingest and metadata-only monitoring."""

from __future__ import annotations

import json
import math
from collections.abc import Callable
from typing import Any, NoReturn, TypeVar

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ValidationError
from secureedge.config import SecuritySettings
from secureedge.contracts import NodeHeartbeat, SignedDetectionEnvelope
from secureedge.ingestion import (
    DetectionEventIngestor,
    IngestionReason,
    IngestionRejection,
    IngestionServiceError,
)
from secureedge.monitoring import (
    DEFAULT_MONITORING_QUERY_LIMIT,
    MAX_MONITORING_QUERY_LIMIT,
    AggregatorHealth,
    HeartbeatReason,
    HeartbeatRejection,
    HeartbeatService,
    MonitoringServiceError,
    NodeHealth,
    RecentDetectionEvent,
    get_aggregator_health,
    list_node_health,
    list_recent_events,
)
from secureedge.persistence import (
    DEFAULT_SECURITY_ALERT_QUERY_LIMIT,
    MAX_SECURITY_ALERT_QUERY_LIMIT,
    PersistenceError,
    SecurityAlert,
    SessionFactory,
    list_security_alerts,
)
from secureedge.security import ReplayFreshnessPolicy

DETECTION_INGEST_PATH = "/v1/events/detections"
EVENTS_PATH = "/v1/events"
HEALTH_PATH = "/health"
NODE_HEARTBEAT_PATH = "/v1/nodes/heartbeat"
NODES_PATH = "/v1/nodes"
SECURITY_ALERTS_PATH = "/v1/security/alerts"

_WireModelT = TypeVar("_WireModelT", bound=BaseModel)
HeartbeatServiceFactory = Callable[[SessionFactory, SecuritySettings], HeartbeatService]


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


def _parse_wire_model(payload: bytes, model_type: type[_WireModelT]) -> _WireModelT:
    try:
        text = payload.decode("utf-8", errors="strict")
        data = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
            parse_float=_parse_finite_float,
        )
        return model_type.model_validate(data, strict=True)
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError, TypeError, ValueError):
        raise _RequestFailure(422, "invalid_request") from None


def parse_detection_envelope(payload: bytes) -> SignedDetectionEnvelope:
    """Strictly decode one UTF-8 JSON envelope without reflecting failures."""

    return _parse_wire_model(payload, SignedDetectionEnvelope)


def parse_node_heartbeat(payload: bytes) -> NodeHeartbeat:
    """Strictly decode one metadata-only advisory heartbeat."""

    return _parse_wire_model(payload, NodeHeartbeat)


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


def _bounded_limit(request: Request, *, default: int, maximum: int) -> int:
    parameters = request.query_params.multi_items()
    if not parameters:
        return default
    if len(parameters) != 1 or parameters[0][0] != "limit":
        raise _RequestFailure(422, "invalid_request")

    raw = parameters[0][1]
    if not raw.isascii() or not raw.isdecimal():
        raise _RequestFailure(422, "invalid_request")
    normalized = raw.lstrip("0") or "0"
    maximum_decimal = str(maximum)
    if normalized == "0" or len(normalized) > len(maximum_decimal) or (
        len(normalized) == len(maximum_decimal) and normalized > maximum_decimal
    ):
        raise _RequestFailure(422, "invalid_request")
    return int(normalized)


def _require_no_query(request: Request) -> None:
    if request.query_params.multi_items():
        raise _RequestFailure(422, "invalid_request")


def create_app(
    *,
    security_settings: SecuritySettings,
    session_factory: SessionFactory,
    replay_policy: ReplayFreshnessPolicy | None = None,
    ingestor_factory: Callable[
        [SessionFactory, ReplayFreshnessPolicy], DetectionEventIngestor
    ] = DetectionEventIngestor,
    heartbeat_service_factory: HeartbeatServiceFactory = HeartbeatService,
) -> FastAPI:
    """Create one explicitly configured, side-effect-free aggregator app."""

    settings = _validated_security_settings(security_settings)
    if not callable(session_factory):
        raise TypeError("session factory must be callable")
    policy = replay_policy or ReplayFreshnessPolicy(settings)
    ingestor = ingestor_factory(session_factory, policy)
    heartbeat_service = heartbeat_service_factory(session_factory, settings)

    app = FastAPI(
        title="SecureEdgeVision Aggregator",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.replay_policy = policy
    app.state.ingestor = ingestor
    app.state.heartbeat_service = heartbeat_service

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

    @app.post(NODE_HEARTBEAT_PATH, status_code=202, response_class=Response)
    async def record_heartbeat(request: Request) -> Response:
        try:
            _require_no_query(request)
            _require_json(request)
            payload = await _read_bounded_body(
                request,
                maximum=settings.max_request_bytes,
            )
            heartbeat_service.record(parse_node_heartbeat(payload))
        except _RequestFailure as exc:
            return _json_error(exc.status_code, exc.code)
        except HeartbeatRejection as exc:
            status = 401 if exc.reason is HeartbeatReason.UNKNOWN_NODE else 409
            return _json_error(status, exc.reason.value)
        except MonitoringServiceError:
            return _json_error(503, HeartbeatReason.SERVICE_UNAVAILABLE.value)
        except Exception:
            return _json_error(503, HeartbeatReason.SERVICE_UNAVAILABLE.value)
        return Response(status_code=202)

    @app.get(HEALTH_PATH, response_model=AggregatorHealth)
    def get_health(request: Request) -> AggregatorHealth:
        try:
            _require_no_query(request)
            return get_aggregator_health(session_factory)
        except _RequestFailure as exc:
            raise HTTPException(
                status_code=exc.status_code,
                detail={"code": exc.code},
            ) from None
        except MonitoringServiceError:
            raise HTTPException(
                status_code=503,
                detail={"code": HeartbeatReason.SERVICE_UNAVAILABLE.value},
            ) from None
        except Exception:
            raise HTTPException(
                status_code=503,
                detail={"code": HeartbeatReason.SERVICE_UNAVAILABLE.value},
            ) from None

    @app.get(NODES_PATH, response_model=list[NodeHealth])
    def get_nodes(request: Request) -> list[NodeHealth]:
        try:
            limit = _bounded_limit(
                request,
                default=DEFAULT_MONITORING_QUERY_LIMIT,
                maximum=MAX_MONITORING_QUERY_LIMIT,
            )
            return list_node_health(session_factory, limit=limit)
        except _RequestFailure as exc:
            raise HTTPException(
                status_code=exc.status_code,
                detail={"code": exc.code},
            ) from None
        except MonitoringServiceError:
            raise HTTPException(
                status_code=503,
                detail={"code": HeartbeatReason.SERVICE_UNAVAILABLE.value},
            ) from None
        except Exception:
            raise HTTPException(
                status_code=503,
                detail={"code": HeartbeatReason.SERVICE_UNAVAILABLE.value},
            ) from None

    @app.get(EVENTS_PATH, response_model=list[RecentDetectionEvent])
    def get_events(request: Request) -> list[RecentDetectionEvent]:
        try:
            limit = _bounded_limit(
                request,
                default=DEFAULT_MONITORING_QUERY_LIMIT,
                maximum=MAX_MONITORING_QUERY_LIMIT,
            )
            return list_recent_events(session_factory, limit=limit)
        except _RequestFailure as exc:
            raise HTTPException(
                status_code=exc.status_code,
                detail={"code": exc.code},
            ) from None
        except MonitoringServiceError:
            raise HTTPException(
                status_code=503,
                detail={"code": HeartbeatReason.SERVICE_UNAVAILABLE.value},
            ) from None
        except Exception:
            raise HTTPException(
                status_code=503,
                detail={"code": HeartbeatReason.SERVICE_UNAVAILABLE.value},
            ) from None

    @app.get(SECURITY_ALERTS_PATH, response_model=list[SecurityAlert])
    def get_security_alerts(request: Request) -> list[SecurityAlert]:
        try:
            limit = _bounded_limit(
                request,
                default=DEFAULT_SECURITY_ALERT_QUERY_LIMIT,
                maximum=MAX_SECURITY_ALERT_QUERY_LIMIT,
            )
            return list_security_alerts(session_factory, limit=limit)
        except _RequestFailure as exc:
            raise HTTPException(
                status_code=exc.status_code,
                detail={"code": exc.code},
            ) from None
        except PersistenceError:
            raise HTTPException(
                status_code=503,
                detail={"code": IngestionReason.SERVICE_UNAVAILABLE.value},
            ) from None
        except Exception:
            raise HTTPException(
                status_code=503,
                detail={"code": IngestionReason.SERVICE_UNAVAILABLE.value},
            ) from None

    return app


__all__ = [
    "DETECTION_INGEST_PATH",
    "EVENTS_PATH",
    "HEALTH_PATH",
    "HeartbeatServiceFactory",
    "NODE_HEARTBEAT_PATH",
    "NODES_PATH",
    "SECURITY_ALERTS_PATH",
    "create_app",
    "parse_detection_envelope",
    "parse_node_heartbeat",
]
