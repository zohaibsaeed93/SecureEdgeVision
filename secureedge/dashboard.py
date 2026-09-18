"""Read-only, bounded dashboard snapshot retrieval and summaries."""

from __future__ import annotations

import json
import math
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, TypeAdapter, ValidationError

from secureedge.monitoring import AggregatorHealth, NodeHealth, RecentDetectionEvent
from secureedge.persistence import SecurityAlert

DEFAULT_DASHBOARD_LIMIT = 50


class DashboardDataError(RuntimeError):
    """Stable sanitized dashboard-data failure."""


class DashboardSnapshot(BaseModel):
    """One bounded, typed, in-memory dashboard snapshot."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    health: AggregatorHealth
    nodes: tuple[NodeHealth, ...]
    events: tuple[RecentDetectionEvent, ...]
    alerts: tuple[SecurityAlert, ...]


@dataclass(frozen=True, slots=True)
class DashboardSummary:
    """Deterministic chart-ready aggregates derived only from a snapshot."""

    event_volume: int
    detection_class_counts: tuple[tuple[str, int], ...]
    node_status_counts: tuple[tuple[str, int], ...]
    alert_reason_counts: tuple[tuple[str, int], ...]


def _reject_constant(value: str) -> None:
    del value
    raise ValueError("non-finite JSON number")


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _parse_json(response: httpx.Response) -> Any:
    try:
        text = response.content.decode("utf-8", errors="strict")
        return json.loads(
            text,
            object_pairs_hook=_unique_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise DashboardDataError("dashboard data is invalid") from exc


def _validate(model_type: type[BaseModel] | TypeAdapter[Any], payload: Any) -> Any:
    try:
        if isinstance(model_type, TypeAdapter):
            return model_type.validate_python(payload, strict=True)
        return model_type.model_validate(payload, strict=True)
    except (ValidationError, TypeError, ValueError) as exc:
        raise DashboardDataError("dashboard data is invalid") from exc


def _origin(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise DashboardDataError("dashboard configuration is invalid")
    normalized = value.rstrip("/")
    if not normalized.startswith(("http://", "https://")):
        raise DashboardDataError("dashboard configuration is invalid")
    return normalized


class DashboardClient:
    """Explicit GET-only client for the aggregator's bounded monitoring surface."""

    def __init__(
        self,
        aggregator_url: str,
        timeout_seconds: float,
        *,
        client: httpx.Client | None = None,
        transport: httpx.BaseTransport | None = None,
        limit: int = DEFAULT_DASHBOARD_LIMIT,
    ) -> None:
        if not isinstance(timeout_seconds, (int, float)) or isinstance(timeout_seconds, bool):
            raise DashboardDataError("dashboard configuration is invalid")
        if not math.isfinite(float(timeout_seconds)) or float(timeout_seconds) <= 0:
            raise DashboardDataError("dashboard configuration is invalid")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise DashboardDataError("dashboard configuration is invalid")
        self._origin = _origin(aggregator_url)
        self._limit = limit
        self._owns_client = client is None
        if client is not None and transport is not None:
            raise DashboardDataError("dashboard configuration is invalid")
        self._client = client or httpx.Client(
            timeout=float(timeout_seconds),
            follow_redirects=False,
            transport=transport,
        )

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def _get(self, path: str) -> Any:
        try:
            response = self._client.get(f"{self._origin}{path}")
        except httpx.HTTPError as exc:
            raise DashboardDataError("dashboard data is unavailable") from exc
        if response.status_code != 200:
            raise DashboardDataError("dashboard data is unavailable")
        return _parse_json(response)

    def snapshot(self) -> DashboardSnapshot:
        """Fetch one consistent bounded snapshot; no retries or background polling."""
        try:
            health = _validate(AggregatorHealth, self._get("/health"))
            nodes_payload = self._get(f"/v1/nodes?limit={self._limit}")
            events_payload = self._get(f"/v1/events?limit={self._limit}")
            alerts_payload = self._get(f"/v1/security/alerts?limit={self._limit}")
            nodes = _validate(TypeAdapter(list[NodeHealth]), nodes_payload)
            events = _validate(TypeAdapter(list[RecentDetectionEvent]), events_payload)
            alerts = _validate(TypeAdapter(list[SecurityAlert]), alerts_payload)
            return DashboardSnapshot(
                health=health,
                nodes=tuple(nodes),
                events=tuple(events),
                alerts=tuple(alerts),
            )
        except DashboardDataError:
            raise
        except (ValidationError, TypeError, ValueError) as exc:
            raise DashboardDataError("dashboard data is invalid") from exc

    def __enter__(self) -> "DashboardClient":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        self.close()


def summarize(snapshot: DashboardSnapshot) -> DashboardSummary:
    """Build deterministic Plotly/table aggregates from one typed snapshot."""
    class_counts: Counter[str] = Counter()
    for item in snapshot.events:
        for detection in item.event.detections:
            class_counts[detection.class_name] += 1

    node_counts: Counter[str] = Counter(
        node.health_status or "unseen" for node in snapshot.nodes
    )
    alert_counts: Counter[str] = Counter(
        f"{alert.category}:{alert.reason}" for alert in snapshot.alerts
    )
    return DashboardSummary(
        event_volume=len(snapshot.events),
        detection_class_counts=tuple(sorted(class_counts.items())),
        node_status_counts=tuple(sorted(node_counts.items())),
        alert_reason_counts=tuple(sorted(alert_counts.items())),
    )


__all__ = [
    "DEFAULT_DASHBOARD_LIMIT",
    "DashboardClient",
    "DashboardDataError",
    "DashboardSnapshot",
    "DashboardSummary",
    "summarize",
]
