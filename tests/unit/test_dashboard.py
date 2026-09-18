from datetime import UTC, datetime

import httpx
import pytest

from secureedge.contracts import DetectionEvent, FrameMetadata, ModelMetadata, PerformanceMetrics
from secureedge.dashboard import DashboardClient, DashboardDataError, summarize
from secureedge.monitoring import AggregatorHealth, NodeHealth, RecentDetectionEvent
from secureedge.persistence import SecurityAlert


def _event() -> DetectionEvent:
    return DetectionEvent(
        schema_version="1.0",
        event_id="event-1",
        node_id="edge-1",
        camera_id="cam-1",
        timestamp_utc=datetime(2026, 9, 18, tzinfo=UTC),
        nonce="nonce-1",
        frame_seq=1,
        job_id=None,
        mode="privacy",
        model=ModelMetadata(name="yolo26n.pt", sha256="a" * 64),
        frame=FrameMetadata(width=1920, height=1080),
        detections=[],
        performance=PerformanceMetrics(decode_ms=1.0, inference_ms=2.0, postprocess_ms=0.5),
    )


def _payloads() -> dict[str, object]:
    return {
        "health": AggregatorHealth(
            registered_nodes=1, accepted_events=1, security_alerts=1
        ).model_dump(mode="json"),
        "nodes": [
            NodeHealth(
                node_id="edge-1",
                registered_at_utc=datetime(2026, 9, 17, tzinfo=UTC),
                last_seen_at_utc=None,
                health_status=None,
            ).model_dump(mode="json")
        ],
        "events": [
            RecentDetectionEvent(
                accepted_at_utc=datetime(2026, 9, 18, tzinfo=UTC), event=_event()
            ).model_dump(mode="json")
        ],
        "alerts": [
            SecurityAlert(
                alert_id="alert-1",
                occurred_at_utc=datetime(2026, 9, 18, tzinfo=UTC),
                category="integrity",
                reason="invalid_signature",
                node_id="edge-1",
                event_id="event-1",
                nonce="nonce-1",
            ).model_dump(mode="json")
        ],
    }


def test_snapshot_uses_fixed_get_only_paths() -> None:
    payloads = _payloads()
    calls: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path + ("?" + request.url.query.decode() if request.url.query else "")))
        values = {
            "/health": payloads["health"],
            "/v1/nodes": payloads["nodes"],
            "/v1/events": payloads["events"],
            "/v1/security/alerts": payloads["alerts"],
        }
        return httpx.Response(200, json=values[request.url.path])

    with DashboardClient("http://aggregator.test", 2.0, transport=httpx.MockTransport(handler)) as client:
        snapshot = client.snapshot()

    assert [method for method, _ in calls] == ["GET"] * 4
    assert [path for _, path in calls] == [
        "/health",
        "/v1/nodes?limit=50",
        "/v1/events?limit=50",
        "/v1/security/alerts?limit=50",
    ]
    assert summarize(snapshot).event_volume == 1


def test_snapshot_rejects_bad_status_without_details() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(500, text="secret response body")

    with DashboardClient("http://aggregator.test", 2.0, transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(DashboardDataError, match="unavailable") as excinfo:
            client.snapshot()
    assert "secret" not in str(excinfo.value)


def test_snapshot_rejects_duplicate_keys() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/health":
            return httpx.Response(
                200,
                content=b'{"status":"healthy","status":"healthy","database":"ready","registered_nodes":0,"accepted_events":0,"security_alerts":0}',
            )
        return httpx.Response(200, json=[])

    with DashboardClient("http://aggregator.test", 2.0, transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(DashboardDataError):
            client.snapshot()
