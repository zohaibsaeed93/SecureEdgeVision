"""Signed metadata transport and heartbeat lifecycle for privacy workers."""

from __future__ import annotations

import math
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from types import TracebackType
from typing import Any, Literal, Protocol, Self

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import secureedge.contracts as contract_models
import secureedge.crypto as crypto_operations
from secureedge.contracts import DetectionEvent, NodeHeartbeat
from secureedge.worker import (
    FrameSource,
    MonotonicClock,
    PrivacyWorkerPipeline,
    UtcClock,
    WorkerPipelineError,
)

DETECTION_PATH = "/v1/events/detections"
HEARTBEAT_PATH = "/v1/nodes/heartbeat"
ACCEPTED_STATUS = 202


class TransportError(RuntimeError):
    """Stable, sanitized failure raised by worker metadata transport."""


class HeartbeatError(WorkerPipelineError):
    """Stable failure raised when worker heartbeat activity cannot continue."""


class EventTransport(Protocol):
    """Transport boundary used by the explicit worker runner."""

    def __enter__(self) -> Self:
        """Open transport resources."""

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> Literal[False]:
        """Close transport resources without suppressing worker failures."""

    def send_detection(self, event: DetectionEvent) -> None:
        """Sign and deliver one detection event."""

    def send_heartbeat(self, heartbeat: NodeHeartbeat) -> None:
        """Deliver one metadata-only heartbeat."""


class ThreadHandle(Protocol):
    """Minimal thread handle needed by the heartbeat lifecycle."""

    def start(self) -> None:
        """Start the heartbeat loop."""

    def join(self, timeout: float | None = None) -> None:
        """Wait for the heartbeat loop to stop."""


ClientFactory = Callable[..., httpx.Client]
ThreadFactory = Callable[[Callable[[], None]], ThreadHandle]
WaitFunction = Callable[[float], bool]
HeartbeatFactory = Callable[
    [EventTransport, str, float],
    "WorkerHeartbeatLifecycle",
]


class SignedWorkerTransport:
    """HTTPX client that signs events and sends only strict wire models.

    Construction performs no network or client activity. The explicit context
    manager owns and closes either the injected client or the client it creates.
    Each call performs exactly one request and never follows redirects.
    """

    def __init__(
        self,
        aggregator_url: object,
        request_timeout_seconds: float,
        private_key: Ed25519PrivateKey,
        *,
        client: httpx.Client | None = None,
        transport: httpx.BaseTransport | None = None,
        client_factory: ClientFactory = httpx.Client,
    ) -> None:
        self._origin = _validated_origin(aggregator_url)
        self._timeout_seconds = _positive_finite(
            request_timeout_seconds,
            "transport request timeout",
        )
        if not isinstance(private_key, Ed25519PrivateKey):
            raise TransportError("worker signing key is invalid")
        if client is not None and transport is not None:
            raise TransportError("metadata transport injection is invalid")
        if not callable(client_factory):
            raise TransportError("metadata client factory is invalid")

        self._private_key = private_key
        self._injected_client = client
        self._http_transport = transport
        self._client_factory = client_factory
        self._client: httpx.Client | None = None

    def __enter__(self) -> Self:
        if self._client is not None:
            raise TransportError("metadata transport is already open")
        try:
            client = self._injected_client
            if client is None:
                client = self._client_factory(
                    timeout=self._timeout_seconds,
                    follow_redirects=False,
                    transport=self._http_transport,
                )
            if client.is_closed:
                raise TransportError("metadata transport client is closed")
        except TransportError:
            raise
        except Exception:
            raise TransportError("metadata transport could not be opened") from None
        self._client = client
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> Literal[False]:
        client = self._client
        self._client = None
        if client is not None:
            try:
                client.close()
            except Exception:
                if exc_type is None:
                    raise TransportError("metadata transport could not be closed") from None
        return False

    def send_detection(self, event: DetectionEvent) -> None:
        try:
            if not isinstance(event, DetectionEvent):
                raise TypeError
            current_event = contract_models.DetectionEvent.model_validate(
                event.model_dump(mode="python")
            )
            envelope = crypto_operations.sign_detection_event(
                current_event,
                self._private_key,
            )
        except (AttributeError, TypeError, ValueError):
            raise TransportError("detection event could not be signed") from None
        self._post(
            DETECTION_PATH,
            envelope.model_dump(mode="json"),
            failure_message="detection delivery failed",
        )

    def send_heartbeat(self, heartbeat: NodeHeartbeat) -> None:
        if not isinstance(heartbeat, NodeHeartbeat):
            raise TransportError("heartbeat metadata is invalid")
        self._post(
            HEARTBEAT_PATH,
            heartbeat.model_dump(mode="json"),
            failure_message="heartbeat delivery failed",
        )

    def _post(self, path: str, payload: dict[str, Any], *, failure_message: str) -> None:
        client = self._client
        if client is None:
            raise TransportError("metadata transport is not open")

        response: httpx.Response | None = None
        try:
            response = client.post(
                self._origin + path,
                json=payload,
                timeout=self._timeout_seconds,
                follow_redirects=False,
            )
            if response.status_code != ACCEPTED_STATUS:
                raise TransportError(failure_message)
        except TransportError:
            raise
        except httpx.HTTPError:
            raise TransportError(failure_message) from None
        except Exception:
            raise TransportError(failure_message) from None
        finally:
            if response is not None:
                response.close()


class WorkerHeartbeatLifecycle:
    """Send an initial heartbeat and bounded periodic heartbeats in one thread."""

    def __init__(
        self,
        transport: EventTransport,
        node_id: str,
        interval_seconds: float,
        *,
        utc_clock: UtcClock | None = None,
        monotonic_clock: MonotonicClock = time.monotonic,
        wait_function: WaitFunction | None = None,
        thread_factory: ThreadFactory | None = None,
    ) -> None:
        self._transport = transport
        self._node_id = node_id
        self._interval_seconds = _positive_finite(
            interval_seconds,
            "heartbeat interval",
        )
        self._utc_clock = utc_clock or _utc_now
        self._monotonic_clock = monotonic_clock
        if not callable(self._utc_clock) or not callable(self._monotonic_clock):
            raise HeartbeatError("heartbeat clock boundary is invalid")

        self._stop = threading.Event()
        self._wait = wait_function or self._stop.wait
        self._thread_factory = thread_factory or _new_heartbeat_thread
        if not callable(self._wait) or not callable(self._thread_factory):
            raise HeartbeatError("heartbeat scheduling boundary is invalid")

        self._thread: ThreadHandle | None = None
        self._failure = False
        self._failure_lock = threading.Lock()
        self._started = False
        self._degraded_sent = False

    @property
    def started(self) -> bool:
        return self._started

    @property
    def failed(self) -> bool:
        with self._failure_lock:
            return self._failure

    def __enter__(self) -> Self:
        if self._started:
            raise HeartbeatError("heartbeat activity is already running")
        self._send("healthy")
        self._started = True
        try:
            thread = self._thread_factory(self._run)
            self._thread = thread
            thread.start()
        except Exception:
            self._stop.set()
            self._record_failure()
            raise HeartbeatError("heartbeat activity could not be started") from None
        self.check()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> Literal[False]:
        self._stop.set()
        thread = self._thread
        self._thread = None
        if thread is not None:
            try:
                thread.join()
            except Exception:
                self._record_failure()
        if exc_type is None:
            self.check()
        return False

    def check(self) -> None:
        if self.failed:
            raise HeartbeatError("heartbeat activity failed") from None

    def best_effort_degraded(self) -> None:
        """Send at most one degraded heartbeat without raising or masking failure."""

        if not self._started or self.failed or self._degraded_sent:
            return
        self._degraded_sent = True
        try:
            self._send("degraded")
        except HeartbeatError:
            return

    def _run(self) -> None:
        previous = self._monotonic_value()
        while True:
            try:
                should_stop = self._wait(self._interval_seconds)
                if not isinstance(should_stop, bool):
                    raise TypeError("wait boundary returned a non-boolean value")
                if should_stop:
                    return
                current = self._monotonic_value()
                if current < previous:
                    raise ValueError("heartbeat monotonic clock moved backwards")
                previous = current
                self._send("healthy")
            except Exception:
                self._record_failure()
                self._stop.set()
                return

    def _send(self, status: Literal["healthy", "degraded"]) -> None:
        try:
            timestamp = self._utc_clock()
            heartbeat = NodeHeartbeat(
                node_id=self._node_id,
                timestamp_utc=timestamp,
                status=status,
            )
            self._transport.send_heartbeat(heartbeat)
        except Exception:
            raise HeartbeatError("heartbeat delivery failed") from None

    def _record_failure(self) -> None:
        with self._failure_lock:
            self._failure = True

    def _monotonic_value(self) -> float:
        try:
            value = self._monotonic_clock()
        except Exception:
            raise HeartbeatError("heartbeat monotonic clock failed") from None
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise HeartbeatError("heartbeat monotonic clock is invalid")
        number = float(value)
        if not math.isfinite(number) or number < 0.0:
            raise HeartbeatError("heartbeat monotonic clock is invalid")
        return number


class SignedWorkerRunner:
    """Compose local detection, signed delivery, and heartbeat lifecycle."""

    def __init__(
        self,
        *,
        pipeline: PrivacyWorkerPipeline,
        source: FrameSource,
        transport: EventTransport,
        node_id: str,
        heartbeat_interval_seconds: float,
        heartbeat_factory: HeartbeatFactory | None = None,
    ) -> None:
        self._pipeline = pipeline
        self._source = source
        self._transport = transport
        self._node_id = node_id
        self._heartbeat_interval_seconds = heartbeat_interval_seconds
        self._heartbeat_factory = heartbeat_factory or _create_heartbeat_lifecycle

    def run(self, *, max_events: int | None = None) -> int:
        with self._transport:
            lifecycle = self._heartbeat_factory(
                self._transport,
                self._node_id,
                self._heartbeat_interval_seconds,
            )
            try:
                return self._pipeline.run(
                    self._source,
                    self._transport.send_detection,
                    max_events=max_events,
                    lifecycle=lifecycle,
                )
            except Exception:
                lifecycle.best_effort_degraded()
                raise


def _validated_origin(value: object) -> str:
    try:
        url = httpx.URL(str(value))
    except Exception:
        raise TransportError("aggregator origin is invalid") from None
    if (
        url.scheme not in ("http", "https")
        or not url.host
        or url.username
        or url.password
        or url.query
        or url.fragment
        or url.path not in ("", "/")
    ):
        raise TransportError("aggregator origin is invalid")
    return str(url).rstrip("/")


def _positive_finite(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TransportError(f"{label} is invalid")
    number = float(value)
    if not math.isfinite(number) or number <= 0.0:
        raise TransportError(f"{label} is invalid")
    return number


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _new_heartbeat_thread(target: Callable[[], None]) -> threading.Thread:
    return threading.Thread(
        target=target,
        name="secureedge-heartbeat",
        daemon=True,
    )


def _create_heartbeat_lifecycle(
    transport: EventTransport,
    node_id: str,
    interval_seconds: float,
) -> WorkerHeartbeatLifecycle:
    return WorkerHeartbeatLifecycle(transport, node_id, interval_seconds)


__all__ = [
    "ACCEPTED_STATUS",
    "DETECTION_PATH",
    "HEARTBEAT_PATH",
    "EventTransport",
    "HeartbeatError",
    "HeartbeatFactory",
    "SignedWorkerRunner",
    "SignedWorkerTransport",
    "TransportError",
    "WaitFunction",
    "WorkerHeartbeatLifecycle",
]
