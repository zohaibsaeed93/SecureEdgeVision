"""Local privacy-worker acquisition, sampling, and event assembly."""

from __future__ import annotations

import importlib
import math
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import TracebackType
from typing import Any, Literal, Protocol, Self
from uuid import uuid4

from pydantic import TypeAdapter, ValidationError

from secureedge.config import VisionSettings
from secureedge.contracts import (
    DetectionEvent,
    PerformanceMetrics,
    SafeIdentifier,
)
from secureedge.vision import VisionError, VisionResult


class WorkerPipelineError(RuntimeError):
    """Raised when the local worker cannot safely produce metadata."""


class FrameDetector(Protocol):
    """Detector boundary consumed by the worker pipeline."""

    def infer(self, frame: Any) -> VisionResult:
        """Return metadata for one in-memory local frame."""


@dataclass(frozen=True, slots=True)
class CapturedFrame:
    """One transient local frame plus acquisition timing metadata.

    ``frame`` is deliberately excluded from ``repr`` so diagnostics cannot
    accidentally render pixel values. Only :class:`DetectionEvent` leaves the
    worker pipeline.
    """

    frame: Any = field(repr=False)
    decode_ms: float
    sample_time_seconds: float


class FrameSource(Protocol):
    """Explicit context-managed source for local frames."""

    def __enter__(self) -> Self:
        """Open the source and return it."""

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> Literal[False]:
        """Release source resources."""

    def read(self) -> CapturedFrame | None:
        """Return a local frame or ``None`` for a clean finite-source EOF."""


class WorkerLifecycle(Protocol):
    """Optional runtime activity coupled to an opened local frame source."""

    def __enter__(self) -> Self:
        """Start activity only after the local source opened successfully."""

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> Literal[False]:
        """Stop activity without suppressing a worker failure."""

    def check(self) -> None:
        """Raise when background activity has failed."""


class CaptureBackend(Protocol):
    """Small subset of ``cv2.VideoCapture`` used by the local adapter."""

    def isOpened(self) -> bool:
        """Return whether acquisition opened successfully."""

    def read(self) -> tuple[bool, Any]:
        """Decode one frame."""

    def get(self, property_id: int) -> float:
        """Read numeric source metadata."""

    def release(self) -> None:
        """Release acquisition resources."""


CaptureFactory = Callable[[int | str], CaptureBackend]
MonotonicClock = Callable[[], float]
UtcClock = Callable[[], datetime]
IdentifierFactory = Callable[[], str]
EventSink = Callable[[DetectionEvent], None]


class OpenCvFrameSource:
    """Read a local camera device or local image/video through OpenCV.

    Integer sources are local camera device indexes and use monotonic read
    completion times for sampling. Files use their declared frame rate as a
    content timeline when available, then fall back to the monotonic clock.
    URI sources are rejected: network acquisition is outside this task.
    """

    def __init__(
        self,
        source: int | str | Path,
        *,
        capture_factory: CaptureFactory | None = None,
        monotonic_clock: MonotonicClock = time.perf_counter,
        fps_property: int | None = None,
        frame_count_property: int | None = None,
    ) -> None:
        self._camera_index: int | None = None
        self._path: Path | None = None
        if isinstance(source, bool):
            raise WorkerPipelineError("local frame source is invalid")
        if isinstance(source, int):
            if source < 0:
                raise WorkerPipelineError("local camera index is invalid")
            self._camera_index = source
        elif isinstance(source, (str, Path)):
            raw_source = str(source)
            if not raw_source.strip() or "://" in raw_source:
                raise WorkerPipelineError("local media source is invalid")
            self._path = Path(source).expanduser()
        else:
            raise WorkerPipelineError("local frame source is invalid")

        if not callable(monotonic_clock):
            raise WorkerPipelineError("local source clock is invalid")
        self._capture_factory = capture_factory
        self._clock = monotonic_clock
        self._fps_property = fps_property
        self._frame_count_property = frame_count_property
        self._capture: CaptureBackend | None = None
        self._source_fps: float | None = None
        self._expected_frames: int | None = None
        self._frame_index = 0

    def __enter__(self) -> Self:
        if self._capture is not None:
            raise WorkerPipelineError("local frame source is already open")

        source_argument: int | str
        if self._camera_index is not None:
            source_argument = self._camera_index
        else:
            path = self._path
            if path is None:
                raise WorkerPipelineError("local media source is invalid")
            try:
                if not path.is_file():
                    raise WorkerPipelineError("local media source is unavailable")
            except OSError as exc:
                raise WorkerPipelineError("local media source is unavailable") from exc
            source_argument = str(path)

        factory = self._capture_factory
        fps_property = self._fps_property
        frame_count_property = self._frame_count_property
        if factory is None:
            try:
                cv2: Any = importlib.import_module("cv2")
                factory = cv2.VideoCapture
                fps_property = int(cv2.CAP_PROP_FPS)
                frame_count_property = int(cv2.CAP_PROP_FRAME_COUNT)
            except Exception as exc:
                raise WorkerPipelineError("OpenCV frame acquisition is unavailable") from exc

        try:
            capture = factory(source_argument)
        except Exception as exc:
            raise WorkerPipelineError("local frame source could not be opened") from exc
        try:
            opened = bool(capture.isOpened())
        except Exception as exc:
            _release_quietly(capture)
            raise WorkerPipelineError("local frame source could not be opened") from exc
        if not opened:
            _release_quietly(capture)
            raise WorkerPipelineError("local frame source could not be opened")

        self._capture = capture
        self._frame_index = 0
        if self._path is not None:
            self._source_fps = _optional_positive_capture_value(capture, fps_property)
            frame_count = _optional_positive_capture_value(capture, frame_count_property)
            self._expected_frames = None if frame_count is None else math.ceil(frame_count)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> Literal[False]:
        try:
            self.close()
        except WorkerPipelineError:
            if exc_type is None:
                raise
        return False

    def close(self) -> None:
        """Release the capture exactly once."""

        capture = self._capture
        self._capture = None
        if capture is None:
            return
        try:
            capture.release()
        except Exception as exc:
            raise WorkerPipelineError("local frame source could not be released") from exc

    def read(self) -> CapturedFrame | None:
        """Decode one frame without exposing source details in errors."""

        capture = self._capture
        if capture is None:
            raise WorkerPipelineError("local frame source is not open")

        started = _monotonic_value(self._clock, "local source clock")
        try:
            decoded, frame = capture.read()
        except Exception as exc:
            raise WorkerPipelineError("local frame acquisition failed") from exc
        finished = _monotonic_value(self._clock, "local source clock")
        decode_ms = _elapsed_ms(started, finished, "local frame decode timing")

        if not decoded:
            if self._camera_index is not None:
                raise WorkerPipelineError("local camera frame acquisition failed")
            if self._expected_frames is not None and self._frame_index < self._expected_frames:
                raise WorkerPipelineError("local media ended before its declared frame count")
            return None
        if frame is None:
            raise WorkerPipelineError("local frame acquisition returned no frame")

        if self._source_fps is None:
            sample_time = finished
        else:
            sample_time = self._frame_index / self._source_fps
        self._frame_index += 1
        return CapturedFrame(
            frame=frame,
            decode_ms=decode_ms,
            sample_time_seconds=sample_time,
        )


class PrivacyWorkerPipeline:
    """Turn sampled local frames into strict unsigned detection events.

    ``inference_ms`` spans the integrated detector call, including the
    detector's normalization work. ``postprocess_ms`` covers worker identity,
    timestamp, identifier, and event-input preparation immediately before
    final Pydantic validation. This boundary does not pretend to expose timing
    precision unavailable from the detector implementation.

    Frame sequence numbers start at zero and increment only after a complete
    event validates. Skipped or failed frames do not consume a sequence number.
    """

    def __init__(
        self,
        *,
        node_id: str,
        camera_id: str,
        settings: VisionSettings,
        detector: FrameDetector,
        utc_clock: UtcClock | None = None,
        monotonic_clock: MonotonicClock = time.perf_counter,
        event_id_factory: IdentifierFactory | None = None,
        nonce_factory: IdentifierFactory | None = None,
    ) -> None:
        self._node_id = _safe_identifier(node_id, "worker node identity")
        self._camera_id = _safe_identifier(camera_id, "worker camera identity")
        try:
            self._settings = VisionSettings.model_validate(
                settings.model_dump(mode="python"),
                strict=True,
            )
        except Exception as exc:
            raise WorkerPipelineError("worker vision settings are invalid") from exc
        if not callable(getattr(detector, "infer", None)):
            raise WorkerPipelineError("worker detector is invalid")
        if not callable(monotonic_clock):
            raise WorkerPipelineError("worker monotonic clock is invalid")

        self._detector = detector
        self._utc_clock = utc_clock or _utc_now
        self._monotonic_clock = monotonic_clock
        self._event_id_factory = event_id_factory or _new_event_id
        self._nonce_factory = nonce_factory or _new_nonce
        if not all(
            callable(factory)
            for factory in (self._utc_clock, self._event_id_factory, self._nonce_factory)
        ):
            raise WorkerPipelineError("worker event factory is invalid")

        self._next_frame_seq = 0
        self._issued_event_ids: set[str] = set()
        self._issued_nonces: set[str] = set()

    @property
    def next_frame_seq(self) -> int:
        """Return the sequence number that the next successful event will use."""

        return self._next_frame_seq

    def process_frame(self, captured: CapturedFrame) -> DetectionEvent:
        """Run local detection and assemble one validated metadata event."""

        if not isinstance(captured, CapturedFrame):
            raise WorkerPipelineError("captured frame metadata is invalid")
        decode_ms = _nonnegative_finite(captured.decode_ms, "frame decode timing")
        _nonnegative_finite(captured.sample_time_seconds, "frame sample timing")

        inference_started = _monotonic_value(
            self._monotonic_clock,
            "worker monotonic clock",
        )
        try:
            result = self._detector.infer(captured.frame)
        except VisionError as exc:
            raise WorkerPipelineError("local detection failed") from exc
        except Exception as exc:
            raise WorkerPipelineError("local detector failed unexpectedly") from exc
        inference_finished = _monotonic_value(
            self._monotonic_clock,
            "worker monotonic clock",
        )
        inference_ms = _elapsed_ms(
            inference_started,
            inference_finished,
            "worker inference timing",
        )
        if not isinstance(result, VisionResult):
            raise WorkerPipelineError("local detector returned invalid metadata")

        postprocess_started = _monotonic_value(
            self._monotonic_clock,
            "worker monotonic clock",
        )
        timestamp = _utc_timestamp(self._utc_clock)
        event_id = _factory_identifier(self._event_id_factory, "event identifier")
        nonce = _factory_identifier(self._nonce_factory, "event nonce")
        if event_id in self._issued_event_ids:
            raise WorkerPipelineError("event identifier factory reused a value")
        if nonce in self._issued_nonces:
            raise WorkerPipelineError("event nonce factory reused a value")
        detections = list(result.detections)
        frame_seq = self._next_frame_seq
        postprocess_finished = _monotonic_value(
            self._monotonic_clock,
            "worker monotonic clock",
        )
        postprocess_ms = _elapsed_ms(
            postprocess_started,
            postprocess_finished,
            "worker postprocess timing",
        )

        try:
            event = DetectionEvent(
                schema_version="1.0",
                event_id=event_id,
                node_id=self._node_id,
                camera_id=self._camera_id,
                timestamp_utc=timestamp,
                nonce=nonce,
                frame_seq=frame_seq,
                job_id=None,
                mode="privacy",
                model=result.model,
                frame=result.frame,
                detections=detections,
                performance=PerformanceMetrics(
                    decode_ms=decode_ms,
                    inference_ms=inference_ms,
                    postprocess_ms=postprocess_ms,
                ),
            )
        except (TypeError, ValueError, ValidationError) as exc:
            raise WorkerPipelineError("detection event validation failed") from exc

        self._issued_event_ids.add(event_id)
        self._issued_nonces.add(nonce)
        self._next_frame_seq += 1
        return event

    def run(
        self,
        source: FrameSource,
        sink: EventSink,
        *,
        max_events: int | None = None,
        lifecycle: WorkerLifecycle | None = None,
    ) -> int:
        """Process one explicit local source and send only events to ``sink``."""

        if not callable(sink):
            raise WorkerPipelineError("metadata sink is invalid")
        if max_events is not None and (
            isinstance(max_events, bool) or not isinstance(max_events, int) or max_events <= 0
        ):
            raise WorkerPipelineError("maximum event count is invalid")

        sampler = _SamplingGate(self._settings.frame_sample_fps)
        emitted = 0
        active_lifecycle: WorkerLifecycle = lifecycle or _NullWorkerLifecycle()
        try:
            with source as active_source, active_lifecycle:
                active_lifecycle.check()
                while max_events is None or emitted < max_events:
                    active_lifecycle.check()
                    captured = active_source.read()
                    active_lifecycle.check()
                    if captured is None:
                        break
                    if not sampler.accept(captured.sample_time_seconds):
                        continue
                    event = self.process_frame(captured)
                    active_lifecycle.check()
                    try:
                        sink(event)
                    except Exception as exc:
                        raise WorkerPipelineError("metadata sink failed") from exc
                    emitted += 1
                    active_lifecycle.check()
        except WorkerPipelineError:
            raise
        except Exception as exc:
            raise WorkerPipelineError("local worker pipeline failed") from exc
        return emitted


class _NullWorkerLifecycle:
    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> Literal[False]:
        return False

    def check(self) -> None:
        return None


class _SamplingGate:
    def __init__(self, sample_fps: float) -> None:
        rate = _positive_finite(sample_fps, "worker sample rate")
        self._interval_seconds = 1.0 / rate
        self._last_observed: float | None = None
        self._next_allowed: float | None = None

    def accept(self, timestamp: float) -> bool:
        current = _nonnegative_finite(timestamp, "frame sample timing")
        if self._last_observed is not None and current < self._last_observed:
            raise WorkerPipelineError("frame sample timing moved backwards")
        self._last_observed = current
        if self._next_allowed is not None and current < self._next_allowed:
            return False
        self._next_allowed = current + self._interval_seconds
        return True


def _optional_positive_capture_value(
    capture: CaptureBackend,
    property_id: int | None,
) -> float | None:
    if property_id is None:
        return None
    try:
        value = float(capture.get(property_id))
    except Exception:
        return None
    return value if math.isfinite(value) and value > 0.0 else None


def _release_quietly(capture: CaptureBackend) -> None:
    try:
        capture.release()
    except Exception:
        pass


def _monotonic_value(clock: MonotonicClock, label: str) -> float:
    try:
        value = clock()
    except Exception as exc:
        raise WorkerPipelineError(f"{label} failed") from exc
    return _nonnegative_finite(value, label)


def _elapsed_ms(started: float, finished: float, label: str) -> float:
    if finished < started:
        raise WorkerPipelineError(f"{label} moved backwards")
    elapsed = (finished - started) * 1_000.0
    return _nonnegative_finite(elapsed, label)


def _nonnegative_finite(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise WorkerPipelineError(f"{label} is invalid")
    try:
        number = float(value)
    except (OverflowError, TypeError, ValueError) as exc:
        raise WorkerPipelineError(f"{label} is invalid") from exc
    if not math.isfinite(number) or number < 0.0:
        raise WorkerPipelineError(f"{label} is invalid")
    return number


def _positive_finite(value: object, label: str) -> float:
    number = _nonnegative_finite(value, label)
    if number <= 0.0:
        raise WorkerPipelineError(f"{label} is invalid")
    return number


def _safe_identifier(value: object, label: str) -> str:
    try:
        return TypeAdapter(SafeIdentifier).validate_python(value, strict=True)
    except Exception as exc:
        raise WorkerPipelineError(f"{label} is invalid") from exc


def _factory_identifier(factory: IdentifierFactory, label: str) -> str:
    try:
        value = factory()
    except Exception as exc:
        raise WorkerPipelineError(f"{label} factory failed") from exc
    return _safe_identifier(value, label)


def _utc_timestamp(clock: UtcClock) -> datetime:
    try:
        value = clock()
    except Exception as exc:
        raise WorkerPipelineError("worker UTC clock failed") from exc
    if not isinstance(value, datetime):
        raise WorkerPipelineError("worker UTC clock is invalid")
    try:
        offset = value.utcoffset()
    except Exception as exc:
        raise WorkerPipelineError("worker UTC clock is invalid") from exc
    if value.tzinfo is None or offset != timedelta(0):
        raise WorkerPipelineError("worker UTC clock must return UTC")
    return value


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _new_event_id() -> str:
    return f"event-{uuid4().hex}"


def _new_nonce() -> str:
    return f"nonce-{secrets.token_hex(16)}"


__all__ = [
    "CapturedFrame",
    "CaptureBackend",
    "CaptureFactory",
    "EventSink",
    "FrameDetector",
    "FrameSource",
    "IdentifierFactory",
    "MonotonicClock",
    "OpenCvFrameSource",
    "PrivacyWorkerPipeline",
    "UtcClock",
    "WorkerLifecycle",
    "WorkerPipelineError",
]
