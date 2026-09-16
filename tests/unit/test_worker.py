from __future__ import annotations

import importlib
import json
import os
import pathlib
import socket
import sqlite3
import threading
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path
from typing import Any

import numpy as np
import pytest
from apps.worker.main import run_cli
from secureedge.config import VisionSettings
from secureedge.contracts import Detection, FrameMetadata, ModelMetadata
from secureedge.vision import VisionError, VisionResult
from secureedge.worker import (
    CapturedFrame,
    OpenCvFrameSource,
    PrivacyWorkerPipeline,
    WorkerPipelineError,
)


def _settings(*, sample_fps: float = 2.0) -> VisionSettings:
    return VisionSettings(
        model="yolo26n.pt",
        device="cpu",
        image_size=640,
        confidence=0.25,
        frame_sample_fps=sample_fps,
    )


def _vision_result(*, detections: tuple[Detection, ...] = ()) -> VisionResult:
    return VisionResult(
        frame=FrameMetadata(width=20, height=10),
        model=ModelMetadata(name="yolo26n.pt", sha256="a" * 64),
        detections=detections,
    )


class SequenceClock:
    def __init__(self, values: list[float]) -> None:
        self._values = iter(values)

    def __call__(self) -> float:
        return next(self._values)


class StepClock:
    def __init__(self, start: float = 0.0, step: float = 0.001) -> None:
        self._value = start
        self._step = step

    def __call__(self) -> float:
        value = self._value
        self._value += self._step
        return value


def _factory(values: list[str]) -> Callable[[], str]:
    iterator: Iterator[str] = iter(values)
    return lambda: next(iterator)


class FakeDetector:
    def __init__(
        self,
        results: list[VisionResult] | None = None,
        *,
        failure: Exception | None = None,
    ) -> None:
        self.results = list(results or [_vision_result()])
        self.failure = failure
        self.calls: list[Any] = []

    def infer(self, frame: Any) -> VisionResult:
        self.calls.append(frame)
        if self.failure is not None:
            raise self.failure
        if len(self.results) > 1:
            return self.results.pop(0)
        return self.results[0]


class FakeSource:
    def __init__(self, values: list[CapturedFrame | BaseException | None]) -> None:
        self._values = iter(values)
        self.entered = False
        self.released = False

    def __enter__(self) -> FakeSource:
        self.entered = True
        return self

    def __exit__(self, *_args: object) -> bool:
        self.released = True
        return False

    def read(self) -> CapturedFrame | None:
        value = next(self._values, None)
        if isinstance(value, BaseException):
            raise value
        return value


def _pipeline(
    detector: FakeDetector,
    *,
    sample_fps: float = 2.0,
    monotonic_clock: Callable[[], float] | None = None,
    utc_clock: Callable[[], datetime] | None = None,
    event_ids: list[str] | None = None,
    nonces: list[str] | None = None,
) -> PrivacyWorkerPipeline:
    return PrivacyWorkerPipeline(
        node_id="edge-1",
        camera_id="cam-1",
        settings=_settings(sample_fps=sample_fps),
        detector=detector,
        monotonic_clock=monotonic_clock or StepClock(),
        utc_clock=utc_clock or (lambda: datetime(2026, 9, 15, 12, 0, tzinfo=UTC)),
        event_id_factory=_factory(event_ids or ["event-1", "event-2", "event-3"]),
        nonce_factory=_factory(nonces or ["nonce-1", "nonce-2", "nonce-3"]),
    )


def _captured(sample_time: float, *, decode_ms: float = 4.5) -> CapturedFrame:
    return CapturedFrame(
        frame=np.zeros((10, 20, 3), dtype=np.uint8),
        decode_ms=decode_ms,
        sample_time_seconds=sample_time,
    )


def test_process_frame_builds_strict_metadata_event_with_honest_timings() -> None:
    detection = Detection(
        class_id=0,
        class_name="person",
        confidence=0.9,
        bbox_xyxy_norm=[0.1, 0.2, 0.8, 0.9],
        track_id=7,
    )
    detector = FakeDetector([_vision_result(detections=(detection,))])
    pipeline = _pipeline(
        detector,
        monotonic_clock=SequenceClock([1.0, 1.25, 2.0, 2.1]),
    )
    captured = _captured(0.0)
    original_frame = captured.frame.copy()

    event = pipeline.process_frame(captured)

    assert event.schema_version == "1.0"
    assert event.event_id == "event-1"
    assert event.node_id == "edge-1"
    assert event.camera_id == "cam-1"
    assert event.timestamp_utc == datetime(2026, 9, 15, 12, 0, tzinfo=UTC)
    assert event.nonce == "nonce-1"
    assert event.frame_seq == 0
    assert event.job_id is None
    assert event.mode == "privacy"
    assert event.model == detector.results[0].model
    assert event.frame == detector.results[0].frame
    assert event.detections == [detection]
    assert event.performance.decode_ms == 4.5
    assert event.performance.inference_ms == 250.0
    assert event.performance.postprocess_ms == pytest.approx(100.0)
    np.testing.assert_array_equal(captured.frame, original_frame)
    assert "frame" not in repr(captured)
    assert "pixels" not in event.model_dump_json()


def test_successive_events_preserve_order_empty_results_and_sequence() -> None:
    first = Detection(
        class_id=2,
        class_name="car",
        confidence=0.8,
        bbox_xyxy_norm=[0.0, 0.0, 0.5, 0.5],
    )
    second = Detection(
        class_id=0,
        class_name="person",
        confidence=0.7,
        bbox_xyxy_norm=[0.5, 0.5, 1.0, 1.0],
    )
    detector = FakeDetector(
        [_vision_result(detections=(first, second)), _vision_result()]
    )
    timestamps = iter(
        [
            datetime(2026, 9, 15, 12, 0, tzinfo=UTC),
            datetime(2026, 9, 15, 12, 0, 1, tzinfo=UTC),
        ]
    )
    pipeline = _pipeline(detector, utc_clock=lambda: next(timestamps))

    event_one = pipeline.process_frame(_captured(0.0))
    event_two = pipeline.process_frame(_captured(0.5))

    assert [item.class_id for item in event_one.detections] == [2, 0]
    assert event_two.detections == []
    assert (event_one.event_id, event_two.event_id) == ("event-1", "event-2")
    assert (event_one.nonce, event_two.nonce) == ("nonce-1", "nonce-2")
    assert event_two.timestamp_utc > event_one.timestamp_utc
    assert (event_one.frame_seq, event_two.frame_seq) == (0, 1)
    assert pipeline.next_frame_seq == 2


def test_duplicate_identity_fails_closed_without_consuming_sequence() -> None:
    detector = FakeDetector()
    pipeline = _pipeline(
        detector,
        event_ids=["same-event", "same-event"],
        nonces=["nonce-1", "nonce-2"],
    )
    pipeline.process_frame(_captured(0.0))

    with pytest.raises(WorkerPipelineError, match="reused"):
        pipeline.process_frame(_captured(0.5))

    assert pipeline.next_frame_seq == 1


@pytest.mark.parametrize(
    "clock",
    [
        lambda: datetime(2026, 9, 15, 12, 0),
        lambda: "2026-09-15T12:00:00Z",  # type: ignore[return-value]
    ],
)
def test_invalid_utc_clock_fails_without_event(clock: Callable[[], datetime]) -> None:
    pipeline = _pipeline(FakeDetector(), utc_clock=clock)

    with pytest.raises(WorkerPipelineError, match="UTC clock"):
        pipeline.process_frame(_captured(0.0))

    assert pipeline.next_frame_seq == 0


def test_detector_failure_is_sanitized_and_preserves_cause() -> None:
    detector = FakeDetector(failure=VisionError("raw frame values 1,2,3"))
    pipeline = _pipeline(detector)

    with pytest.raises(WorkerPipelineError, match="local detection failed") as exc_info:
        pipeline.process_frame(_captured(0.0))

    assert "1,2,3" not in str(exc_info.value)
    assert isinstance(exc_info.value.__cause__, VisionError)
    assert pipeline.next_frame_seq == 0


def test_sampling_uses_configured_rate_and_releases_source() -> None:
    detector = FakeDetector()
    pipeline = _pipeline(
        detector,
        sample_fps=2.0,
        event_ids=["event-1", "event-2", "event-3"],
        nonces=["nonce-1", "nonce-2", "nonce-3"],
    )
    source = FakeSource(
        [
            _captured(0.0),
            _captured(0.49),
            _captured(0.5),
            _captured(0.999),
            _captured(1.0),
            None,
        ]
    )
    events: list[Any] = []

    count = pipeline.run(source, events.append)

    assert count == 3
    assert len(detector.calls) == 3
    assert [event.frame_seq for event in events] == [0, 1, 2]
    assert source.entered is True
    assert source.released is True


def test_backwards_sample_time_and_source_failure_release_resources() -> None:
    backwards = FakeSource([_captured(1.0), _captured(0.9)])
    pipeline = _pipeline(FakeDetector())
    with pytest.raises(WorkerPipelineError, match="moved backwards"):
        pipeline.run(backwards, lambda _event: None)
    assert backwards.released is True

    failing = FakeSource([WorkerPipelineError("safe source failure")])
    with pytest.raises(WorkerPipelineError, match="safe source failure"):
        _pipeline(FakeDetector()).run(failing, lambda _event: None)
    assert failing.released is True

    interrupted = FakeSource([KeyboardInterrupt()])
    with pytest.raises(KeyboardInterrupt):
        _pipeline(FakeDetector()).run(interrupted, lambda _event: None)
    assert interrupted.released is True


def test_event_bound_and_sink_failure_release_resources() -> None:
    bounded = FakeSource([_captured(0.0), _captured(1.0), _captured(2.0)])
    pipeline = _pipeline(FakeDetector())
    events: list[Any] = []
    assert pipeline.run(bounded, events.append, max_events=1) == 1
    assert bounded.released is True
    assert len(events) == 1

    failing_sink_source = FakeSource([_captured(0.0)])
    with pytest.raises(WorkerPipelineError, match="metadata sink failed") as exc_info:
        _pipeline(FakeDetector()).run(
            failing_sink_source,
            lambda _event: (_ for _ in ()).throw(RuntimeError("payload secret")),
        )
    assert "payload secret" not in str(exc_info.value)
    assert failing_sink_source.released is True

    invalid_event_source = FakeSource([_captured(0.0)])
    invalid_event_pipeline = PrivacyWorkerPipeline(
        node_id="edge-1",
        camera_id="cam-1",
        settings=_settings(),
        detector=FakeDetector(),
        monotonic_clock=StepClock(),
        event_id_factory=lambda: "invalid event identifier",
    )
    emitted: list[Any] = []
    with pytest.raises(WorkerPipelineError, match="event identifier"):
        invalid_event_pipeline.run(invalid_event_source, emitted.append)
    assert emitted == []
    assert invalid_event_pipeline.next_frame_seq == 0
    assert invalid_event_source.released is True


class FakeCapture:
    def __init__(
        self,
        reads: list[tuple[bool, Any]],
        *,
        opened: bool = True,
        fps: float = 10.0,
        frame_count: float = 2.0,
    ) -> None:
        self._reads = iter(reads)
        self._opened = opened
        self._fps = fps
        self._frame_count = frame_count
        self.release_count = 0

    def isOpened(self) -> bool:
        return self._opened

    def read(self) -> tuple[bool, Any]:
        return next(self._reads)

    def get(self, property_id: int) -> float:
        return {5: self._fps, 7: self._frame_count}[property_id]

    def release(self) -> None:
        self.release_count += 1


def test_opencv_file_source_uses_content_timeline_and_clean_eof(tmp_path: Path) -> None:
    media = tmp_path / "local.mp4"
    media.write_bytes(b"local-test-placeholder")
    frame_one = np.zeros((2, 2, 3), dtype=np.uint8)
    frame_two = np.ones((2, 2, 3), dtype=np.uint8)
    capture = FakeCapture([(True, frame_one), (True, frame_two), (False, None)])
    factory_calls: list[int | str] = []

    def factory(source: int | str) -> FakeCapture:
        factory_calls.append(source)
        return capture

    source = OpenCvFrameSource(
        media,
        capture_factory=factory,
        monotonic_clock=SequenceClock([1.0, 1.01, 2.0, 2.02, 3.0, 3.01]),
        fps_property=5,
        frame_count_property=7,
    )

    with source:
        first = source.read()
        second = source.read()
        eof = source.read()

    assert factory_calls == [str(media)]
    assert first is not None and first.sample_time_seconds == 0.0
    assert second is not None and second.sample_time_seconds == 0.1
    assert first.decode_ms == pytest.approx(10.0)
    assert second.decode_ms == pytest.approx(20.0)
    assert eof is None
    assert capture.release_count == 1


def test_opencv_source_distinguishes_early_eof_and_camera_failure(tmp_path: Path) -> None:
    media = tmp_path / "local.mp4"
    media.write_bytes(b"local-test-placeholder")
    short_capture = FakeCapture([(True, object()), (False, None)], frame_count=2.0)
    file_source = OpenCvFrameSource(
        media,
        capture_factory=lambda _source: short_capture,
        monotonic_clock=StepClock(),
        fps_property=5,
        frame_count_property=7,
    )
    with pytest.raises(WorkerPipelineError, match="declared frame count"):
        with file_source:
            assert file_source.read() is not None
            file_source.read()
    assert short_capture.release_count == 1

    camera_capture = FakeCapture([(False, None)], frame_count=0.0)
    camera_source = OpenCvFrameSource(
        0,
        capture_factory=lambda _source: camera_capture,
        monotonic_clock=StepClock(),
    )
    with pytest.raises(WorkerPipelineError, match="camera frame acquisition"):
        with camera_source:
            camera_source.read()
    assert camera_capture.release_count == 1

    closed_capture = FakeCapture([], opened=False)
    closed_source = OpenCvFrameSource(
        0,
        capture_factory=lambda _source: closed_capture,
        monotonic_clock=StepClock(),
    )
    with pytest.raises(WorkerPipelineError, match="could not be opened"):
        with closed_source:
            pass
    assert closed_capture.release_count == 1


def test_opencv_source_releases_capture_when_open_validation_raises() -> None:
    class FailingOpenCapture(FakeCapture):
        def isOpened(self) -> bool:
            raise RuntimeError("sensitive backend source detail")

    capture = FailingOpenCapture([])
    source = OpenCvFrameSource(
        0,
        capture_factory=lambda _source: capture,
        monotonic_clock=StepClock(),
    )

    with pytest.raises(WorkerPipelineError) as error:
        with source:
            pass

    assert str(error.value) == "local frame source could not be opened"
    assert "sensitive" not in str(error.value)
    assert isinstance(error.value.__cause__, RuntimeError)
    assert capture.release_count == 1


def test_opencv_source_rejects_remote_sources_and_has_no_constructor_io() -> None:
    calls: list[int | str] = []
    with pytest.raises(WorkerPipelineError, match="local media source"):
        OpenCvFrameSource("https://example.test/frame.mp4")
    with pytest.raises(WorkerPipelineError, match="camera index"):
        OpenCvFrameSource(-1)

    OpenCvFrameSource("not-opened-yet.mp4", capture_factory=lambda value: calls.append(value))  # type: ignore[arg-type]
    assert calls == []


def _write_config(path: Path) -> None:
    path.write_text(
        """mode: privacy
aggregator_url: http://aggregator:8000
security:
  max_clock_skew_seconds: 30
  nonce_ttl_seconds: 300
  max_request_bytes: 262144
vision:
  model: yolo26n.pt
  device: cpu
  image_size: 640
  confidence: 0.25
  frame_sample_fps: 2
consensus:
  policy: trust_weighted
  iou_threshold: 0.5
  accept_threshold: 0.6
  alpha: 0.85
  trust_min: 0.05
""",
        encoding="utf-8",
    )


def test_cli_emits_only_unsigned_metadata_json_lines(tmp_path: Path) -> None:
    config = tmp_path / "system.yaml"
    _write_config(config)
    output = StringIO()
    errors = StringIO()
    received_sources: list[int | str | Path] = []

    def source_factory(value: int | str | Path) -> FakeSource:
        received_sources.append(value)
        return FakeSource([_captured(0.0), None])

    code = run_cli(
        [
            "--config",
            str(config),
            "--node-id",
            "edge-1",
            "--camera-id",
            "cam-1",
            "--source",
            "camera:0",
            "--max-events",
            "1",
        ],
        environ={},
        stdout=output,
        stderr=errors,
        detector_factory=lambda _settings: FakeDetector(),
        source_factory=source_factory,
    )

    payload = json.loads(output.getvalue())
    assert code == 0
    assert errors.getvalue() == ""
    assert received_sources == [0]
    assert payload["node_id"] == "edge-1"
    assert payload["camera_id"] == "cam-1"
    assert payload["mode"] == "privacy"
    assert payload["job_id"] is None
    assert "signature_b64" not in payload
    assert "image" not in payload


def test_cli_failure_is_nonzero_and_does_not_echo_underlying_error(tmp_path: Path) -> None:
    config = tmp_path / "system.yaml"
    _write_config(config)
    errors = StringIO()

    def fail(_settings: VisionSettings) -> FakeDetector:
        raise VisionError("private source details")

    code = run_cli(
        [
            "--config",
            str(config),
            "--node-id",
            "edge-1",
            "--camera-id",
            "cam-1",
            "--source",
            str(tmp_path / "local.mp4"),
        ],
        environ={},
        stdout=StringIO(),
        stderr=errors,
        detector_factory=fail,
    )

    assert code == 2
    assert "private source details" not in errors.getvalue()
    assert "stopped safely" in errors.getvalue()


def test_invalid_identity_settings_and_frame_metadata_fail_closed() -> None:
    with pytest.raises(WorkerPipelineError, match="node identity"):
        PrivacyWorkerPipeline(
            node_id="bad node",
            camera_id="cam-1",
            settings=_settings(),
            detector=FakeDetector(),
        )

    pipeline = _pipeline(FakeDetector())
    with pytest.raises(WorkerPipelineError, match="decode timing"):
        pipeline.process_frame(_captured(0.0, decode_ms=float("nan")))
    with pytest.raises(WorkerPipelineError, match="maximum event count"):
        pipeline.run(FakeSource([None]), lambda _event: None, max_events=0)


def test_worker_imports_have_no_runtime_side_effects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker_module = importlib.import_module("secureedge.worker")
    cli_module = importlib.import_module("apps.worker.main")

    def fail(*_args: object, **_kwargs: object) -> Any:
        raise AssertionError("worker import performed a runtime side effect")

    monkeypatch.setattr(pathlib.Path, "read_text", fail)
    monkeypatch.setattr(pathlib.Path, "is_file", fail)
    monkeypatch.setattr(importlib, "import_module", fail)
    monkeypatch.setattr(os, "getenv", fail)
    monkeypatch.setattr(socket, "socket", fail)
    monkeypatch.setattr(sqlite3, "connect", fail)
    monkeypatch.setattr(threading.Thread, "start", fail)

    worker_module = importlib.reload(worker_module)
    cli_module = importlib.reload(cli_module)

    assert worker_module.__name__ == "secureedge.worker"
    assert cli_module.__name__ == "apps.worker.main"
