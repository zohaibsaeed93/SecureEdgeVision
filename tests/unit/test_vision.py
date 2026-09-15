from __future__ import annotations

import hashlib
import importlib
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import numpy as np
import pytest
from secureedge.config import VisionSettings
from secureedge.vision import LocalYoloDetector, VisionError


class FakeTensor:
    def __init__(self, value: Any) -> None:
        self.value = value

    def tolist(self) -> Any:
        return self.value


class FakeBoxes:
    def __init__(
        self,
        xyxy: Any,
        conf: Any,
        cls: Any,
        track_ids: Any = None,
    ) -> None:
        self.xyxy = FakeTensor(xyxy)
        self.conf = FakeTensor(conf)
        self.cls = FakeTensor(cls)
        self.id = None if track_ids is None else FakeTensor(track_ids)


class FakeModel:
    names = {0: "person", 2: "car"}

    def __init__(
        self,
        results: Any,
        *,
        mutate: bool = False,
        failure: Exception | None = None,
    ) -> None:
        self.results = results
        self.mutate = mutate
        self.failure = failure
        self.calls: list[tuple[Any, dict[str, Any]]] = []

    def __call__(self, frame: Any, **kwargs: Any) -> Any:
        self.calls.append((frame, kwargs))
        if self.mutate:
            frame[...] = 255
        if self.failure is not None:
            raise self.failure
        return self.results


def _settings() -> VisionSettings:
    return VisionSettings(
        model="yolo26n.pt",
        device="cpu",
        image_size=640,
        confidence=0.25,
        frame_sample_fps=2.0,
    )


def _weights(tmp_path: Path) -> Path:
    path = tmp_path / "yolo26n.pt"
    path.write_bytes(b"test-weight-bytes")
    return path


def _result(*, boxes: Any, names: Any = None) -> SimpleNamespace:
    result = SimpleNamespace(boxes=boxes)
    if names is not None:
        result.names = names
    return result


def _detector(
    tmp_path: Path,
    boxes: Any,
    *,
    names: Any = None,
    mutate: bool = False,
    failure: Exception | None = None,
) -> tuple[LocalYoloDetector, FakeModel]:
    model = FakeModel([_result(boxes=boxes, names=names)], mutate=mutate, failure=failure)
    detector = LocalYoloDetector(
        _settings(),
        model=model,
        weights_path=_weights(tmp_path),
    )
    return detector, model


def test_infers_normalized_metadata_with_exact_configured_arguments(tmp_path: Path) -> None:
    boxes = FakeBoxes(
        xyxy=[[-10.0, 5.0, 210.0, 90.0], [20.0, 10.0, 100.0, 50.0]],
        conf=[0.9, 0.8],
        cls=[0.0, 2.0],
        track_ids=[7.0, None],
    )
    detector, model = _detector(tmp_path, boxes, names={0: "person", 2: "car"})
    frame = np.zeros((100, 200, 3), dtype=np.uint8)

    result = detector.infer(frame)

    assert model.calls[0][1] == {"device": "cpu", "imgsz": 640, "conf": 0.25}
    assert model.calls[0][0] is not frame
    assert result.frame.width == 200
    assert result.frame.height == 100
    assert result.model.name == "yolo26n.pt"
    assert result.model.sha256 == hashlib.sha256(b"test-weight-bytes").hexdigest()
    assert [d.class_id for d in result.detections] == [0, 2]
    assert result.detections[0].bbox_xyxy_norm == [0.0, 0.05, 1.0, 0.9]
    assert result.detections[0].track_id == 7
    assert result.detections[1].track_id is None


def test_below_threshold_is_filtered_and_boundary_is_retained(tmp_path: Path) -> None:
    boxes = FakeBoxes(
        xyxy=[[1.0, 1.0, 20.0, 20.0], [2.0, 2.0, 30.0, 30.0]],
        conf=[0.25, 0.249],
        cls=[0, 0],
    )
    detector, _ = _detector(tmp_path, boxes, names={0: "person"})

    result = detector.infer(np.zeros((40, 40, 3), dtype=np.uint8))

    assert len(result.detections) == 1
    assert result.detections[0].confidence == 0.25


def test_empty_detection_output_is_successful(tmp_path: Path) -> None:
    detector, _ = _detector(
        tmp_path,
        FakeBoxes(xyxy=[], conf=[], cls=[]),
        names={},
    )

    result = detector.infer(np.zeros((8, 8, 3), dtype=np.uint8))

    assert result.detections == ()


def test_absent_optional_metadata_uses_safe_defaults(tmp_path: Path) -> None:
    boxes = SimpleNamespace(
        xyxy=FakeTensor([[1.0, 1.0, 4.0, 4.0]]),
        conf=FakeTensor([0.9]),
        cls=FakeTensor([0]),
    )
    detector, _ = _detector(tmp_path, boxes)

    result = detector.infer(np.zeros((5, 5, 3), dtype=np.uint8))

    assert result.detections[0].class_name == "person"
    assert result.detections[0].track_id is None


@pytest.mark.parametrize(
    "bad_boxes",
    [
        FakeBoxes(xyxy=[[1.0, 1.0, 2.0, 2.0]], conf=[], cls=[0]),
        FakeBoxes(
            xyxy=[[1.0, 1.0, 2.0, 2.0]],
            conf=[0.9],
            cls=[0],
            track_ids=[1, 2],
        ),
        FakeBoxes(xyxy=[[1.0, 1.0, 2.0]], conf=[0.9], cls=[0]),
        FakeBoxes(
            xyxy=[[1.0, 1.0, float("nan"), 2.0]],
            conf=[0.9],
            cls=[0],
        ),
        FakeBoxes(
            xyxy=[[3.0, 1.0, 2.0, 2.0]],
            conf=[0.9],
            cls=[0],
        ),
    ],
)
def test_malformed_backend_output_fails_closed(tmp_path: Path, bad_boxes: FakeBoxes) -> None:
    detector, _ = _detector(tmp_path, bad_boxes, names={0: "person"})

    with pytest.raises(VisionError):
        detector.infer(np.zeros((10, 10, 3), dtype=np.uint8))


def test_unknown_class_multiple_results_and_backend_failure_are_rejected(tmp_path: Path) -> None:
    path = _weights(tmp_path)
    unknown_model = FakeModel(
        [_result(boxes=FakeBoxes([[1.0, 1.0, 2.0, 2.0]], [0.9], [9]))],
    )
    unknown = LocalYoloDetector(_settings(), model=unknown_model, weights_path=path)
    with pytest.raises(VisionError, match="unknown class"):
        unknown.infer(np.zeros((10, 10, 3), dtype=np.uint8))

    multiple_model = FakeModel(
        [
            _result(boxes=FakeBoxes([[1.0, 1.0, 2.0, 2.0]], [0.9], [0])),
            _result(boxes=FakeBoxes([[1.0, 1.0, 2.0, 2.0]], [0.9], [0])),
        ],
    )
    multiple = LocalYoloDetector(_settings(), model=multiple_model, weights_path=path)
    with pytest.raises(VisionError, match="exactly one result"):
        multiple.infer(np.zeros((10, 10, 3), dtype=np.uint8))

    failing_model = FakeModel(
        [_result(boxes=FakeBoxes([], [], []))],
        failure=RuntimeError("frame bytes must not leak"),
    )
    failing = LocalYoloDetector(_settings(), model=failing_model, weights_path=path)
    with pytest.raises(VisionError, match="inference failed") as exc_info:
        failing.infer(np.zeros((10, 10, 3), dtype=np.uint8))
    assert "frame bytes" not in str(exc_info.value)


def test_invalid_frames_hashes_and_input_mutation_fail_closed(tmp_path: Path) -> None:
    detector, _ = _detector(
        tmp_path,
        FakeBoxes(xyxy=[], conf=[], cls=[]),
    )
    with pytest.raises(VisionError):
        detector.infer(None)
    with pytest.raises(VisionError):
        detector.infer(np.zeros((0, 10, 3), dtype=np.uint8))
    with pytest.raises(VisionError):
        detector.infer(np.zeros((10, 10, 2), dtype=np.uint8))
    with pytest.raises(VisionError):
        detector.infer(np.zeros((10, 10, 3), dtype=object))

    mutating_detector, _ = _detector(
        tmp_path,
        FakeBoxes(xyxy=[], conf=[], cls=[]),
        mutate=True,
    )
    original = np.zeros((10, 10, 3), dtype=np.uint8)
    before = original.copy()
    mutating_detector.infer(original)
    assert np.array_equal(original, before)

    with pytest.raises(VisionError, match="weights"):
        LocalYoloDetector(_settings(), model=FakeModel([]))

    missing_path = tmp_path / "missing.pt"
    with pytest.raises(VisionError, match="weights"):
        LocalYoloDetector(_settings(), model=FakeModel([]), weights_path=missing_path)


def test_importing_vision_does_not_load_runtime_services_or_models(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import os
    import pathlib
    import socket
    import sqlite3

    def fail(*args: object, **kwargs: object) -> None:
        raise AssertionError("vision import performed an external side effect")

    real_getenv = os.getenv

    def guarded_getenv(key: str, default: str | None = None) -> str | None:
        if key.startswith("SEV_"):
            raise AssertionError("vision import inspected configuration environment")
        return real_getenv(key, default)

    unloaded = {name for name in ("cv2", "ultralytics") if name not in sys.modules}
    monkeypatch.setattr(pathlib.Path, "read_text", fail)
    monkeypatch.setattr(os, "getenv", guarded_getenv)
    monkeypatch.setattr(socket, "socket", fail)
    monkeypatch.setattr(sqlite3, "connect", fail)

    module = importlib.import_module("secureedge.vision")
    importlib.reload(module)

    assert unloaded.isdisjoint(sys.modules)
