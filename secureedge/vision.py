"""Local, metadata-only Ultralytics YOLO inference for the privacy path."""

from __future__ import annotations

import hashlib
import importlib
import math
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from secureedge.config import VisionSettings
from secureedge.contracts import Detection, FrameMetadata, ModelMetadata

_MISSING = object()


class VisionError(RuntimeError):
    """Raised when local inference cannot produce safe normalized metadata."""


class DetectorBackend(Protocol):
    """Small callable boundary implemented by an Ultralytics YOLO model."""

    def __call__(
        self,
        source: Any,
        *,
        device: str,
        imgsz: int,
        conf: float,
    ) -> Any:
        ...


ModelFactory = Callable[[VisionSettings], Any]


@dataclass(frozen=True, slots=True)
class VisionResult:
    """Typed metadata returned by one local detector invocation."""

    frame: FrameMetadata
    model: ModelMetadata
    detections: tuple[Detection, ...]

    @property
    def frame_metadata(self) -> FrameMetadata:
        """Return the original input frame dimensions."""

        return self.frame

    @property
    def model_metadata(self) -> ModelMetadata:
        """Return the configured model identity and local-weight digest."""

        return self.model


class LocalYoloDetector:
    """Run one explicit Ultralytics YOLO inference without exporting the frame.

    The model is constructed only when this class is instantiated. The caller
    supplies one in-memory OpenCV-compatible NumPy array to infer; the returned
    value contains dimensions, model metadata, and normalized detections only.
    Tests may inject a callable model and an explicit weight path.
    """

    def __init__(
        self,
        settings: VisionSettings,
        *,
        model: Any | None = None,
        model_factory: ModelFactory | None = None,
        weights_path: str | Path | None = None,
        weight_path: str | Path | None = None,
    ) -> None:
        if model is not None and model_factory is not None:
            raise VisionError("provide either a model or model factory, not both")
        if weights_path is not None and weight_path is not None:
            raise VisionError("provide either weights_path or weight_path, not both")

        self._settings = _validated_vision_settings(settings)
        factory = model_factory or _load_ultralytics_model

        if model is None:
            try:
                backend = factory(self._settings)
            except VisionError:
                raise
            except Exception as exc:
                raise VisionError("unable to construct the configured YOLO model") from exc
        else:
            backend = model

        if not callable(backend) and not callable(_optional_attr(backend, "predict")):
            raise VisionError("configured YOLO model is not callable")

        requested_weight_path = weights_path if weights_path is not None else weight_path
        resolved_weight_path = _resolve_weights_path(
            self._settings,
            backend,
            requested_weight_path,
        )
        self._model = backend
        self._model_metadata = ModelMetadata(
            name=_safe_model_name(self._settings.model),
            sha256=_sha256_file(resolved_weight_path),
        )

    @property
    def settings(self) -> VisionSettings:
        """Return the validated settings used for every inference call."""

        return self._settings

    def infer(self, frame: Any) -> VisionResult:
        """Run exactly one local inference and return metadata-only output."""

        height, width = _validate_frame(frame)
        try:
            protected_frame = frame.copy()
        except Exception as exc:
            raise VisionError("input frame could not be safely copied") from exc

        raw_results = self._run_model(protected_frame)
        detections = _convert_results(
            raw_results,
            width=width,
            height=height,
            confidence_threshold=self._settings.confidence,
            backend=self._model,
        )
        return VisionResult(
            frame=FrameMetadata(width=width, height=height),
            model=self._model_metadata,
            detections=tuple(detections),
        )

    predict = infer
    detect = infer

    def __call__(self, frame: Any) -> VisionResult:
        """Allow the detector to be used as a one-frame callable."""

        return self.infer(frame)

    def _run_model(self, frame: Any) -> Any:
        runner = self._model if callable(self._model) else _optional_attr(self._model, "predict")
        if not callable(runner):
            raise VisionError("configured YOLO model is not callable")
        try:
            return runner(
                frame,
                device=_ultralytics_device(self._settings.device),
                imgsz=self._settings.image_size,
                conf=self._settings.confidence,
            )
        except Exception as exc:
            raise VisionError("local YOLO inference failed") from exc


def _ultralytics_device(configured_device: str) -> str:
    """Translate the config sentinel to Ultralytics' automatic selector."""

    return "" if configured_device == "auto" else configured_device


YoloDetector = LocalYoloDetector
LocalYOLODetector = LocalYoloDetector


def create_yolo_detector(
    settings: VisionSettings,
    *,
    model: Any | None = None,
    model_factory: ModelFactory | None = None,
    weights_path: str | Path | None = None,
) -> LocalYoloDetector:
    """Construct the explicit local YOLO detector boundary."""

    return LocalYoloDetector(
        settings,
        model=model,
        model_factory=model_factory,
        weights_path=weights_path,
    )


def infer_frame(
    frame: Any,
    settings: VisionSettings,
    *,
    detector: LocalYoloDetector | None = None,
    model: Any | None = None,
    model_factory: ModelFactory | None = None,
    weights_path: str | Path | None = None,
) -> VisionResult:
    """Construct or reuse a detector and infer one caller-supplied frame."""

    if detector is not None and any(
        value is not None for value in (model, model_factory, weights_path)
    ):
        raise VisionError("provide a detector or detector construction arguments, not both")
    active_detector = detector or create_yolo_detector(
        settings,
        model=model,
        model_factory=model_factory,
        weights_path=weights_path,
    )
    return active_detector.infer(frame)


detect_frame = infer_frame


def _load_ultralytics_model(settings: VisionSettings) -> Any:
    try:
        from ultralytics import YOLO

        return YOLO(settings.model)
    except Exception as exc:
        raise VisionError("unable to load Ultralytics YOLO weights") from exc


def _validated_vision_settings(settings: VisionSettings) -> VisionSettings:
    if not isinstance(settings, VisionSettings):
        raise VisionError("vision settings must be validated")
    try:
        return VisionSettings.model_validate(
            settings.model_dump(mode="python"),
            strict=True,
        )
    except Exception:
        raise VisionError("vision settings are invalid") from None


def _safe_model_name(configured_name: str) -> str:
    name = Path(configured_name).name
    if not name or name in {".", ".."}:
        raise VisionError("configured YOLO model name is invalid")
    return name


def _resolve_weights_path(
    settings: VisionSettings,
    backend: Any,
    requested: str | Path | None,
) -> Path:
    if requested is not None:
        path = _path_if_file(requested)
        if path is None:
            raise VisionError("configured YOLO weights are unavailable")
        return path

    configured_path = _path_if_file(settings.model)
    if configured_path is not None:
        return configured_path

    for attribute in ("ckpt_path", "weight_path", "weights_path", "model_path"):
        candidate = _path_if_file(_optional_attr(backend, attribute))
        if candidate is not None:
            return candidate

    raise VisionError("configured YOLO weights are unavailable")


def _path_if_file(candidate: object) -> Path | None:
    if not isinstance(candidate, (str, Path)):
        return None
    try:
        path = Path(candidate).expanduser()
    except (OSError, RuntimeError, TypeError, ValueError):
        return None
    try:
        return path if path.is_file() else None
    except OSError:
        return None


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except (OSError, ValueError) as exc:
        raise VisionError("configured YOLO weights could not be read") from exc
    return digest.hexdigest()


def _validate_frame(frame: Any) -> tuple[int, int]:
    try:
        np: Any = importlib.import_module("numpy")
    except Exception as exc:
        raise VisionError("OpenCV frame support is unavailable") from exc

    if not isinstance(frame, np.ndarray):
        raise VisionError("inference input must be an in-memory NumPy frame")
    if frame.ndim not in (2, 3) or frame.size == 0:
        raise VisionError("inference input must be a non-empty image frame")

    try:
        height = int(frame.shape[0])
        width = int(frame.shape[1])
        dtype_kind = frame.dtype.kind
    except Exception as exc:
        raise VisionError("inference input frame shape or type is invalid") from exc

    if height <= 0 or width <= 0:
        raise VisionError("inference input frame dimensions must be positive")
    if dtype_kind not in "uif":
        raise VisionError("inference input frame must use a numeric image dtype")
    if frame.ndim == 3:
        try:
            channels = int(frame.shape[2])
        except Exception as exc:
            raise VisionError("inference input frame shape is invalid") from exc
        if channels not in (1, 3, 4):
            raise VisionError("inference input frame must have 1, 3, or 4 channels")
    if dtype_kind == "f":
        try:
            finite = bool(np.isfinite(frame).all())
        except Exception as exc:
            raise VisionError("inference input frame values are invalid") from exc
        if not finite:
            raise VisionError("inference input frame values must be finite")

    return height, width


def _convert_results(
    raw_results: Any,
    *,
    width: int,
    height: int,
    confidence_threshold: float,
    backend: Any,
) -> list[Detection]:
    if not isinstance(raw_results, (list, tuple)):
        raise VisionError("YOLO output must contain exactly one result")
    if len(raw_results) != 1:
        raise VisionError("YOLO output must contain exactly one result")

    result = raw_results[0]
    boxes = _required_attr(result, "boxes")
    xyxy_rows = _rows(_required_attr(boxes, "xyxy"), "box coordinates")
    count = len(xyxy_rows)
    confidence_values = _vector(
        _required_attr(boxes, "conf"),
        count,
        "confidence values",
    )
    class_values = _vector(
        _required_attr(boxes, "cls"),
        count,
        "class IDs",
    )

    raw_track_ids = _optional_attr(boxes, "id")
    if raw_track_ids is _MISSING or raw_track_ids is None:
        track_values: list[Any] = [None] * count
    else:
        track_values = _vector(raw_track_ids, count, "track IDs")

    names = _optional_attr(result, "names")
    if names is _MISSING or names is None:
        names = _optional_attr(backend, "names")

    detections: list[Detection] = []
    for index, row in enumerate(xyxy_rows):
        confidence = _finite_number(confidence_values[index], "confidence")
        if confidence < 0.0 or confidence > 1.0:
            raise VisionError("YOLO output confidence is outside the supported range")

        class_id = _nonnegative_integer(class_values[index], "class ID")
        class_name = _class_name(names, class_id)
        normalized_box = _normalize_box(row, width=width, height=height)

        track_value = track_values[index]
        track_id = (
            None
            if track_value is None
            else _nonnegative_integer(track_value, "track ID")
        )

        if confidence < confidence_threshold:
            continue
        try:
            detections.append(
                Detection(
                    class_id=class_id,
                    class_name=class_name,
                    confidence=confidence,
                    bbox_xyxy_norm=normalized_box,
                    track_id=track_id,
                )
            )
        except Exception as exc:
            raise VisionError("YOLO output could not be represented as safe metadata") from exc

    return detections


def _rows(value: Any, label: str) -> list[list[Any]]:
    converted = _to_python(value, label)
    if not isinstance(converted, (list, tuple)):
        raise VisionError(f"YOLO output {label} has an invalid shape")

    rows: list[list[Any]] = []
    for row in converted:
        if not isinstance(row, (list, tuple)) or len(row) != 4:
            raise VisionError(f"YOLO output {label} has an invalid shape")
        rows.append(list(row))
    return rows


def _vector(value: Any, expected_length: int, label: str) -> list[Any]:
    converted = _to_python(value, label)
    if isinstance(converted, (list, tuple)):
        values = list(converted)
    elif expected_length == 1:
        values = [converted]
    else:
        raise VisionError(f"YOLO output {label} has an invalid shape")

    if len(values) != expected_length:
        raise VisionError(f"YOLO output {label} has inconsistent lengths")
    return values


def _to_python(value: Any, label: str) -> Any:
    converted = value
    try:
        detach = getattr(converted, "detach", None)
        if callable(detach):
            converted = detach()
        cpu = getattr(converted, "cpu", None)
        if callable(cpu):
            converted = cpu()
        tolist = getattr(converted, "tolist", None)
        if callable(tolist):
            converted = tolist()
    except Exception as exc:
        raise VisionError(f"YOLO output {label} could not be read") from exc
    return converted


def _normalize_box(row: list[Any], *, width: int, height: int) -> list[float]:
    values = [_finite_number(value, "box coordinate") for value in row]
    x_min, y_min, x_max, y_max = values
    if x_min >= x_max or y_min >= y_max:
        raise VisionError("YOLO output contains a reversed or zero-area box")

    clipped_x_min = min(max(x_min, 0.0), float(width))
    clipped_y_min = min(max(y_min, 0.0), float(height))
    clipped_x_max = min(max(x_max, 0.0), float(width))
    clipped_y_max = min(max(y_max, 0.0), float(height))
    if clipped_x_min >= clipped_x_max or clipped_y_min >= clipped_y_max:
        raise VisionError("YOLO output contains a box outside the frame")

    return [
        clipped_x_min / width,
        clipped_y_min / height,
        clipped_x_max / width,
        clipped_y_max / height,
    ]


def _class_name(names: Any, class_id: int) -> str:
    value: Any = _MISSING
    if isinstance(names, Mapping):
        try:
            value = names.get(class_id, _MISSING)
            if value is _MISSING:
                value = names.get(str(class_id), _MISSING)
        except Exception as exc:
            raise VisionError("YOLO output class names are invalid") from exc
    elif isinstance(names, (list, tuple)) and 0 <= class_id < len(names):
        value = names[class_id]

    if not isinstance(value, str) or not value.strip():
        raise VisionError("YOLO output contains an unknown class ID")
    return value


def _finite_number(value: Any, label: str) -> float:
    if isinstance(value, (bool, str, bytes)):
        raise VisionError(f"YOLO output {label} is not numeric")
    try:
        number = float(value)
    except (OverflowError, TypeError, ValueError) as exc:
        raise VisionError(f"YOLO output {label} is not numeric") from exc
    if not math.isfinite(number):
        raise VisionError(f"YOLO output {label} is not finite")
    return number


def _nonnegative_integer(value: Any, label: str) -> int:
    number = _finite_number(value, label)
    if not number.is_integer() or number < 0.0:
        raise VisionError(f"YOLO output {label} is not a non-negative integer")
    return int(number)


def _required_attr(target: Any, attribute: str) -> Any:
    value = _optional_attr(target, attribute)
    if value is _MISSING:
        raise VisionError("YOLO output is missing required box data")
    return value


def _optional_attr(target: Any, attribute: str) -> Any:
    try:
        return getattr(target, attribute, _MISSING)
    except Exception as exc:
        raise VisionError("YOLO output could not be inspected") from exc


