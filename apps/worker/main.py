"""Thin local-only worker adapter for unsigned privacy metadata."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import TextIO

from secureedge.config import ConfigurationError, VisionSettings, load_settings
from secureedge.contracts import DetectionEvent
from secureedge.vision import VisionError, create_yolo_detector
from secureedge.worker import (
    FrameDetector,
    FrameSource,
    OpenCvFrameSource,
    PrivacyWorkerPipeline,
    WorkerPipelineError,
)

DetectorFactory = Callable[[VisionSettings], FrameDetector]
SourceFactory = Callable[[int | str | Path], FrameSource]


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def _parser(environ: Mapping[str, str]) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run local OpenCV/YOLO detection and emit unsigned DetectionEvent JSON Lines. "
            "Signing and transport are not part of this command yet."
        )
    )
    config = environ.get("SEV_CONFIG_PATH")
    node_id = environ.get("SEV_NODE_ID")
    camera_id = environ.get("SEV_CAMERA_ID")
    source = environ.get("SEV_MEDIA_SOURCE")
    parser.add_argument("--config", default=config, required=config is None)
    parser.add_argument("--node-id", default=node_id, required=node_id is None)
    parser.add_argument("--camera-id", default=camera_id, required=camera_id is None)
    parser.add_argument(
        "--source",
        default=source,
        required=source is None,
        help="local file path or camera:<non-negative-index>",
    )
    parser.add_argument(
        "--max-events",
        type=_positive_int,
        help="optional explicit bound for local smoke/demo runs",
    )
    return parser


def _parse_local_source(value: str) -> int | Path:
    if value.startswith("camera:"):
        index = value.removeprefix("camera:")
        if not index.isdigit():
            raise WorkerPipelineError("local camera source is invalid")
        return int(index)
    if not value.strip() or "://" in value:
        raise WorkerPipelineError("local media source is invalid")
    return Path(value).expanduser()


def run_cli(
    argv: Sequence[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    detector_factory: DetectorFactory = create_yolo_detector,
    source_factory: SourceFactory = OpenCvFrameSource,
) -> int:
    """Run the explicit local adapter with injectable boundaries for tests."""

    active_environ = os.environ if environ is None else environ
    output = sys.stdout if stdout is None else stdout
    errors = sys.stderr if stderr is None else stderr
    arguments = _parser(active_environ).parse_args(None if argv is None else list(argv))

    try:
        settings = load_settings(arguments.config, active_environ)
        detector = detector_factory(settings.vision)
        pipeline = PrivacyWorkerPipeline(
            node_id=arguments.node_id,
            camera_id=arguments.camera_id,
            settings=settings.vision,
            detector=detector,
        )
        source = source_factory(_parse_local_source(arguments.source))

        def emit(event: DetectionEvent) -> None:
            output.write(event.model_dump_json() + "\n")
            output.flush()

        pipeline.run(source, emit, max_events=arguments.max_events)
    except KeyboardInterrupt:
        errors.write("SecureEdgeVision worker interrupted; local source released.\n")
        return 130
    except (ConfigurationError, VisionError, WorkerPipelineError, OSError, ValueError):
        errors.write("SecureEdgeVision worker stopped safely after invalid local runtime input.\n")
        return 2
    return 0


def main() -> int:
    """Run the local unsigned metadata adapter from process arguments/environment."""

    return run_cli()


if __name__ == "__main__":
    raise SystemExit(main())
