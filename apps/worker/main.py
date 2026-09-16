"""Thin explicit adapter for signed privacy-worker metadata delivery."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import TextIO

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from secureedge.config import (
    ConfigurationError,
    SystemSettings,
    VisionSettings,
    load_settings,
)
from secureedge.crypto import KeyMaterialError, load_private_key
from secureedge.transport import (
    EventTransport,
    HeartbeatFactory,
    SignedWorkerRunner,
    SignedWorkerTransport,
    TransportError,
)
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
TransportFactory = Callable[[SystemSettings, Ed25519PrivateKey], EventTransport]


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
            "Run local OpenCV/YOLO detection, sign each metadata event, and deliver "
            "the strict envelope with worker heartbeats."
        )
    )
    config = environ.get("SEV_CONFIG_PATH")
    node_id = environ.get("SEV_NODE_ID")
    camera_id = environ.get("SEV_CAMERA_ID")
    source = environ.get("SEV_MEDIA_SOURCE")
    private_key = environ.get("SEV_PRIVATE_KEY_PATH")
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
        "--private-key",
        default=private_key,
        required=private_key is None,
        help="local PKCS#8 Ed25519 private-key path",
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


def _load_explicit_private_key(value: str) -> Ed25519PrivateKey:
    if not value.strip() or "://" in value:
        raise KeyMaterialError("private key path is invalid")
    try:
        pem_data = Path(value).expanduser().read_bytes()
    except OSError:
        raise KeyMaterialError("private key could not be read") from None
    return load_private_key(pem_data)


def _create_transport(
    settings: SystemSettings,
    private_key: Ed25519PrivateKey,
) -> SignedWorkerTransport:
    return SignedWorkerTransport(
        settings.aggregator_url,
        settings.transport.request_timeout_seconds,
        private_key,
    )


def run_cli(
    argv: Sequence[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    detector_factory: DetectorFactory = create_yolo_detector,
    source_factory: SourceFactory = OpenCvFrameSource,
    transport_factory: TransportFactory = _create_transport,
    heartbeat_factory: HeartbeatFactory | None = None,
) -> int:
    """Run signed local inference with injectable deterministic test boundaries."""

    active_environ = os.environ if environ is None else environ
    _ = stdout  # Successful operation deliberately emits no event/key material.
    errors = sys.stderr if stderr is None else stderr
    arguments = _parser(active_environ).parse_args(None if argv is None else list(argv))

    try:
        settings = load_settings(arguments.config, active_environ)
        private_key = _load_explicit_private_key(arguments.private_key)
        detector = detector_factory(settings.vision)
        pipeline = PrivacyWorkerPipeline(
            node_id=arguments.node_id,
            camera_id=arguments.camera_id,
            settings=settings.vision,
            detector=detector,
        )
        source = source_factory(_parse_local_source(arguments.source))
        transport = transport_factory(settings, private_key)
        runner = SignedWorkerRunner(
            pipeline=pipeline,
            source=source,
            transport=transport,
            node_id=arguments.node_id,
            heartbeat_interval_seconds=settings.transport.heartbeat_interval_seconds,
            heartbeat_factory=heartbeat_factory,
        )
        runner.run(max_events=arguments.max_events)
    except KeyboardInterrupt:
        errors.write("SecureEdgeVision worker interrupted; resources released.\n")
        return 130
    except (
        ConfigurationError,
        KeyMaterialError,
        TransportError,
        VisionError,
        WorkerPipelineError,
        OSError,
        ValueError,
    ):
        errors.write("SecureEdgeVision worker stopped safely after a runtime failure.\n")
        return 2
    return 0


def main() -> int:
    """Run signed metadata delivery from process arguments and environment."""

    return run_cli()


if __name__ == "__main__":
    raise SystemExit(main())

