"""Reusable SecureEdgeVision domain package.

This package is intentionally side-effect free. Service applications import
domain logic from here; importing it must not start a server or load a model.
"""

from secureedge.canonical import canonical_event_bytes
from secureedge.contracts import (
    Detection,
    DetectionEvent,
    FrameMetadata,
    ModelMetadata,
    NodeHeartbeat,
    NodeRegistration,
    PerformanceMetrics,
    SignedDetectionEnvelope,
)

__version__ = "0.1.0"

__all__ = [
    "Detection",
    "DetectionEvent",
    "FrameMetadata",
    "ModelMetadata",
    "NodeHeartbeat",
    "NodeRegistration",
    "PerformanceMetrics",
    "SignedDetectionEnvelope",
    "__version__",
    "canonical_event_bytes",
]
