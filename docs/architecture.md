# SecureEdgeVision architecture

SecureEdgeVision uses one reusable `secureedge/` domain package beneath small Python services. The intended Milestone 1 path is:

```text
local camera or sample media
        |
        v
edge worker: OpenCV -> local YOLO -> normalized DetectionEvent -> Ed25519 signature
        |
        | signed metadata only in privacy mode
        v
aggregator API: node lookup -> signature/freshness/replay checks -> SQLite persistence
        |
        v
dashboard and query APIs
```

The aggregator is the source of truth. The dashboard is a read-only view and must not become a second authoritative store.

The architecture has three explicitly separated execution modes:

1. Privacy edge mode keeps raw frames local and sends signed detection metadata.
2. Replicated Byzantine benchmark mode later sends public benchmark inputs to multiple workers so authenticated semantic faults can be measured.
3. Centralized baseline mode later sends benchmark frames to a central detector for comparison only.

## Current local vision boundary

The current Milestone 1 vision primitive is an explicit `LocalYoloDetector` boundary. It accepts exactly one non-empty OpenCV-compatible in-memory NumPy frame, constructs the configured Ultralytics nano model only when the detector is explicitly created, and returns frame dimensions, model identity, a SHA-256 digest of the resolved local weight bytes, and normalized detection metadata. It does not open cameras, sample streams, send HTTP, persist data, or export pixels.

The configured model is `yolo26n.pt`. A first use may require the configured weights to be available locally or an explicit Ultralytics runtime acquisition; tests and CI never download weights. Missing or unreadable weights fail through the typed vision error, with no substitute model or import-time download. The digest identifies the exact local weight bytes used by the detector; it is provenance metadata, not proof that a detection is semantically correct.

Detector XYXY coordinates are clipped to the original input width and height before division by those original dimensions. The public result contains only normalized boxes, class labels, confidence, and optional track IDs. Raw frames and crops remain transient inside the worker process and are not part of the metadata boundary.

The current foundation only establishes package and service boundaries. The Build Queue tracks which later Milestone 1 deliverables are implemented.
