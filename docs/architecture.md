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

## Privacy worker pipeline

`PrivacyWorkerPipeline` composes the local detector with the strict
`DetectionEvent` contract. An explicit `OpenCvFrameSource` opens either a local
filesystem image/video or a local camera device; URI/network sources are rejected.
The source is context managed and is released after finite-media EOF, a configured
event bound, interruption, or failure. Finite media uses its declared FPS as a
content timeline when available; cameras and media without usable FPS metadata use
monotonic read-completion time. The configured `vision.frame_sample_fps` is the
only sampling cadence.

Frame sequences start at zero for a worker pipeline instance and increase only
after a complete event validates. Skipped and failed frames do not consume a
sequence number. Event IDs and nonces are independently generated safe identifiers,
and process-local reuse fails closed. Each event has an aware UTC timestamp,
`job_id: null`, and `mode: privacy`.

Performance fields are deliberately bounded by observable components:
`decode_ms` measures one local capture/decode call; `inference_ms` covers the
integrated detector call, including its normalization; and `postprocess_ms` covers
worker timestamp/identifier and event-input preparation before final Pydantic
validation. The pipeline does not invent a finer split than the detector exposes.

The current worker command can emit these **unsigned** metadata events as JSON
Lines for local inspection. It does not load a private key, sign, contact the
aggregator, register a node, or send a heartbeat. Signed transport is the next
separate Milestone 1 boundary. Raw frames remain transient between the local source
and local detector and never enter event output, logs, persistence, or transport.
Detector output is not semantic truth; later signatures establish origin and byte
integrity only.
