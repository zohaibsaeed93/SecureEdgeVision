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

The worker loads an Ed25519 private key only from an explicit local path, signs each
validated event with the integrated canonical signing primitive, and makes one
HTTPX request to `POST /v1/events/detections`. It also sends the existing strict
metadata-only heartbeat to `POST /v1/nodes/heartbeat` initially and at the
configured interval while the source is active. The source-coupled lifecycle stops
the heartbeat and releases HTTP/OpenCV resources on EOF or failure. Raw frames
remain transient between the local source and detector and never enter an event,
request, log, or fallback output.

The worker follows no redirects and automatically retries neither request. A lost
response is therefore reported as an ambiguous failed delivery, not fabricated
success. Heartbeats are not signed in the current wire contract, HTTP is suitable
only for the local demo, and node registration/aggregator verification remain later
Milestone 1 boundaries. Event signatures establish origin and byte integrity only,
not detector truth.

## Aggregator persistence boundary

`secureedge.persistence` defines the Milestone 1 SQLite source of truth without
starting an aggregator service. Its single declarative metadata boundary contains
exactly three tables: `nodes` for canonical Ed25519 public identities and minimal
heartbeat state, `detection_events` for losslessly reconstructable privacy-mode
metadata, and `security_alerts` for sanitized rejection-audit identifiers. Alert
rows deliberately do not require a node foreign key so an unknown claimed node can
be audited; accepted events do require a registered node.

Detections use deterministic validated JSON because their ordered cardinality is
variable. Every conversion back to a domain event passes through the strict
Pydantic contracts, so malformed or non-finite stored metadata fails closed. The
schema has no fields for pixels, crops, tensors, local media paths, model bytes,
private keys, credentials, request bodies, signatures in alerts, or exception
text. Event IDs and nonces are indexed but are not permanently unique: the
configured process-local `ReplayFreshnessPolicy` remains the replay authority for
this milestone.

Engine creation, schema initialization, sessions, commits, rollbacks, and node
seeding are explicit caller actions. Initialization is idempotent for the exact
schema and preserves rows; it neither drops data nor pretends to migrate an
incompatible database. Heartbeat ingestion, alert persistence, and query APIs are
intentionally outside this persistence boundary.

## Authenticated detection ingestion

The aggregator is created only through an explicit FastAPI factory. One caller-owned
`ReplayFreshnessPolicy` lives for the lifetime of the app, while every request gets
a short-lived SQLAlchemy session. The only current server route is
`POST /v1/events/detections`; documentation/OpenAPI convenience routes are disabled
so unimplemented surfaces are not implied.

The HTTP adapter bounds streamed bytes before parsing and applies strict JSON and
Pydantic validation. Reusable `DetectionEventIngestor` domain logic then performs
registered-node lookup, registered-key Ed25519 verification, atomic freshness/replay
reservation, and metadata persistence in that order. HTTP 202 is emitted only after
commit. Failures roll back and close the request session; a replay reservation made
before an uncertain commit failure remains until its configured TTL. The runtime
uses a single Uvicorn worker because replay state is process-local.
