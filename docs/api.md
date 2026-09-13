# API contract

The Milestone 1 aggregator will expose a typed FastAPI surface. Planned endpoints include:

- `GET /health` for liveness/readiness and database/node summary
- `POST /v1/events/detections` for one signed detection envelope
- `POST /v1/nodes/heartbeat` for worker health
- `GET /v1/nodes` for node status
- `GET /v1/events` for recent accepted metadata
- `GET /v1/security/alerts` for signature, freshness, replay, and later semantic alerts
- `GET /metrics` for Prometheus counters and histograms

The specified response policy is: accepted event `202`; unknown node or invalid signature `401`; replay or stale timestamp `409`; schema validation failure `422`; and oversized request `413`. The service implementation and integration tests are queued as later coherent Milestone 1 deliverables.

## Milestone 1 wire contracts

All request models reject unknown fields and unsafe type coercion. Identifiers are
1–128 characters and contain only ASCII letters, digits, `.`, `_`, `:`, or `-`;
timestamps must be timezone-aware UTC. These contracts carry metadata only—raw
frames, image bytes, private keys, and credentials are not fields in any shape.

### Detection event

`DetectionEvent` has exactly these top-level fields:

| Field | Type and constraint |
| --- | --- |
| `schema_version` | literal `"1.0"` |
| `event_id`, `node_id`, `camera_id`, `nonce` | required safe identifiers |
| `timestamp_utc` | timezone-aware UTC timestamp |
| `frame_seq` | non-negative integer |
| `job_id` | safe identifier or `null`; the field remains required |
| `mode` | literal `"privacy"` |
| `model` | `{name, sha256}`; `sha256` is 64 lowercase hexadecimal characters |
| `frame` | `{width, height}` positive integer dimensions; no pixel data |
| `detections` | array of the detection shape below |
| `performance` | `{decode_ms, inference_ms, postprocess_ms}` non-negative timings |

Each detection is
`{class_id, class_name, confidence, bbox_xyxy_norm, track_id?}`. `class_id` is
non-negative, `confidence` is in `[0,1]`, and `track_id` is either omitted,
`null`, or non-negative. `bbox_xyxy_norm` is the four-number array
`[x_min, y_min, x_max, y_max]`; every coordinate is in `[0,1]` and the box must
satisfy `x_min < x_max` and `y_min < y_max`.

### Node messages

Node registration is exactly `{node_id, public_key_b64}`. The public key is the
canonical standard-base64 representation of 32 bytes of raw Ed25519 public-key
material. It is not a private key or credential.

A heartbeat is exactly `{node_id, timestamp_utc, status}`. `status` is one of
`"healthy"`, `"degraded"`, or `"unhealthy"`; its timestamp follows the same UTC
rule as an event.

### Signed detection envelope

The signed envelope is exactly
`{body, signature_algorithm: "ed25519", signature_b64}`. `body` is a typed
`DetectionEvent`, and `signature_b64` is the canonical standard-base64
representation of a 64-byte Ed25519 signature. This layer validates only the
wire representation. Deterministic canonicalization, signing, verification,
freshness, replay enforcement, and API behavior are separate Milestone 1 tasks.
A valid signature will establish origin and byte integrity, not the semantic
correctness of a detection.
