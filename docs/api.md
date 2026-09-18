# API contract

The Milestone 1 aggregator exposes six current typed FastAPI routes. Metrics remain
a separate reviewed boundary:

- `GET /health` for database readiness and safe row-count summary (**implemented**)
- `POST /v1/events/detections` for one signed detection envelope (**implemented**)
- `POST /v1/nodes/heartbeat` for advisory worker health (**implemented**)
- `GET /v1/nodes` for safe node status (**implemented**)
- `GET /v1/events` for recent accepted metadata (**implemented**)
- `GET /v1/security/alerts` for sanitized identity, integrity, freshness, and replay alerts (**implemented**)
- `GET /metrics` for Prometheus counters and histograms (**planned**)

The current response policy is: accepted event or heartbeat `202`; unknown node or
invalid signature `401`; replay, stale, future, or out-of-order timestamp `409`;
malformed JSON or strict contract failure `422`; oversized request `413`; and
sanitized registry, clock, configuration, or persistence failure `503`. A 202
response has an empty body and is returned only after its metadata transaction
commits.

## Current authenticated ingestion behavior

`POST /v1/events/detections` requires `application/json` and exactly one strict
`SignedDetectionEnvelope`. The adapter enforces
`security.max_request_bytes` against both a declared `Content-Length` and the bytes
actually streamed, stopping as soon as the bound is exceeded. Missing or chunked
length is allowed but never bypasses the streamed limit. Malformed UTF-8/JSON,
duplicate object keys, non-finite values, incorrect length, extra/raw-frame fields,
and wire-model violations return a stable `invalid_request` without reflecting the
payload.

Processing order is fixed: validate the bounded wire request, look up the claimed
node in the SQLite registry, verify the signature with only that stored public key,
apply the single app-owned freshness/replay policy, then commit a metadata-only
`DetectionEventRecord`. Unknown nodes and invalid signatures do not mutate replay
state. A security rejection commits exactly one sanitized audit alert before the
adapter returns its 401/409 status. Alert-write uncertainty fails closed as the
same sanitized 503 used for other persistence failures.

## Current security-alert behavior

`GET /v1/security/alerts` is read-only and returns a JSON array of strict
`SecurityAlert` values ordered by `occurred_at_utc` descending and then
`alert_id` descending. The only fields are `alert_id`,
`occurred_at_utc`, `category`, `reason`, `node_id`, `event_id`,
and `nonce`. It never returns payloads, detections, signatures, key material,
request bodies, or internal errors.

The optional `limit` query parameter defaults to 50 and accepts decimal values
from 1 through 100. Duplicate, unknown, malformed, zero, or oversized query values
return the stable 422 `invalid_request` response. Database/query uncertainty
returns the stable 503 `service_unavailable` response.

Alert categories and reasons are fixed for this boundary: `identity/unknown_node`,
`integrity/invalid_signature`, `freshness/stale_timestamp`,
`freshness/future_timestamp`, `replay/replayed_event_id`, and
`replay/replayed_nonce`. Accepted events, malformed contracts, oversized
requests, and non-security dependency failures do not create alert rows.

## Current worker request behavior

The worker targets the configured aggregator origin with fixed
`POST /v1/events/detections` and `POST /v1/nodes/heartbeat` paths. A detection
request contains exactly one `SignedDetectionEnvelope`; the heartbeat request
contains exactly one `NodeHeartbeat`. Both currently require HTTP 202. Redirects
are not followed, response bodies are never surfaced in worker errors, and an event
gets at most one automatic attempt so an ambiguous lost response cannot cause a
silent duplicate retry.

The heartbeat wire model remains unsigned. The worker transport does not implement
server registration or verification itself; the aggregator owns registered-key
event verification and persistence. Heartbeat state is advisory local-demo
liveness only and is never used as an authorization or authenticated-security
verdict.

## Current heartbeat and monitoring behavior

`POST /v1/nodes/heartbeat` requires `application/json`, no query parameters, and
exactly one strict `{node_id, timestamp_utc, status}` body. It uses the same
configured streamed request-size bound and strict JSON rules as detection ingest.
The node must already exist in the explicit registry; heartbeat receipt never
registers a node or changes its public key. A fresh timestamp atomically advances
only `last_seen_at_utc` and `health_status` before the route returns an empty 202.

Unknown nodes receive 401 `unknown_node`. Timestamps outside the inclusive
configured `security.max_clock_skew_seconds` window receive 409
`stale_timestamp` or `future_timestamp`; a timestamp equal to or older than the
stored heartbeat receives 409 `out_of_order_heartbeat`. Those rejections never
overwrite newer state and do not create accepted-event or security-alert rows.
Persistence or clock uncertainty rolls back and returns only 503
`service_unavailable`.

Heartbeats are intentionally unsigned in the current wire contract. Registry
membership limits which row an advisory message may update, but it does not prove
who sent the message, its byte integrity, or worker correctness. The local demo
must not expose this HTTP route as a production trust signal; TLS, signed
heartbeats, node provisioning, and PKI remain outside this boundary.

`GET /health` accepts no query parameters. It returns
`{status: "healthy", database: "ready", registered_nodes, accepted_events,
security_alerts}` only after the database count queries succeed; otherwise it
returns sanitized 503. It exposes no DSN, path, key, credential, or exception.

`GET /v1/nodes` returns only `node_id`, `registered_at_utc`, nullable
`last_seen_at_utc`, and nullable `health_status`, ordered deterministically by
`node_id`. Public keys are deliberately not part of the response, and the API does
not derive an unconfigured online/offline threshold. `GET /v1/events` returns
accepted records newest-first with a stable internal tie-breaker as
`{accepted_at_utc, event}`; `event` is the full normalized metadata-only
`DetectionEvent`. Neither response can contain pixels, crops, tensors, local media
paths, signatures, or key material.

Both collection endpoints use an optional decimal `limit` that defaults to 50 and
is bounded from 1 through 100. Duplicate, unknown, malformed, zero, or oversized
query values return 422 `invalid_request`; query or stored-row uncertainty returns
sanitized 503. Empty collections return an empty JSON array.

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
wire representation. Deterministic canonicalization and the reusable Ed25519
signing/verification primitives are separate domain layers. The process-local
freshness/replay policy described below is another separate domain layer. The
authenticated ingestion route composes these layers. Monitoring routes reuse the
strict metadata contracts but do not reinterpret signatures as semantic truth.
A valid signature will establish origin and byte integrity, not the semantic
correctness of a detection.

### Canonical signed content

The canonical signed content is the validated `DetectionEvent` in the envelope's
`body`, not the full envelope. `signature_algorithm`, `signature_b64`, key material,
and transport metadata are excluded. `canonical_event_bytes` converts the event to
its Pydantic JSON-compatible representation and emits UTF-8 JSON with recursively
sorted object keys, compact `,` and `:` separators, direct Unicode encoding, no
insignificant whitespace or trailing newline, and no NaN or Infinity values.

Array order remains significant, including the order of `detections`. UTC timestamps
are normalized through the validated model's JSON representation, so equivalent UTC
inputs produce the same bytes. This deterministic representation is the input for the
separate Ed25519 signing and verification layer; this layer does not perform cryptography,
authenticate a node, prevent replay, or establish that a detection is semantically
correct.

### Ed25519 key material and local demo generation

`secureedge.crypto` generates keys with `Ed25519PrivateKey.generate()`. Public
keys are encoded as canonical standard base64 of the 32-byte raw Ed25519 public
key, matching `NodeRegistration.public_key_b64`. Local private keys are written
as unencrypted PKCS#8 PEM only by the explicit command:

```text
make keys NODE_ID=edge-1 [KEY_DIR=secrets]
```

The command writes `<node_id>.key` and `<node_id>.pub` under the ignored local
directory, refuses unsafe IDs, pre-existing files, and symlink targets, and
cleans up a newly created partial pair if the second write fails. It reports
paths and public material only; it never prints or sends private key bytes.
Unencrypted local demo keys rely on filesystem permissions. Key custody,
rotation, revocation, PKI, and TLS are not claimed by this milestone.

### Authenticated-event freshness and replay policy

`ReplayFreshnessPolicy.accept_verified_event()` consumes a validated
`DetectionEvent` only after its Ed25519 envelope has been authenticated by the
caller. It accepts timestamps at the inclusive edges of the configured clock-skew
window and otherwise raises `EventSecurityRejection` with one stable reason:
`stale_timestamp`, `future_timestamp`, `replayed_event_id`, or `replayed_nonce`.
The FastAPI adapter maps those rejections to `409` and commits their sanitized
security alerts without inspecting exception text.

The policy normalizes accepted clock and event timestamps to plain UTC datetimes.
Malformed datetime behavior and a clock that moves behind the latest accepted
instant fail closed through a sanitized `EventSecurityConfigurationError`; the
underlying exception text and event values are not exposed.

Replay identity is scoped by `node_id`: both an event ID and nonce are reserved
atomically for that node. State belongs to one policy instance and is held only in
process memory. The returned `EventSecurityDecision` reports the UTC acceptance
instant and replay-protection horizon but contains no frame, detection payload, key,
or credential. This layer performs no signature verification, persistence, HTTP,
or semantic validation of detections.
