# SecureEdgeVision

SecureEdgeVision is a research-oriented distributed computer-vision system. Computer vision is the workload, edge/distributed computing is the execution architecture, and information security is the research problem.

In privacy mode, an edge worker keeps camera frames local, runs a pretrained Ultralytics YOLO nano detector, creates compact normalized detection metadata, signs each event with a node-specific Ed25519 key, and sends only signed metadata to a central aggregator. The aggregator verifies node identity, signatures, freshness, and replay protection before persisting accepted events and security audit data.

Replicated Byzantine benchmark mode is a separate future research path for public benchmark inputs. It must not be confused with privacy mode: a valid signature proves origin and integrity, not that a detection is semantically correct.

## Current status

Milestone 1 is being delivered in reviewed coherent boundaries. The repository now
contains strict detection/node contracts, deterministic canonicalization, Ed25519
primitives, process-local replay/freshness policy, normalized local YOLO inference,
the local privacy-worker pipeline, and one-attempt signed metadata transport with
periodic metadata-only heartbeats. It also contains the explicit SQLAlchemy/SQLite
persistence foundation for registered public node identities, accepted detection
metadata, and sanitized security-alert metadata. The aggregator now exposes the
bounded authenticated detection-ingest route: it validates strict JSON, resolves a
registered public key, verifies the Ed25519 signature, applies the configured
freshness/replay policy, and commits accepted metadata before returning HTTP 202.
It also commits sanitized audit metadata for identity, integrity, freshness, and
replay rejections before returning 401/409, and exposes a bounded read-only security
alert view. It now also accepts bounded advisory heartbeats for registered nodes
and exposes sanitized database health, public-key-free node status, and recent
metadata-only accepted-event views. Dashboard behavior and the end-to-end demo
remain later Milestone 1 tasks.

Milestone 1 is the supervisor-demo vertical slice: local YOLO inference, normalized `DetectionEvent` creation, Ed25519 signing, freshness/replay protection, signed metadata transport, FastAPI aggregation, SQLite persistence, security alerts, health/query APIs, a basic dashboard, tests, CI, and demo documentation. Milestones 2–4 remain future work and are not implemented here.

## Technology choices

- Python 3.11 or 3.12 with `uv` and `uv.lock`
- Ultralytics YOLO nano and OpenCV for local vision processing
- FastAPI, Uvicorn, Pydantic, and HTTPX for typed service contracts
- `cryptography` Ed25519 for event authenticity and integrity
- SQLite and SQLAlchemy for centralized prototype persistence
- Streamlit and Plotly for the supervisor-facing view
- `prometheus-client` plus CSV/JSON artifacts for observability and experiments
- Docker Compose for reproducible process boundaries
- pytest, Ruff, and targeted mypy for verification

The design deliberately excludes Redis, Kafka, Celery, Kubernetes, React, cloud services, custom detector training, and production PKI infrastructure.

## Repository layout

```text
secureedgevision/
├── apps/                 # service entry points; domain logic lives in secureedge/
├── artifacts/            # reproducible run outputs (local runs are ignored)
├── config/               # explicit, reviewable configuration examples
├── data/                 # local inputs; raw media is not committed
├── docs/                 # architecture, threat model, API, and roadmap notes
├── scripts/              # operational helpers added by later milestones
├── secureedge/           # reusable side-effect-free domain package
└── tests/                # unit and integration coverage
```

## Development commands

The Makefile is the public command surface. It is intentionally honest about work that is not implemented yet.

```text
make bootstrap     # synchronize the locked uv environment
make test          # run the current pytest suite
make lint          # run Ruff and targeted mypy checks
make up            # start the Compose topology
make down          # stop the Compose topology
make demo          # run the Milestone 1 demo once it is implemented
make keys NODE_ID=edge-1 [KEY_DIR=secrets]  # generate local demo keys
make attack ...    # future Milestone 2 command
make experiment ...# future Milestone 3 command
make verify-runs   # future artifact validation command
```

Run `uv sync` (or `make bootstrap`) before the test and lint commands. The worker
requires explicit config, node, camera, local source, and local Ed25519 private-key
path inputs as documented in `docs/configuration.md`. It signs and sends only the
strict event envelope and metadata-only heartbeat; it emits no unsigned success
fallback. Other application services remain incremental, and the privacy-mode
workflow is not complete until the Build Queue acceptance criteria are satisfied.

The aggregator runtime is constructed explicitly. Supply validated configuration,
an approved local SQLite URL, and one or more public node registrations as needed:

```text
uv run secureedgevision-aggregator \
  --config config/system.yaml \
  --database-url sqlite:///data/secureedgevision.sqlite3 \
  --node-public-key edge-1=<canonical-public-key-base64>
```

The command initializes the exact non-destructive schema and runs one Uvicorn
worker. The replay policy is process-local, so multi-worker serving is deliberately
not enabled for this demo boundary.

`make keys NODE_ID=edge-1` writes an unencrypted PKCS#8 PEM private key and a
canonical base64 raw public key under the ignored `secrets/` directory. The
command requires a safe node ID, refuses to overwrite either target, and never
prints private key bytes. Use `KEY_DIR` to select another local directory. These
demo keys rely on filesystem permissions; production key custody, rotation, and
revocation are outside this milestone.

## Security boundary

Private keys belong only in the ignored local `secrets/` directory and must never be committed. Privacy-mode workers must never send raw camera frames to the aggregator. Thresholds such as clock skew, nonce TTL, request size, confidence, and image size belong in configuration, not hidden code constants. Signatures authenticate the node and signed bytes; they do not validate the truth of a detector’s output.

The persistence module has no import-time database behavior. An application must
explicitly supply an approved local SQLite URL, create its engine/session factory,
and call the non-destructive initializer. It stores only public node identity and
validated metadata—never frames, crops, tensors, model bytes, private keys,
credentials, or arbitrary request bodies. Replay expiry remains process-local and
configured; database rows do not create permanent event-ID or nonce uniqueness.
The ingestion route bounds the streamed body before JSON parsing, rejects duplicate
JSON keys and non-finite values, authenticates before reserving replay identifiers,
and returns only stable sanitized errors. A reservation is retained until TTL if a
later commit outcome fails, preventing an uncertain write from reopening replay.
Security rejections are acknowledged only after their sanitized alert commits;
alert-write uncertainty returns a sanitized service failure. The read-only
`GET /v1/security/alerts` view returns only bounded audit metadata and never
stores or exposes request bodies, signatures, keys, or detector payloads.

Heartbeat ingestion is a separate unsigned local-demo boundary. It only updates
the advisory `last_seen_at_utc` and `health_status` fields of an already registered
node, applies the configured clock-skew window, and atomically refuses older state.
It is not proof of sender identity, integrity, authorization, or worker correctness
and is never used as an authenticated security verdict. The `/health`, `/v1/nodes`,
and `/v1/events` views are bounded and read-only; they expose safe counts, node
status without public keys, and normalized detection metadata without frames,
signatures, secrets, or local paths.

## Milestone roadmap

1. **Supervisor demo:** privacy-mode vertical slice and its security controls.
2. **Replicated resilience:** public benchmark jobs, authenticated malicious workers, matching, aggregation, and trust history.
3. **Research experiments:** centralized baseline, reproducible E1–E5 runs, metrics, artifacts, and plots.
4. **Final integration:** broader dashboard, topology hardening, reproducibility validation, and FYP completion.

See the GitHub issue `[AUTO] SecureEdgeVision Build Queue` for the authoritative current task, acceptance criteria, handoffs, and progress.
