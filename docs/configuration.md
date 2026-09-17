# System configuration

`config/system.yaml` is the explicit source of shared system settings. Applications
must call `secureedge.config.load_settings(path, environ)` during startup; importing
the module does not read files, inspect the process environment, load a model, or
contact another service.

The loader validates privacy mode, a credential-free HTTP(S) aggregator origin,
replay/freshness and request-size limits, YOLO nano vision settings, bounded
transport request timeout and heartbeat interval, and the reserved future
consensus values. Consensus values are configuration only in Milestone 1 and
enable no consensus or trust behavior.

## Environment overrides

Overrides are optional and must be passed explicitly by the application. The
allowlisted names are documented in `.env.example` and use the
`SEV_CONFIG__SECTION__FIELD` convention. Values are parsed to the target numeric or
string type and then receive the same bounds validation as YAML values. Unknown
`SEV_CONFIG__...` names, malformed values, URL credentials, unknown YAML fields,
and missing fields fail closed with a field-specific `ConfigurationError`.

Node identity, camera identity, database URLs, and logging settings are separate
application concerns. Private keys and credentials are never system-setting
overrides and must not be committed.

## Aggregator database input

Persistence code accepts a database URL only through an explicit
`create_sqlite_engine(...)` call; it does not read `SEV_DATABASE_URL`, another
environment variable, or a hidden default. For the local demo, an application may
pass the existing example `sqlite:///state/secureedgevision.db`. The parent
directory must already exist: the reusable persistence layer rejects a missing
parent rather than creating filesystem structure implicitly. Explicit
`sqlite:///:memory:` is supported for tests.

Only credential-free local `sqlite`/`sqlite+pysqlite` URLs without query options,
URI mode, traversal, or remote hosts are accepted. The application owns engine
disposal and must explicitly call `initialize_database(engine)` followed by
`create_session_factory(engine)`. Initialization creates the exact schema when the
database is empty, is idempotent without deleting rows, and rejects partial or
incompatible schemas; there is no implicit migration behavior. Transactional
`session_scope(...)` commits successful units of work and rolls back and closes on
failure.

Node-registry seeding consumes validated `NodeRegistration` values containing only
public key material. Repeating the same node/key is a no-op; attempting to replace
a node's key through seeding rejects the entire batch. Private-key paths and bytes
never enter persistence configuration. Database event IDs and nonces are not
permanently unique, so configured replay/freshness enforcement remains
process-local in the current authenticated-ingestion design.

## Local aggregator inputs

The aggregator command requires explicit `--config <path>` and
`--database-url <approved-local-sqlite-url>` arguments. It does not discover a
database URL from the environment or hide one in domain logic. Public registry
entries may be seeded with repeated
`--node-public-key NODE_ID=PUBLIC_KEY_B64` arguments; values pass through the
strict `NodeRegistration` boundary and identical existing registrations are
idempotent. Private keys are never accepted.

The command initializes the schema explicitly, owns engine disposal, constructs one
process-local replay policy from `settings.security`, and runs one Uvicorn worker.
For example:

```text
uv run secureedgevision-aggregator \
  --config config/system.yaml \
  --database-url sqlite:///data/secureedgevision.sqlite3 \
  --node-public-key edge-1=<canonical-public-key-base64>
```

The database parent directory must already exist. `security.max_request_bytes`
bounds the actual streamed request body as well as declared length;
`max_clock_skew_seconds` and `nonce_ttl_seconds` are used by the single app-owned
freshness/replay policy. No route-specific threshold is hidden in code.

## Local worker inputs

The signed worker adapter requires five explicit application inputs:

- `SEV_CONFIG_PATH` or `--config` for the validated system YAML;
- `SEV_NODE_ID` or `--node-id` for the event node identity;
- `SEV_CAMERA_ID` or `--camera-id` for the event camera identity; and
- `SEV_MEDIA_SOURCE` or `--source` as a local path or
  `camera:<non-negative-index>`; and
- `SEV_PRIVATE_KEY_PATH` or `--private-key` as a local unencrypted PKCS#8
  Ed25519 private-key path.

CLI values take precedence over their environment counterparts. Network/URI media
sources are rejected. `--max-events <positive-int>` is an optional explicit bound
for a local smoke/demo run. A finite local file exits cleanly at EOF; local camera
read failure is an error. After configuration, key, detector, source, and transport
setup succeed, the command sends an initial healthy heartbeat and then continues at
`transport.heartbeat_interval_seconds`. Each sampled `DetectionEvent` is signed
and delivered once; only HTTP 202 is success. Redirects, timeouts, network errors,
and other statuses fail closed. `transport.request_timeout_seconds` bounds each
request. The command emits no event, signature, key, or unsigned fallback to stdout.

Frame sampling comes only from validated `vision.frame_sample_fps`. Node and camera
IDs are validated against the existing safe wire-identifier rules; they are not
secret configuration and are not silently defaulted by the worker adapter.
Private-key bytes are deliberately outside `SystemSettings` and all
`SEV_CONFIG__...` overrides.

## Replay and timestamp settings

`security.max_clock_skew_seconds` defines an inclusive past/future UTC window for
an already authenticated detection event. A timestamp exactly one configured skew
away from the injected current time is accepted; an older timestamp is
`stale_timestamp`, and a later timestamp is `future_timestamp`. The clock must
return an aware UTC `datetime` or the policy fails closed.

`security.nonce_ttl_seconds` is the minimum process-local reservation time for both
the event ID and nonce, scoped by node. The effective reservation is extended when
necessary through `event.timestamp_utc + max_clock_skew_seconds`, preventing a
short TTL from making an otherwise fresh signed event reusable. Expiration is
inclusive and expired entries are pruned deterministically during later accepted
checks. Both thresholds come only from validated configuration; there are no
hard-coded service overrides or background cleanup workers.

Each policy instance records the latest UTC instant at which it accepted an event.
If the wall clock later moves behind that high-water mark, checks fail closed until
the clock catches up. This prevents a forward adjustment, pruning, and subsequent
rollback from making an earlier signed event fresh and replayable again.
