# System configuration

`config/system.yaml` is the explicit source of shared system settings. Applications
must call `secureedge.config.load_settings(path, environ)` during startup; importing
the module does not read files, inspect the process environment, load a model, or
contact another service.

The loader validates privacy mode, the HTTP(S) aggregator URL, replay/freshness and
request-size limits, YOLO nano vision settings, and the reserved future consensus
values. Consensus values are configuration only in Milestone 1 and enable no
consensus or trust behavior.

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

## Local worker inputs

The local unsigned worker adapter requires four explicit application inputs:

- `SEV_CONFIG_PATH` or `--config` for the validated system YAML;
- `SEV_NODE_ID` or `--node-id` for the event node identity;
- `SEV_CAMERA_ID` or `--camera-id` for the event camera identity; and
- `SEV_MEDIA_SOURCE` or `--source` as a local path or
  `camera:<non-negative-index>`.

CLI values take precedence over their environment counterparts. Network/URI media
sources are rejected. `--max-events <positive-int>` is an optional explicit bound
for a local smoke/demo run. A finite local file exits cleanly at EOF; local camera
read failure is an error. The command emits one unsigned metadata-only
`DetectionEvent` JSON object per line. It accepts no private-key input and performs
no signing, HTTP transport, registration, or heartbeat in this task.

Frame sampling comes only from validated `vision.frame_sample_fps`. Node and camera
IDs are validated against the existing safe wire-identifier rules; they are not
secret configuration and are not silently defaulted by the worker adapter.

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
