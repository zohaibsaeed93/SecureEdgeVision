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
