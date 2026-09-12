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
