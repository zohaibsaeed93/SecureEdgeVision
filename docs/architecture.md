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

The current foundation only establishes package and service boundaries. The Build Queue tracks which later Milestone 1 deliverables are implemented.
