# Configuration

Configuration is intentionally explicit and reviewable. `system.yaml` contains the starting values from the architecture specification, including security freshness/request limits and vision parameters. Later tasks will add validated loading and environment overrides without moving experiment-sensitive thresholds into code.

`nodes.example.yaml` contains public-key paths only. Generate private keys locally under the ignored `secrets/` directory when the Milestone 1 key-management task is implemented.
