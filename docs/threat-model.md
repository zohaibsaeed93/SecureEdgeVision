# Threat model

The prototype treats the network as able to modify, delay, duplicate, or replay messages. Each worker will have a unique Ed25519 private key, while the aggregator will hold the corresponding public-key registry. Unknown nodes, tampered signed bytes, stale timestamps, and replayed nonces/event IDs will be rejected and recorded as security audit data.

A compromised worker may use its legitimate key to sign false detections. Therefore a valid signature proves origin and integrity of the signed event, not semantic correctness. Byzantine replication, matching, aggregation, and trust scoring are separate future work and must not be folded into the privacy claim.

Private-key protection, automated certificate lifecycle, TLS confidentiality, rate limiting, and production zero-trust infrastructure are documented limitations or later work. No key or credential belongs in this repository.
