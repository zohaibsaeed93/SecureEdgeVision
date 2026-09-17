# Threat model

The prototype treats the network as able to modify, delay, duplicate, or replay messages. Each worker will have a unique Ed25519 private key, while the aggregator will hold the corresponding public-key registry. Unknown nodes, tampered signed bytes, stale timestamps, and replayed nonces/event IDs will be rejected and recorded as security audit data.

A compromised worker may use its legitimate key to sign false detections. Therefore a valid signature proves origin and integrity of the signed event, not semantic correctness. Byzantine replication, matching, aggregation, and trust scoring are separate future work and must not be folded into the privacy claim.

Private-key protection, automated certificate lifecycle, TLS confidentiality, rate limiting, and production zero-trust infrastructure are documented limitations or later work. No key or credential belongs in this repository.

For the local supervisor demo, `make keys NODE_ID=edge-1` creates an unencrypted
PKCS#8 PEM private key and a canonical base64 raw Ed25519 public key in the
ignored `secrets/` directory. Generation uses operating-system cryptographic
randomness, refuses unsafe IDs, refuses overwrites and symlink targets, and
removes only newly created partial files after a failed pair write. Filesystem
permissions protect the unencrypted demo private key; this is not production key
custody, rotation, revocation, PKI, or TLS.

After signature verification, the reusable `ReplayFreshnessPolicy` rejects events
outside the inclusive configured UTC clock-skew window and prevents reuse of both
`event_id` and `nonce` within each `node_id`. Checking and reserving both identifiers
is one lock-protected operation, so concurrent duplicate submissions cannot both be
accepted or leave a partial reservation. Rejections use stable reason codes and do
not include event identifiers, nonces, payloads, or key material in their messages.

Replay state is deliberately process-local for Milestone 1. It is neither durable
across restarts nor coordinated across multiple aggregator processes; deployment
must therefore use one aggregator process for the supervisor demo. Entries remain
protected through the later of the configured nonce TTL and the final instant at
which the original signed timestamp could pass freshness, then are lazily pruned.
The policy also rejects wall-clock rollback behind its latest accepted instant, so
a forward jump cannot prune identifiers and a later backward jump reopen them.
Distributed or durable replay prevention belongs to later architecture work and is
not claimed here.

The current worker signs only canonical `DetectionEvent` bytes and sends only the
strict signed envelope. Private-key paths and bytes, raw frames, crops, tensors, and
model bytes are excluded from requests and sanitized failures. Delivery has a
configured timeout, follows no redirect, and makes one attempt; a lost response is
an explicit ambiguous failure rather than a retry or success.

The current heartbeat contract is intentionally unsigned and therefore does not
provide event-style authenticity. Plain HTTP is acceptable only inside the local
Compose demo. Production TLS, authenticated heartbeats, durable delivery,
key rotation/revocation, and production identity lifecycle remain documented
limitations rather than claims of this task.

The current ingestion route enforces server-side public-key lookup and event
authentication. Request size is checked against both declared and streamed bytes;
JSON rejects duplicate keys and non-finite numbers; and strict contracts prevent
raw-frame/image/crop/tensor/media-path fields from entering the domain boundary.
The route verifies the registered-key signature before invoking the replay policy,
so unknown nodes, tampered events, and malformed requests cannot consume replay
state. Responses contain only stable reason codes and never include payloads,
signatures, keys, SQL, paths, or lower-level exception text.

Accepted metadata is acknowledged only after the SQLite commit. If persistence
fails after replay reservation, the reservation remains until TTL because the
durable outcome may be uncertain. This can temporarily reduce availability but
does not silently permit replay. Rejection-alert persistence is not yet wired, so
current rejections create no audit row; that limitation is the next Milestone 1
boundary.
