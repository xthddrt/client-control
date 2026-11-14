# Vendored msmon session-format support

These files are copied into `client-control` so the traffic ledger can read and
verify msmon-compatible session bundles without cloning or importing the
`monitor-filter` repository.

Source: `monitor-filter` at commit `a9e9e79` (the checkout used while this branch
was built).

| Vendored path | Source path | Role |
|---|---|---|
| `traffic/vendor/verify_msmon_log.py` | `monitor/tools/verify_log.py` | Recomputes the SHA-256 chain, checks record indexes, sequences and payload chunk completeness. |
| `traffic/vendor/schema/event-v1.json` | `monitor/schema/event-v1.json` | Event-record schema used by the vendored reader/tests. |
| `traffic/vendor/schema/session-v1.json` | `monitor/schema/session-v1.json` | Session manifest schema used to read labels/build identity. |
| `traffic/vendor/schema/checksums-v1.json` | `monitor/schema/checksums-v1.json` | Bundle checksum schema used to read manifests. |

The packet reader, pcapng reader, event-to-ledger integration and policy
evaluator are implemented in `traffic/` itself; they do not import or execute
anything from `monitor-filter`.
