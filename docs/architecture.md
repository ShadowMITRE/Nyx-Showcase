# Architecture

Nyx is designed around a separation between evidence handling, deterministic analysis, governance, and optional action execution. This public edition preserves that separation while implementing only the non-actuating analysis path.

## Showcase data flow

1. The CLI accepts one event or a UTF-8 line-oriented file.
2. The analyzer finds a small, explicit set of security-language signals.
3. IPv4 candidates are syntax-validated and deduplicated.
4. Independent signals raise confidence and review priority.
5. Externally visible samples are redacted and length-bounded.
6. Raw events are represented by stable SHA-256 identifiers.
7. The report recommends observation or analyst review; it never executes an action.

## Production design represented by the project

The private Nyx implementation extends the pipeline with:

- normalized line, CSV, TSV, JSONL, syslog, Windows-event, and packet-summary input
- typed policy loading and validation
- deterministic explainability contracts and provenance
- optional non-authoritative local model signals
- locally governed memory and publication controls
- action allow-lists, authority checks, explicit execution enablement, and human approval
- hash-linked receipts for detecting local audit-ledger tampering

## Engineering properties

- **Offline-first:** deterministic analysis does not depend on network services.
- **Fail-closed actuation:** a missing gate cannot become implicit approval.
- **Explainable:** each supported signal maps to a human-readable reason.
- **Reproducible:** identical text produces the same result and event identifier.
- **Bounded disclosure:** output uses redaction and does not retain a raw-event field.

