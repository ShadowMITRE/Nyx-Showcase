# Security model

## Trust boundaries

| Boundary | Showcase behavior |
|---|---|
| Input | Treated as untrusted text; no evaluation or shell execution |
| Network | No network calls |
| Filesystem | Reads only the explicitly selected input file |
| Output | JSON to standard output with redacted, bounded samples |
| Actions | Disabled; the report cannot change external systems |
| Data | Synthetic examples only; raw events are not returned |

## Intended use

The showcase is suitable for evaluating code organization, deterministic triage behavior, tests, and safety-oriented design. It is not intended for unsupervised detection, production incident response, or automated containment.

## Known limitations

- Keyword evidence can produce false positives and false negatives.
- Event-by-event analysis lacks full temporal and environmental context.
- Confidence values are deterministic policy values, not calibrated probabilities.
- Redaction is defense in depth and cannot guarantee removal of every sensitive format.
- A SHA-256 event identifier may still be subject to guessing when the source text has low entropy.

## Safe evaluation

Use synthetic data and documentation-only IP ranges:

- `192.0.2.0/24`
- `198.51.100.0/24`
- `203.0.113.0/24`

Do not paste credentials, client telemetry, regulated information, or live incident evidence into public issue reports.

