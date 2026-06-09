# No-Fake Backend Guarantees

This project explicitly avoids presenting unavailable data as real backend output.

## NLP

- Strict mode requires a loaded model and passing quality gate.
- Fallback output must not be presented as trained NLP.
- `/api/nlp/health` exposes model readiness, metrics and quality gate status.

## Threat Intelligence

The system does not invent:

- CVSS scores
- NVD advisories
- CISA KEV status
- known exploited status
- MISP matches

Each source reports one of:

- `ok`
- `not_found`
- `disabled`
- `error`

A fake or nonexistent CVE must return no CVSS and no KEV status.

## Risk Scoring

Risk scoring is deterministic and auditable. It may use report data and real enrichment, but it must not increase risk based on missing threat intelligence.

## Knowledge Graph

Graph relationships are built from report extraction, deterministic mappings with provenance, threat intelligence, risk data and report-scoped evidence. Report-scoped nodes carry report/user identifiers where relevant.

## Attack Paths

A path is graph-derived only when it is backed by report-scoped graph evidence. If the system only has a finding row and cannot derive a full graph path, the output must be labelled as a fallback/finding-only path, not as graph-derived.

## Recommendations

Backend recommendations must carry sources such as:

- `reported-remediation`
- `rule:sqli`
- `rule:rce`
- `rule:network-exposure`
- `rule:known-exploited`
- `rule:monitoring`

UI-derived fallback recommendations, if ever shown, must be clearly labelled and must not replace backend-backed remediation.

## Delivery

The final delivery must not include:

- `.env`
- `.env.local`
- `.env.production`
- real API keys
- real passwords
- local database dumps with sensitive data
- private model artifacts unless explicitly intended for delivery
