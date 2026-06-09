# System Architecture

## High-level flow

```text
User/Auth
  -> Analyzer UI
  -> /api/analyze
  -> Text extraction
  -> Strict NLP / hybrid extraction
  -> PostgreSQL report + findings persistence
  -> Post-analysis pipeline
      -> Threat intelligence enrichment
      -> Risk scoring
      -> Knowledge graph build/update
      -> Attack path generation
      -> Threat scenarios / recommendations
  -> SOC frontend dashboards
  -> Export
```

## Main layers

### Frontend

- Dashboard
- Analyzer
- Reports
- Results / Findings
- Risk Scoring
- Recommendations
- Threat Intel
- Knowledge Graph
- Attack Paths
- Export
- Auth pages

The frontend should display data returned by backend APIs or clearly label any UI-only fallback. It must not present fake attack paths, fake known-exploited status, fake threat intelligence, fake CVSS or fake recommendations.

### API layer

Main routes:

- `/api/analyze`
- `/api/nlp/health`
- `/api/reports`
- `/api/findings`
- `/api/risk-scoring/[reportId]`
- `/api/threat-intel/*`
- `/api/knowledge-graph/[reportId]`
- `/api/attack-paths/[reportId]`
- `/api/export`
- `/api/auth/*`

Every report-scoped API must verify the authenticated session and user ownership before reading or writing report data.

### Persistence

- PostgreSQL via Prisma stores users, reports, findings, analysis runs, summaries and risk scores.
- Neo4j stores report-scoped graph nodes and relationships plus global vulnerability taxonomy and threat-intelligence enrichment nodes.

### NLP and extraction

- File extraction supports text-based PDF, DOCX, TXT, Markdown, HTML, CSV, JSON and logs.
- NLP strict mode requires the trained model to be loaded, not using fallback, and passing the model quality gate.
- Heuristic fallback must not be represented as trained NLP.

### Threat intelligence

- NVD is used for CVE advisory/CVSS enrichment.
- CISA KEV is used for known-exploited status.
- MISP is optional and must show `disabled` when not configured.
- Each source reports `ok`, `not_found`, `disabled` or `error`.

### Risk scoring

The risk engine uses deterministic, auditable inputs:

- Report severity
- Report CVSS
- Threat-intel CVSS
- CISA KEV / known exploited
- Exploit availability / proof-of-concept evidence
- Attack vector
- Asset exposure
- Impact terms
- Workflow status and remediation coverage

### Knowledge graph and attack paths

The graph connects:

```text
Report -> Finding -> Asset / Indicator / CVE / CWE / OWASP / MITRE / Exploit / Impact / Remediation
```

Attack paths are graph-derived when they use report-scoped graph evidence. Finding-only fallback rows must be labelled as not graph-derived.
