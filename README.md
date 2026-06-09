# AI CTIX Extractor

AI CTIX Extractor is an end-to-end cyber threat intelligence analysis platform for pentest and security reports. It ingests TXT, PDF, DOCX, Markdown, HTML and related text formats, extracts security findings with a strict NLP pipeline, enriches CVEs with threat intelligence, computes threat-aware risk, builds a Neo4j knowledge graph, derives attack paths, and presents the results in a SOC-style analyst dashboard.

## Current validated capabilities

- Authenticated report analysis with PostgreSQL/Prisma persistence.
- File and pasted-text ingestion with PDF, DOCX, TXT, Markdown, HTML, CSV, JSON and log support.
- Strict NLP health checks with model readiness and quality-gate validation.
- Extraction of findings, CVEs, CWEs, affected assets/components, attack vectors, exploitation steps, impact, remediation, evidence and confidence metadata.
- Threat-aware deterministic risk scoring using report CVSS, threat-intel CVSS, CISA KEV, known-exploited status, exploit evidence, attack vector and business exposure signals.
- Defense recommendations with source tracking such as `reported-remediation`, `rule:rce`, `rule:sqli`, `rule:known-exploited` and `rule:monitoring`.
- NVD, CISA KEV and optional MISP threat-intelligence enrichment with explicit source status values: `ok`, `not_found`, `disabled`, and `error`.
- Neo4j knowledge graph with report-scoped findings, assets, indicators, CVEs, CWEs, OWASP mappings, MITRE techniques, exploit evidence, impact and remediation nodes.
- Graph-derived attack paths with `graphDerived`, `pathStatus`, confidence, risk score, known exploited / CISA KEV status, exploit availability, and report-scoped reasoning.
- SOC frontend pages for Dashboard, Findings, Reports, Risk Scoring, Recommendations, Threat Intel, Knowledge Graph, Attack Paths and Export.
- JSON export of report-scoped findings, summaries and risk scoring data.

## No-fake-backend position

The application should not invent threat intelligence, CVSS scores, CISA KEV status, known-exploited status, MISP matches, graph paths or backend recommendations. When a source is unavailable, disabled or has no record, the response must say so explicitly through source status fields, warnings, notes or errors.

Model fallback must not be presented as trained NLP. In strict mode, the analysis pipeline blocks model-based analysis when the trained NLP model is missing, not loaded, using fallback, or failing the quality gate.

## Main routes

- `/api/analyze`
- `/api/nlp/health`
- `/api/reports`
- `/api/reports/[id]`
- `/api/findings`
- `/api/findings/[id]`
- `/api/risk-scoring/[reportId]`
- `/api/threat-intel/lookup?cve=CVE-...`
- `/api/threat-intel/enrich/[reportId]`
- `/api/threat-intel/[reportId]`
- `/api/knowledge-graph/[reportId]`
- `/api/attack-paths/[reportId]`
- `/api/export?reportId=...`

See `docs/api-endpoints.md` for endpoint details.

## Environment

Use `.env.example` as a template and create `.env.local` locally. Do not commit or deliver real `.env`, `.env.local`, `.env.production`, keys, passwords, tokens or exported local databases.

Important variables:

```bash
DATABASE_URL="postgresql://ctix_user:ctix_password@localhost:5432/ctix_db?schema=public"
AUTH_SECRET="replace-with-a-long-random-secret"
APP_BASE_URL="http://localhost:3000"

ENABLE_NLP=true
NLP_MODEL_DIR="nlp_engine/models/cyberbert-ner"
NLP_STRICT_MODEL=true
NLP_REQUIRE_QUALITY_GATE=true
NLP_MIN_MODEL_F1=0.30

NEO4J_URI="neo4j://127.0.0.1:7687"
NEO4J_USERNAME="neo4j"
NEO4J_PASSWORD="replace-locally"

NVD_API_KEY=""
MISP_BASE_URL=""
MISP_API_KEY=""
```

## Run locally

```bash
npm install
npm run build
npm run dev
```

Then open `http://localhost:3000`.

## Final verification flow

1. Run `npm run build`.
2. Start the app with `npm run dev`.
3. Check `/api/nlp/health`.
4. Analyze a TXT sample report.
5. Analyze PDF / Markdown / HTML samples.
6. Test `/api/threat-intel/lookup?cve=CVE-2099-99999` and confirm no fake enrichment.
7. Open Dashboard, Threat Intel, Recommendations, Graph, Attack Paths, Risk Scoring, Reports and Findings.
8. Export a report with `/api/export?reportId=<REPORT_ID>`.
9. Confirm `.env.local` and secrets are not included in delivery artifacts.

See `docs/final-testing-report.md` for the acceptance checklist.
