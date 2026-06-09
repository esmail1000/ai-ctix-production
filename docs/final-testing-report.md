# Phase 7 Final Testing Report

## Purpose

This document records the final acceptance checks for AI CTIX Extractor after Phases 1 through 6. The goal is to prove that the system works end-to-end and does not rely on fake backend data.

## Build status

Run:

```bash
npm run build
```

Acceptance:

- Prisma Client generation succeeds.
- Next.js compilation succeeds.
- TypeScript finishes successfully.
- Static and dynamic routes are listed.
- Any warnings are non-blocking and documented.

Latest observed project state during Phase 6:

- `Compiled successfully`
- `Finished TypeScript`
- Next dev server started successfully on `localhost:3000`.

## End-to-end test flow

Use one report that contains at least:

- SQL Injection with CVE, CWE, CVSS, affected endpoint, IP/URL/port, exploitation steps, impact and remediation.
- Apache Struts RCE with CVE-2017-5638, CWE, CVSS, affected component, proof of concept, impact and remediation.

Expected results:

| Area | Expected result |
|---|---|
| Report ingestion | Report saved with stable report ID and owner scope. |
| Extraction | Two findings created, not one merged finding. |
| Findings | CVE, CWE, asset, impact, remediation and exploitation steps are visible. |
| Threat Intel | CVE-2017-5638 has NVD + CISA KEV; fake CVE has no fake enrichment. |
| Risk scoring | Final threat-aware risk score saved and displayed. |
| Knowledge graph | Report-scoped graph nodes and relationships are created. |
| Attack paths | Paths are graph-derived with asset, indicator, CVE, CWE, OWASP, MITRE, exploit, impact and remediation evidence. |
| Recommendations | Backend recommendations and recommendation sources are shown. |
| SOC dashboard | Dashboard displays real API-backed data and no fake attack path. |
| Export | Report-scoped JSON export returns report, findings, summary and risk score. |

## Multi-format ingestion checks

Test at least these inputs:

| Format | Acceptance |
|---|---|
| TXT | Pasted text or `.txt` upload analyzed successfully. |
| PDF | Text-based PDF extracts readable text. Scanned PDFs return a clear OCR/extraction warning if OCR fails. |
| Markdown | `.md` accepted and analyzed as text. |
| HTML | `.html` / `.htm` accepted and converted to text. |
| DOCX | `.docx` accepted and parsed when supported dependencies are installed. |

## NLP health check

Endpoint:

```text
/api/nlp/health
```

Acceptance in strict mode:

- `enableNlp = true`
- `strictModel = true`
- `requireQualityGate = true`
- `modelDirExists = true`
- `configExists = true`
- `weightFile` is present.
- `metricsFound = true`
- `qualityGatePassed = true`
- HTTP status is `200`.

If the model is missing or the quality gate fails, the system must not present fallback output as trained NLP.

## Threat intelligence checks

Positive CVE:

```text
/api/threat-intel/lookup?cve=CVE-2017-5638
```

Expected:

- NVD status: `ok`
- CISA KEV status: `ok`
- `knownExploited = true`
- `cvssScore = 9.8`

Negative CVE:

```text
/api/threat-intel/lookup?cve=CVE-2099-99999
```

Expected:

- `nvd = false`
- `cisaKev = false`
- `knownExploited = false`
- `cvssScore = null`
- NVD source status is `not_found` or `error`, never fake `ok`.
- CISA KEV source status is `not_found`, never fake `ok`.
- MISP source status is `disabled` if MISP is not configured.

## Graph and attack path checks

For the final sample report, expected graph/attack path evidence includes:

- Report
- Finding
- Asset
- Indicator
- CVE
- CWE
- OWASP
- MITRETechnique
- Exploit
- Impact
- Remediation

Attack path acceptance:

- `pathStatus = graph-derived`
- `graphDerived = true`
- No fake fallback path is displayed as graph-derived.
- Reasoning references final threat-aware risk score and graph evidence types.

## Frontend page checks

| Page | Acceptance |
|---|---|
| `/dashboard` | API-backed SOC summary, no fake trends or fake attack path. |
| `/threat-intel` | CVE cards, NVD/CISA/MISP source statuses, negative CVE test. |
| `/recommendations` | Backend recommendations and sources first; derived fallback count is visible. |
| `/graph` | Real graph nodes/edges and impact/mitigation metrics. |
| `/attack-paths` | Graph-derived paths with evidence sequence and reasoning. |
| `/risk-scoring` | Saved backend score and rationale. |
| `/reports` | Real report list and export/view actions. |
| `/results` | Extracted findings with evidence, remediation, CVE and risk links. |

## Security and delivery checks

- Protected pages redirect unauthenticated users to `/login?next=...`.
- Protected APIs return `401` when unauthenticated.
- Report-scoped APIs verify the authenticated user owns the report.
- `.env`, `.env.local`, `.env.production` and real secrets are excluded from delivery.
- `.env.example` contains placeholders only.
- OTP is not returned to the frontend and is stored hashed in new registrations.
