# API Endpoints

All protected endpoints require a valid application session cookie unless noted otherwise.

## Auth

### `POST /api/auth/register`

Creates a user and sends an email verification code. The OTP is not returned to the frontend.

### `POST /api/auth/verify`

Verifies the user-provided OTP and creates a session cookie.

### `POST /api/auth/login`

Authenticates by username or email and creates a session cookie.

### `POST /api/auth/logout`

Clears the session cookie.

### `GET /api/auth/me`

Returns the current authenticated user.

### `POST /api/auth/forgot-password`

Sends a password reset email if the email exists, without account enumeration.

### `POST /api/auth/reset-password`

Resets password using a valid token and creates a session.

## Analysis

### `POST /api/analyze`

Accepts `FormData`:

- `text`: pasted report text
- `file`: optional uploaded report file

Returns:

- `report`
- `findings`
- `run`
- `graphBuildStatus`
- `postAnalysis`

The route requires authentication and persists report/finding data for the current user.

## NLP

### `GET /api/nlp/health`

Returns model readiness and quality-gate status.

Important fields:

- `ok`
- `enableNlp`
- `strictModel`
- `requireQualityGate`
- `modelDirExists`
- `configExists`
- `weightFile`
- `metricsFound`
- `evalF1`
- `qualityGatePassed`
- `notes`

## Reports and Findings

### `GET /api/reports`

Lists reports owned by the authenticated user.

### `GET /api/reports/[id]`

Returns one report if it belongs to the authenticated user.

### `GET /api/findings`

Lists findings owned by the authenticated user.

### `GET /api/findings/[id]`

Returns one finding if it belongs to the authenticated user.

## Risk Scoring

### `GET /api/risk-scoring/[reportId]`

Loads saved risk score or generates one when requested by route parameters.

Response includes:

- overall risk score/band
- finding-level scores
- scoring rationale
- summary and risk metadata

## Threat Intelligence

### `GET /api/threat-intel/lookup?cve=CVE-...`

Looks up a single CVE using NVD, CISA KEV and optional MISP.

No fake values are generated. A missing CVE returns `nvd=false`, `cisaKev=false`, `knownExploited=false`, `cvssScore=null`.

### `GET /api/threat-intel/enrich/[reportId]`

Enriches all CVEs for a report. Uses graph CVEs when available and fallback extracted CVEs from PostgreSQL findings when the graph has no CVE nodes.

### `GET /api/threat-intel/[reportId]`

Reads graph-stored threat-intelligence enrichment for a report.

## Knowledge Graph

### `GET /api/knowledge-graph/[reportId]`

Returns report-scoped graph nodes and edges for the authenticated user.

## Attack Paths

### `GET /api/attack-paths/[reportId]`

Returns graph-derived attack paths and labelled fallback rows when full graph evidence is unavailable.

Expected path fields:

- `findingId`
- `riskScore`
- `attackPathScore`
- `confidence`
- `pathStatus`
- `graphDerived`
- `knownExploited`
- `cisaKev`
- `exploitAvailable`
- `attackVector`
- `path.nodes`
- `path.relationships`
- `reasoning`

## Export

### `GET /api/export?reportId=<id>`

Exports a report-scoped JSON payload containing report, findings, summaries and risk scores.

### `GET /api/export`

Exports a list-mode payload with authenticated user reports.
