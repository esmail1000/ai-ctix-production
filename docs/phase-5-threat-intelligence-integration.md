# Phase 5 — Threat Intelligence Integration

## Scope

This patch hardens the threat-intelligence backend integration for NVD, CISA KEV, and optional MISP without fabricating enrichment data.

## Implemented changes

- Adds per-source timeout handling for NVD, CISA KEV, and MISP.
- Adds explicit `sourceStatuses` for `ok`, `not_found`, `disabled`, and `error` source outcomes.
- Keeps NVD CVSS separate from report-extracted CVSS.
- Keeps CISA KEV / `knownExploited` false unless CISA explicitly returns the CVE.
- Makes MISP disabled state explicit when `MISP_BASE_URL` or `MISP_API_KEY` is not configured.
- Adds stronger user scoping to report-scoped Neo4j threat-intel reads and enrichment.
- Allows a read-only fallback to CVEs extracted from the owned report record when Neo4j has no CVE nodes.
- Adds a protected CVE lookup endpoint for negative testing:
  - `/api/threat-intel/lookup?cve=CVE-2099-99999`

## No-fabrication guarantees

- No CVSS is invented when NVD returns no result or fails.
- No CISA KEV status is invented when CISA does not list a CVE.
- No MISP match is invented when MISP is disabled or returns no results.
- Source errors are exposed in `errors` and `sourceStatuses` rather than hidden.
- `not_found` is distinct from `error` and from `disabled`.

## Acceptance tests

1. Run `npm run build`.
2. Run the existing analyze flow for the sample report.
3. Check `/api/threat-intel/[reportId]`.
4. Check `/api/threat-intel/enrich/[reportId]`.
5. Negative CVE lookup:
   - `/api/threat-intel/lookup?cve=CVE-2099-99999`
   - Expected:
     - `nvd = false`
     - `cisaKev = false`
     - `knownExploited = false`
     - `cvssScore = null`
     - MISP disabled state or zero matches is explicit.

## Environment variables

Optional timeout controls:

- `NVD_TIMEOUT_MS` (default `12000`)
- `CISA_KEV_TIMEOUT_MS` (default `12000`)
- `MISP_TIMEOUT_MS` (default `12000`)

Optional source configuration:

- `NVD_API_KEY`
- `MISP_BASE_URL`
- `MISP_API_KEY`
