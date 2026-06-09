# Phase 3 — Risk Scoring & Defense Engine

## Scope

This phase replaces the previous risk-prioritization wrapper with a deterministic, evidence-grounded backend engine. It does not fabricate CVSS, KEV, MISP, or threat intelligence values.

## Implemented behavior

- Separates report-extracted CVSS from threat-intelligence CVSS.
- Keeps the original report severity unchanged.
- Computes `finalRiskScore` from:
  - report severity
  - report CVSS
  - threat intelligence CVSS
  - known-exploited/CISA KEV status
  - MISP match count when configured
  - proof-of-concept or exploitation steps in the report
  - attack vector
  - exposed/network-reachable evidence
  - impact text
  - workflow status
- Produces explainable `riskFactors` for each finding.
- Produces rule-based defense recommendations from real report evidence and vulnerability class.
- Saves report-level risk output in `AnalysisRiskScore` without requiring a Prisma migration.
- Updates Neo4j `Finding` nodes with final risk properties before attack-path and threat-scenario generation.

## No fake backend guarantees

- NVD is read from the NVD API only.
- CISA KEV is read from the CISA KEV catalog only.
- MISP is used only when `MISP_BASE_URL` and `MISP_API_KEY` are configured.
- If a threat-intelligence source fails or is unavailable, the engine records missing/partial intel and continues without inventing replacement values.
- Recommendations are deterministic rule-engine outputs derived from finding text, CWE/CVE indicators, report remediation, attack vector, and real threat-intelligence flags.

## Files changed

- `lib/mock-data.ts`
- `lib/server/types.ts`
- `lib/server/risk-scoring.ts`
- `lib/server/ai-risk-scoring.ts`
- `lib/server/threat-aware-risk.ts`
- `lib/server/recommendations.ts`
- `lib/server/public-data.ts`
- `lib/server/pipeline/post-analysis.ts`
- `lib/server/knowledge-graph/update-risk.ts`
- `lib/server/knowledge-graph/attack-path.ts`
- `lib/server/llm-analysis/threat-scenarios.ts`
- `lib/server/threat-intel/enrich-report.ts`
- `app/api/risk-scoring/[reportId]/route.ts`
- `app/reports/[id]/page.tsx`

## Acceptance test

Use the same `sample_full_report.txt`.

Expected `/api/analyze` properties:

- `report.findings = 2`
- each finding includes `reportCvss`
- each finding includes `finalRiskScore`
- each finding includes `riskFactors`
- each finding includes `recommendations`
- `CVE-2017-5638` has `knownExploited = true` when CISA KEV enrichment succeeds
- Attack Paths use the final graph risk score
- Threat Scenarios use the updated recommendation list stored on the graph

## Notes

The historic filename `ai-risk-scoring.ts` is kept only for compatibility with existing imports. Its implementation now delegates to the deterministic threat-aware engine.
