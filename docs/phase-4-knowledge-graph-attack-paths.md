# Phase 4 — Knowledge Graph & Attack Paths

## Scope

This patch hardens the backend Knowledge Graph and Attack Path layer. It does not add mock graph data, fake threat intelligence, or synthetic CVE enrichment.

## What changed

- Added first-class graph indicators: URL, Domain, IP, Port, Service, and Endpoint.
- Added relationship provenance for deterministic mappings:
  - `report-extracted`
  - `known-cve-rule`
  - `deterministic-keyword-rule`
  - `threat-intel`
  - `risk-engine`
- Added confidence and inferred flags on graph relationships where mappings are not directly reported.
- Added safe per-report graph cleanup before rebuilding findings to avoid stale report-specific graph paths.
- Tightened graph query isolation so every node in a traversed path must either belong to the current user/report or be an allowed global CTI node such as CVE/CWE/OWASP/MITRE.
- Extended attack paths to include Asset and Indicator nodes.
- Added explicit `pathStatus` and `graphDerived` flags so finding-only fallbacks are not presented as full graph-derived attack paths.
- Attack path reasoning now surfaces final risk score, known exploitation, exploit evidence, and attack vector where present.

## Non-goals

- No fake MITRE or CVE enrichment.
- No fake successful Neo4j response.
- No fabricated known-exploited status.
- No generated threat intelligence when NVD/CISA/MISP has not supplied it.

## Acceptance checks

1. `npm run build` passes.
2. `/api/analyze` still returns successful `graphBuildStatus`.
3. `/api/knowledge-graph/[reportId]` includes Report, Finding, CVE, CWE, OWASP/MITRE, Asset, Indicator, Impact, Remediation, and Exploit nodes when present in the report.
4. `/api/attack-paths/[reportId]` includes `pathStatus`, `graphDerived`, `final threat-aware risk score` reasoning, and uses Asset/Indicator evidence where available.
5. If Neo4j fails, the API must return an error and not fake a successful graph response.

## Phase 4 Follow-up Fix

The follow-up patch tightens report scoping and attack-path construction after UI/API validation:

- Attack paths are now assembled from direct report-scoped graph evidence connected to each finding: Asset, Indicator, CVE, CWE, OWASP, MITRETechnique, Exploit, Impact, and Remediation.
- Impact selection prefers report-extracted, non-inferred impact nodes over generic or rule-derived impact labels.
- Query traversal now requires report-scoped nodes such as Impact, Remediation, Exploit, and Indicator to have an exact `reportId` match instead of accepting missing `reportId` through fallback coalescing.
- Report-scoped relationships now carry `userId`, `reportId`, and where applicable `findingId`, preventing stale scoped relationships from being treated as current report evidence.
- The graph remains non-fabricated: if direct evidence is absent, the path is marked `finding-only` rather than presenting a fake enriched path.
