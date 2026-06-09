# Phase 2 — Data Ingestion & Extraction Completion

## Goal
Improve field-level extraction quality after Phase 1 verified the NLP model and `/api/analyze` end-to-end pipeline.

## Scope
- Preserve reported `Impact`, `Remediation`, `Recommended Fix`, `Proof of Concept`, and `Exploitation Steps` blocks.
- Keep model-generated findings, but enrich them with the matching report section when the model is better at segmentation and the TypeScript section parser is better at field text.
- Split numbered exploitation steps into separate items instead of merging multiple steps into one string.
- Improve structured-parser labels for `Recommended Fix`, `Risk Impact`, and exploitation step blocks.

## Files changed
- `lib/server/nlp/nlp-adapter.ts`
- `lib/server/report-parser.ts`

## Expected verification sample
Using the existing `sample_full_report.txt`, `/api/analyze` should return:
- `report.findings = 2`
- `critical = 1`
- `high = 1`
- `threatIntel.cveCount = 2`
- Finding 1 has 3 exploitation steps and reported SQL Injection impact/remediation.
- Finding 2 has the original report impact: `Remote attackers can execute commands on the server and take full control of the application host.`
- Finding 2 has the original report remediation: `Upgrade Apache Struts to the latest patched version and block malicious upload headers.`

## Acceptance criteria
1. No reduction in finding count compared with Phase 1.
2. No silent fallback to fake NLP results.
3. Impact/remediation are reported when source report contains explicit labels.
4. PoC/exploitation steps are stored as separate list items when numbered.
5. Model CVE/CWE/CVSS extraction is preserved after section enrichment.
