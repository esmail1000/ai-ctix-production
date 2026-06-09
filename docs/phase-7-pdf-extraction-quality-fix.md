# Phase 7 PDF Extraction Quality Fix

## Scope

This patch fixes quality issues found during final testing with the real `pentest-report-minivpn.pdf` report.

## Issues fixed

- Added a narrow 7ASecurity/minivpn profile extractor for `MIV-01-###` findings.
- Preserved the correct MIV finding IDs instead of allowing index recovery to attach the wrong ID to a title.
- Fixed section delimiting so the current heading is not immediately re-matched as the next heading.
- Prefer detailed report-body sections over index/catalog-only rows when the same MIV ID appears twice.
- Extract minivpn-specific remediation text such as `In order to resolve this issue...`.
- Produce availability/DoS-focused impact text for minivpn crash, handshake, and connection-disruption issues.
- Adjusted risk-factor ordering so DoS/availability findings are not labeled as authentication-bypass/data-exposure risks merely because a generic impact sentence contains broad wording.

## Non-goals

- No fake CVE, CVSS, KEV, MISP, exploit, or threat-intel data is added.
- The minivpn profile only reads text already present in the submitted report.
- The generic extractor remains available for other report families.

## Expected retest

Re-analyze `pentest-report-minivpn.pdf` and verify:

- report type is `PDF`.
- finding count remains `12`.
- `MIV-01-004` maps to `Possible DoS via Index Out of Range`.
- DoS impacts mention crash, service disruption, VPN connection failure, or availability loss rather than authentication bypass/data exposure unless the source section explicitly says so.
- remediation is more specific when the source report provides fix guidance.
- `npm run build` succeeds.
