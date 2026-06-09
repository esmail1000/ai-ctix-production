# Phase 7 PDF Profile Alignment Fix

This patch fixes a regression observed while testing `pentest-report-minivpn.pdf`.

## Fixes

- Prefer detailed `MIV-01-###` report body sections over table-of-contents rows.
- Preserve the correct `MIV-01-004` mapping for `Possible DoS via Index Out of Range`.
- Prevent 7ASecurity index recovery from copying stale evidence/remediation/impact from another finding.
- Detect external finding IDs from evidence and provenance source text.
- Deduplicate by external ID while keeping the richer detailed body finding.
- Keep denial-of-service fallback impacts availability-focused instead of auth/data-exposure oriented.

## Acceptance

Re-analyzing `pentest-report-minivpn.pdf` should keep 12 findings while removing wrong cross-linked evidence IDs.
