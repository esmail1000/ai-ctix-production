# Phase 7 PDF MIV Body Recovery Fix

This patch improves the 7ASecurity/minivpn PDF recovery path used when an MIV entry is present in the report index but the main extraction/deduplication pipeline did not keep the corresponding detailed body finding.

## Fixes

- Recovers missing MIV findings from the detailed report body when possible, not only from the table of contents.
- Keeps the correct external finding ID, for example `MIV-01-004` for `Possible DoS via Index Out of Range`.
- Extracts the real remediation sentence from the detailed body, such as length/bounds checks before indexing or slicing.
- Uses DoS/availability impact text instead of generic attacker-opportunity text for crash and connection-failure findings.
- Marks body-based recovery with `7asecurity-body-recovery` provenance so it is distinguishable from pure index recovery.

## Scope

This is deliberately narrow and only affects 7ASecurity-style reports that contain MIV IDs such as `MIV-01-004`.
