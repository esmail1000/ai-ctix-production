# Phase 2 Field Repair Patch

This patch improves per-finding field repair after NLP extraction.

## Fixes

- If a finding has a weak or generic impact such as `Remote Code Execution`, the adapter now re-reads the original matched finding section and prefers the report's explicit `Impact:` block.
- If a finding has a generic remediation such as `Patch the affected component...`, the adapter now re-reads the original matched finding section and prefers explicit labels such as `Recommended Fix:`.
- This is a late-stage repair inside `toStoredFinding`, so it works even when the model has already split findings correctly but the model output has weak field-level text.

## Expected sample result

For the sample report, Finding 2 should now return:

- impact: `Remote attackers can execute commands on the server and take full control of the application host.`
- remediation: `Upgrade Apache Struts to the latest patched version and block malicious upload headers.`
