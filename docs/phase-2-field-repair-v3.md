# Phase 2 Field Repair v3

Adds a final resolved-finding repair pass in `toStoredFinding`. The pass uses the already resolved title, CVE, asset, and CVSS score to locate the original finding section in the submitted report text, then prefers reported `Impact` and `Recommended Fix`/`Remediation` blocks over weak or generic generated text.
