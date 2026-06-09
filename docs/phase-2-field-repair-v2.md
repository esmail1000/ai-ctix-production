# Phase 2 Field Repair v2

This patch makes the extraction repair step prefer the original input section located by CVE/title/component over a weak `_rawSection` stored on a model finding.

It fixes cases where model-level values such as `Remote Code Execution` or generic remediation text override the more specific `Impact:` and `Recommended Fix:` blocks from the source report.
