# Evaluation Results

## NLP model quality

The project uses strict model readiness checks through `/api/nlp/health`. The endpoint reads model files, weights and metrics from the configured model directory.

Latest user-reported trained model metrics during this implementation cycle:

| Metric | Value |
|---|---:|
| Precision | 0.5503 |
| Recall | 0.7367 |
| F1 | 0.6300 |
| Accuracy | 0.8979 |

These values are not presented as ideal production metrics. They are recorded as real model evaluation outputs and are used to avoid fake quality claims.

## Functional evaluation performed in Phases 1-6

### Extraction sample

The main validation sample contains two findings:

1. SQL Injection in Login API with CVE-2024-12345, CWE-89, CVSS 9.8, affected endpoint, URL, IP, port, exploitation steps, impact and remediation.
2. Remote Code Execution in Apache Struts with CVE-2017-5638, CWE, CVSS 8.1, affected component, proof of concept, impact and remediation.

Expected extraction output:

- Two findings, not one merged finding.
- Each finding has asset/component, CVE, severity, impact, remediation and exploitation steps.
- Parser confidence is surfaced.

### Threat intelligence validation

| CVE | NVD | CISA KEV | Known exploited | CVSS |
|---|---|---|---|---:|
| CVE-2017-5638 | true | true | true | 9.8 |
| CVE-2024-12345 | true | false | false | 6.7 |
| CVE-2099-99999 | false | false | false | null |

MISP disabled state must be explicit when MISP is not configured.

### Risk scoring validation

The final sample report should produce:

- Final report score: Critical / 100 in the threat-aware scenario.
- CISA KEV and known-exploited status increase urgency only when true.
- Negative or missing threat-intel records must not increase risk.

### Graph and attack path validation

Expected graph-derived path evidence:

- Report
- Finding
- Asset
- Indicator
- CVE
- CWE
- OWASP
- MITRETechnique
- Exploit
- Impact
- Remediation

Expected path fields:

- `pathStatus = graph-derived`
- `graphDerived = true`
- `confidence = 95` for the final validated sample.

## Remaining evaluation tasks for final delivery

- Run the same end-to-end validation using one TXT input, one PDF input, one Markdown input and one HTML input.
- Store screenshots or JSON responses for final academic/project evidence.
- Export one report and archive the JSON output as delivery evidence.
- Confirm that `.env.local` is excluded from the final archive.
