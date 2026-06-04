# Sprint 1 Baseline
**Scope:** Baseline + Extraction Fix + Schema Cleanup  
**Created:** 2026-04-17  
**Status:** Active

---

## 1. Purpose
This document captures the current extraction baseline before Sprint 1 changes are fully integrated into the project.

The goal is to:
- document the current behavior
- define expected findings for the benchmark report(s)
- record extraction defects
- create a before/after comparison point for Sprint 1

This document should be updated after parser integration is validated.

---

## 2. Sprint 1 Goals
Sprint 1 is considered successful if we achieve all of the following:

1. Structured findings are extracted from labeled report sections.
2. Duplicate findings are eliminated or materially reduced.
3. `title`, `severity`, `asset`, and `status` come from the report when present.
4. `summary`, `impact`, `evidence`, and `remediation` come from the real finding block when present.
5. Findings include extraction metadata:
   - reported fields
   - normalization
   - provenance
6. Heuristic fallback is only used when structured parsing fails.

---

## 3. Benchmark Report Set

### Benchmark A
**Report Name:** Analyzed Report  
**Source Type:** TXT  
**Current Report ID:** `R-001`  
**Reason for selection:** Contains clearly labeled finding blocks and is the main regression candidate for Sprint 1.

Additional benchmark reports should be added here later:
- Benchmark B: structured PDF report
- Benchmark C: semi-structured/noisy report

---

## 4. Expected Findings for Benchmark A
The source report contains the following explicit finding blocks and should ideally produce **6 findings**:

1. Missing MFA for Privileged Access
   - Severity: Critical
   - Asset: admin.acme.local
   - Status: Open

2. Outdated Apache Server With Public CVE Exposure
   - Severity: High
   - Asset: web-gateway-02.acme.local
   - Status: Open
   - Reference: CVE-2023-25690

3. Public Storage Exposure
   - Severity: High
   - Asset: storage.acme.local
   - Status: In Review

4. Weak Password Policy on VPN Access
   - Severity: Medium
   - Asset: vpn.acme.local
   - Status: Open

5. Verbose Error Disclosure in Portal
   - Severity: Low
   - Asset: portal.acme.local
   - Status: Resolved

6. Suspicious External Communication
   - Severity: Medium
   - Asset: app.acme.local
   - Status: Open

### Expected report summary facts
- Total findings: 6
- Critical: 1
- High: 2
- Medium: 2
- Low: 1

---

## 5. Current Baseline Output (Before Sprint 1 Validation)
The current stored output for Benchmark A shows the following behavior:

### Current extracted finding count
- Actual extracted findings: **12**
- Expected explicit findings: **6**

### Current symptoms
- Over-extraction from non-finding text
- Duplicate/near-duplicate findings
- Generic finding titles
- Asset extraction drift
- Status inference instead of status parsing
- Partial or missing coverage for later finding blocks
- Remediation/impact may be generic in fallback paths

---

## 6. Baseline Defects Observed

### A. Count mismatch
**Problem:** The system currently produces 12 findings where the report explicitly contains 6 labeled findings.

**Impact:** Downstream summarization and risk scoring become inflated and noisy.

---

### B. Duplicate / near-duplicate findings
Observed behavior includes repeated or near-repeated findings around the same theme, especially early-report content and MFA/access-control language.

**Impact:** Top risks and severity distribution become unreliable.

---

### C. Generic or distorted titles
Examples of problematic/generated-style titles observed in the current baseline include patterns such as:
- `Security Finding Affecting ...`
- `Security Finding Requiring Review`
- overly generalized titles derived from summary sentences instead of actual finding headers

**Expected behavior:** The title should come from the labeled finding block title whenever available.

---

### D. Asset extraction drift
Observed extracted assets may degrade into overly generic values such as:
- `administrative`
- `storage`
- `application`
- `admin`

**Expected behavior:** Prefer the report’s labeled asset field, such as:
- `admin.acme.local`
- `web-gateway-02.acme.local`
- `storage.acme.local`
- `vpn.acme.local`
- `portal.acme.local`
- `app.acme.local`

---

### E. Status parsing failure
The report includes explicit statuses:
- Open
- In Review
- Resolved

Current behavior may infer status heuristically instead of honoring the source report.

**Expected behavior:** `Status:` from the finding block must override inferred values.

---

### F. Later finding block coverage is incomplete
The report clearly contains later findings such as:
- Weak Password Policy on VPN Access
- Verbose Error Disclosure in Portal
- Suspicious External Communication

These must be preserved as first-class findings and not lost behind early-summary extraction noise.

---

## 7. Defect Taxonomy
Use the following categories during Sprint 1 validation:

- `COUNT_MISMATCH`
- `DUPLICATE_FINDING`
- `WRONG_TITLE`
- `WRONG_ASSET`
- `WRONG_SEVERITY`
- `WRONG_STATUS`
- `MISSING_FINDING`
- `GENERIC_SUMMARY`
- `GENERIC_IMPACT`
- `GENERIC_REMEDIATION`
- `FALLBACK_USED_UNNECESSARILY`

---

## 8. Validation Checklist
After structured parsing is integrated, validate Benchmark A using this checklist.

### Extraction correctness
- [ ] Exactly 6 findings are extracted
- [ ] No duplicate findings remain
- [ ] Each finding title matches the explicit report block title
- [ ] Each finding asset matches the labeled report asset
- [ ] Each finding status matches the labeled report status
- [ ] `CVE-2023-25690` is preserved on the Apache finding

### Content grounding
- [ ] Summary comes from the report block content
- [ ] Impact comes from the report block content
- [ ] Evidence comes from the report block content
- [ ] Remediation comes from the report block content

### Metadata correctness
- [ ] `reported` fields are populated
- [ ] `normalization` is populated
- [ ] `provenance` is populated
- [ ] `provenance.extractionMethod = structured-parser` for structured findings
- [ ] `parserConfidence` is present

### Fallback control
- [ ] Heuristic fallback is not used when structured finding blocks are present
- [ ] Fallback is only used when structured parsing returns zero findings

---

## 9. Before / After Comparison Template

### Before Sprint 1
- Findings extracted:
- Duplicate count:
- Missing findings:
- Wrong asset count:
- Wrong status count:
- Notes:

### After Sprint 1
- Findings extracted:
- Duplicate count:
- Missing findings:
- Wrong asset count:
- Wrong status count:
- Notes:

---

## 10. Definition of Done for Benchmark A
Benchmark A is considered fixed when:
- the parser returns 6 findings
- findings match the explicit report structure
- asset and status fidelity are correct
- later finding blocks are preserved
- extraction metadata is stored
- summarization/risk scoring can safely use the output without obvious duplication noise

---

## 11. Notes
This baseline intentionally focuses on extraction fidelity first.

No changes to summarization or risk scoring should be considered final until Benchmark A passes the validation checklist above.