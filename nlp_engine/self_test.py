"""Lightweight smoke tests for the upgraded CTI NLP pipeline.

Runs without ML dependencies. It validates:
- CVE normalization and span matching.
- Regex/rule fallback extraction.
- Expanded CTI schema.
- Public inference output.
"""

from __future__ import annotations

from inference import run_inference_text
from regex_extractor import extract_all_structured
from span_matching import find_cve_spans, normalize_cve_token


def main() -> None:
    text = (
        "Critical RCE in Apache Struts version 2.5.10 allows Remote Code Execution "
        "and Data Breach on https://app.acme-corp.com:8443/login. "
        "CVE 2021 44228 affects 10.0.0.5:443; port 8080 is exposed. "
        "CWE-94 was identified with CVSS score: 9.8 and vector "
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H. "
        "Public exploit available T1190. Apply vendor patch and upgrade to a fixed version."
    )

    # ------------------------------------------------------------------
    # CVE normalization / matching
    # ------------------------------------------------------------------
    assert normalize_cve_token("cve 2021 44228") == "CVE-2021-44228"
    assert normalize_cve_token("CVE_2021_44228") == "CVE-2021-44228"
    assert find_cve_spans(text, "cve-2021-44228")

    # ------------------------------------------------------------------
    # Regex/rule fallback extraction
    # ------------------------------------------------------------------
    extracted = extract_all_structured(text)

    assert "CVE-2021-44228" in extracted["cve_ids"], extracted
    assert "CWE-94" in extracted["cwe_ids"], extracted
    assert "9.8" in extracted["cvss_scores"], extracted
    assert "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" in extracted["cvss_vectors"], extracted

    assert "Remote Code Execution" in extracted["vulnerability_types"], extracted
    assert "Critical" in extracted["severity"], extracted
    assert "Data Breach" in extracted["impacts"], extracted
    assert "Remote Code Execution" in extracted["impacts"], extracted

    assert "Apache Struts" in extracted["products"], extracted
    assert "2.5.10" in extracted["versions"], extracted

    assert "10.0.0.5" in extracted["ips"], extracted
    assert "https://app.acme-corp.com:8443/login" in extracted["urls"], extracted
    assert "app.acme-corp.com" in extracted["domains"], extracted
    assert "443" in extracted["ports"], extracted
    assert "8080" in extracted["ports"], extracted
    assert "8443" in extracted["ports"], extracted

    assert "T1190" in extracted["mitre_techniques"], extracted
    assert "Exploit Available" in extracted["exploits"], extracted
    assert "true" in extracted["exploit_available"], extracted

    assert "Apply vendor patch" in extracted["remediations"], extracted
    assert "Upgrade to a fixed version" in extracted["remediations"], extracted

    # ------------------------------------------------------------------
    # Public inference schema
    # ------------------------------------------------------------------
    result = run_inference_text(text, mode="regex")

    required_keys = (
        "cve_ids",
        "cwe_ids",
        "cvss_scores",
        "cvss_vectors",
        "vulnerability_types",
        "severity",
        "impacts",
        "remediations",
        "products",
        "versions",
        "ips",
        "urls",
        "domains",
        "ports",
        "mitre_techniques",
        "exploits",
        "exploit_available",
        "findings",
        "meta",
    )

    for key in required_keys:
        assert key in result, result

    assert result["meta"]["engine"] == "nlp-hybrid-cti", result
    assert result["meta"]["schema_version"] == "2.0", result
    assert result["meta"]["mode"] == "regex", result
    assert result["meta"]["model_loaded"] is False, result
    assert result["meta"]["regex_enrichment_used"] is True, result

    assert "CVE-2021-44228" in result["cve_ids"], result
    assert "CWE-94" in result["cwe_ids"], result
    assert "9.8" in result["cvss_scores"], result
    assert "Critical" in result["severity"], result
    assert "Apache Struts" in result["products"], result
    assert "2.5.10" in result["versions"], result
    assert "T1190" in result["mitre_techniques"], result

    assert isinstance(result["findings"], list), result
    assert len(result["findings"]) >= 1, result

    first_finding = result["findings"][0]
    assert first_finding.get("vulnerability_type") == "Remote Code Execution", result
    assert first_finding.get("severity") == "Critical", result
    assert "CVE-2021-44228" in first_finding.get("cve_ids", []), result

    print("NLP smoke tests passed.")


if __name__ == "__main__":
    main()