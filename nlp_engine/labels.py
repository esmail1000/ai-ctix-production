"""Label schema for cybersecurity NER / CTI extraction.

This schema is designed for a Cyber Threat Intelligence / Pentest Report NLP model.
It supports vulnerability extraction, IOCs, affected assets, products, versions,
risk fields, and remediation-related entities.

Important:
- Keep the first legacy labels stable for backward compatibility.
- New models should be trained using this expanded schema.
"""

from __future__ import annotations

from typing import Dict, Final, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Main entity schema
# ---------------------------------------------------------------------------
# Keep the first four labels stable because older project code/models expected them.
# After that, we extend the schema for higher-quality CTI extraction.
ENTITY_TYPES: Final[Tuple[str, ...]] = (
    # Legacy / core labels
    "VULN_TYPE",
    "CVE_ID",
    "IMPACT",
    "SEVERITY",

    # Vulnerability standards / scoring
    "CWE_ID",
    "CVSS_SCORE",
    "CVSS_VECTOR",
    "CPE",

    # Remediation / mitigation
    "REMEDIATION",
    "PATCH",
    "MITIGATION",

    # Affected technology / assets
    "PRODUCT",
    "VENDOR",
    "VERSION",
    "AFFECTED_COMPONENT",
    "ASSET",
    "ENDPOINT",
    "SERVICE",

    # Network / web indicators
    "IP_ADDRESS",
    "IP_RANGE",
    "URL",
    "DOMAIN",
    "EMAIL",
    "PORT",

    # File / malware / IOC indicators
    "FILE_PATH",
    "FILE_NAME",
    "MD5",
    "SHA1",
    "SHA256",
    "HASH",
    "MALWARE",

    # Attack intelligence
    "ATTACK_VECTOR",
    "ATTACK_TECHNIQUE",
    "MITRE_TECHNIQUE",
    "THREAT_ACTOR",
    "EXPLOIT",
    "EXPLOIT_AVAILABLE",

    # Risk / business context
    "RISK_LEVEL",
    "EXPLOITABILITY",
    "CONFIDENTIALITY_IMPACT",
    "INTEGRITY_IMPACT",
    "AVAILABILITY_IMPACT",
)


# Public schema types expected to be returned by inference later.
# This does not mean every field must always be present in each result.
SCHEMA_ENTITY_TYPES: Final[Tuple[str, ...]] = (
    "VULN_TYPE",
    "CVE_ID",
    "CWE_ID",
    "CVSS_SCORE",
    "CVSS_VECTOR",
    "SEVERITY",
    "RISK_LEVEL",
    "IMPACT",
    "REMEDIATION",
    "MITIGATION",
    "PATCH",
    "PRODUCT",
    "VENDOR",
    "VERSION",
    "AFFECTED_COMPONENT",
    "ASSET",
    "ENDPOINT",
    "SERVICE",
    "IP_ADDRESS",
    "IP_RANGE",
    "URL",
    "DOMAIN",
    "EMAIL",
    "PORT",
    "FILE_PATH",
    "FILE_NAME",
    "MD5",
    "SHA1",
    "SHA256",
    "HASH",
    "MALWARE",
    "ATTACK_VECTOR",
    "ATTACK_TECHNIQUE",
    "MITRE_TECHNIQUE",
    "THREAT_ACTOR",
    "EXPLOIT",
    "EXPLOIT_AVAILABLE",
)


# Maps model entity names to clean JSON output keys.
ENTITY_TO_OUTPUT_KEY: Final[Dict[str, str]] = {
    "VULN_TYPE": "vulnerability_types",
    "CVE_ID": "cve_ids",
    "CWE_ID": "cwe_ids",
    "CVSS_SCORE": "cvss_scores",
    "CVSS_VECTOR": "cvss_vectors",
    "CPE": "cpes",

    "SEVERITY": "severity",
    "RISK_LEVEL": "risk_levels",
    "IMPACT": "impacts",

    "REMEDIATION": "remediations",
    "MITIGATION": "mitigations",
    "PATCH": "patches",

    "PRODUCT": "products",
    "VENDOR": "vendors",
    "VERSION": "versions",
    "AFFECTED_COMPONENT": "affected_components",
    "ASSET": "assets",
    "ENDPOINT": "endpoints",
    "SERVICE": "services",

    "IP_ADDRESS": "ips",
    "IP_RANGE": "ip_ranges",
    "URL": "urls",
    "DOMAIN": "domains",
    "EMAIL": "emails",
    "PORT": "ports",

    "FILE_PATH": "file_paths",
    "FILE_NAME": "file_names",
    "MD5": "md5_hashes",
    "SHA1": "sha1_hashes",
    "SHA256": "sha256_hashes",
    "HASH": "hashes",
    "MALWARE": "malware",

    "ATTACK_VECTOR": "attack_vectors",
    "ATTACK_TECHNIQUE": "attack_techniques",
    "MITRE_TECHNIQUE": "mitre_techniques",
    "THREAT_ACTOR": "threat_actors",
    "EXPLOIT": "exploits",
    "EXPLOIT_AVAILABLE": "exploit_available",

    "EXPLOITABILITY": "exploitability",
    "CONFIDENTIALITY_IMPACT": "confidentiality_impacts",
    "INTEGRITY_IMPACT": "integrity_impacts",
    "AVAILABILITY_IMPACT": "availability_impacts",
}


# Groups will help later in inference/evaluation.
ENTITY_GROUPS: Final[Dict[str, Tuple[str, ...]]] = {
    "core_vulnerability": (
        "VULN_TYPE",
        "CVE_ID",
        "CWE_ID",
        "SEVERITY",
        "RISK_LEVEL",
        "CVSS_SCORE",
        "CVSS_VECTOR",
    ),
    "impact_and_fix": (
        "IMPACT",
        "REMEDIATION",
        "MITIGATION",
        "PATCH",
    ),
    "affected_target": (
        "PRODUCT",
        "VENDOR",
        "VERSION",
        "AFFECTED_COMPONENT",
        "ASSET",
        "ENDPOINT",
        "SERVICE",
        "CPE",
    ),
    "iocs": (
        "IP_ADDRESS",
        "IP_RANGE",
        "URL",
        "DOMAIN",
        "EMAIL",
        "PORT",
        "FILE_PATH",
        "FILE_NAME",
        "MD5",
        "SHA1",
        "SHA256",
        "HASH",
        "MALWARE",
    ),
    "attack_intel": (
        "ATTACK_VECTOR",
        "ATTACK_TECHNIQUE",
        "MITRE_TECHNIQUE",
        "THREAT_ACTOR",
        "EXPLOIT",
        "EXPLOIT_AVAILABLE",
        "EXPLOITABILITY",
    ),
}


# Minimum labels we care about first when building the next dataset.
# We will not force all labels immediately because your current dataset is small.
PRIORITY_TRAINING_ENTITY_TYPES: Final[Tuple[str, ...]] = (
    "VULN_TYPE",
    "CVE_ID",
    "CWE_ID",
    "SEVERITY",
    "CVSS_SCORE",
    "IMPACT",
    "REMEDIATION",
    "PRODUCT",
    "VERSION",
    "AFFECTED_COMPONENT",
    "ASSET",
    "ENDPOINT",
    "IP_ADDRESS",
    "URL",
    "DOMAIN",
    "PORT",
    "ATTACK_VECTOR",
)


# ---------------------------------------------------------------------------
# BIO label helpers
# ---------------------------------------------------------------------------
def build_label_lists() -> Tuple[List[str], Dict[str, int], Dict[int, str]]:
    """Construct ordered BIO label strings and bidirectional mappings.

    Returns:
        labels:
            Ordered labels: O, then all B-* labels, then all I-* labels.
        label2id:
            Mapping from label string to integer id.
        id2label:
            Mapping from integer id to label string.
    """
    labels: List[str] = ["O"]

    for entity_type in ENTITY_TYPES:
        labels.append(f"B-{entity_type}")

    for entity_type in ENTITY_TYPES:
        labels.append(f"I-{entity_type}")

    label2id: Dict[str, int] = {label: idx for idx, label in enumerate(labels)}
    id2label: Dict[int, str] = {idx: label for label, idx in label2id.items()}

    return labels, label2id, id2label


LABELS, LABEL2ID, ID2LABEL = build_label_lists()

# Hugging Face token classification uses -100 to ignore special/subword tokens.
IGNORE_INDEX: Final[int] = -100


def entity_type_from_label(label: str) -> Optional[str]:
    """Return canonical entity type for a BIO label, or None for non-entity labels."""
    if label in {"O", "PAD", "X"}:
        return None

    if label.startswith("B-") or label.startswith("I-"):
        return label[2:]

    return None


def is_begin_label(label: str) -> bool:
    """Return True if label is a B-* entity-begin tag."""
    return label.startswith("B-")


def is_inside_label(label: str) -> bool:
    """Return True if label is an I-* entity-inside tag."""
    return label.startswith("I-")


def is_valid_entity_type(entity_type: str) -> bool:
    """Return True if the given entity type exists in the schema."""
    return entity_type in ENTITY_TYPES


def output_key_for_entity(entity_type: str) -> str:
    """Return the public JSON output key for a model entity type.

    Unknown entity types are converted to a safe lowercase plural-ish key.
    """
    if entity_type in ENTITY_TO_OUTPUT_KEY:
        return ENTITY_TO_OUTPUT_KEY[entity_type]

    return entity_type.lower() + "s"


def get_entity_types() -> Tuple[str, ...]:
    """Return the full immutable entity schema."""
    return ENTITY_TYPES


def get_priority_training_entity_types() -> Tuple[str, ...]:
    """Return the labels we should target first in the next training dataset."""
    return PRIORITY_TRAINING_ENTITY_TYPES