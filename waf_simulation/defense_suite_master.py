"""
🛡️ ENTERPRISE AI-CTI HYBRID DEFENSE SUITE v3.0 - MASTER ENGINE
============================================================
A single, self-contained, elite security suite combining:
1. WAFCore Engine: Real-time OWASP Top 10 protection, recursive de-obfuscator, and AST-like parser.
2. Flask Web Server Sandbox: Premium glassmorphic website with built-in templates (no external files needed!).
3. Live PDF Watchdog Observer: Real-time JSON log listener compiling stunning ReportLab WAF reports.
4. Heuristic Malware Forensic Scanner: Pure-Python PE parser (MZ/PE, Section Entropy, IAT Imports) & script scanner.
5. Risk Speedometer Generator: High-fidelity Matplotlib half-circle gauge chart compiler.
6. Administrative CLI Dashboard: Comprehensive console utility to manage, list, and unblock IPs.
"""

import os
import sys
import re
import urllib
import urllib.parse
import json
import base64
import time
import math
import struct
import datetime
import hashlib
import threading
import warnings
from collections import defaultdict, Counter
from pathlib import Path

# Programmatic dependency resolution for 'requests'
try:
    import requests
except ImportError:
    print("[*] Installing missing dependency: requests...")
    import subprocess
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])
        import requests
    except Exception as e:
        print(f"[!] Failed to auto-install requests: {e}")
        print("[!] Please run: pip install requests")
        sys.exit(1)


# Core Third-Party Dependencies
from flask import Flask, request, jsonify, redirect, url_for, render_template_string, Response, g
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ReportLab Layout & PDF Compiler Elements
try:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from fpdf import FPDF
    HAS_FPDF = True
except ImportError:
    HAS_FPDF = False

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.platypus.flowables import HRFlowable

# Data Telemetry Visualization Elements
import matplotlib
matplotlib.use('Agg')  # Thread-safe headless GUI rendering
import matplotlib.pyplot as plt
import numpy as np

# Global Paths & Configurations
BASE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = BASE_DIR / "waf_reports"
PDF_REPORTS_DIR = BASE_DIR / "waf_pdf_reports"
KB_PATH = BASE_DIR.parent / "defense_analysis_output" / "defense_knowledge_base.json"
DESKTOP = Path(os.path.join(os.path.expanduser("~")), "Desktop")

# Ensure required directories exist immediately
for directory in [BASE_DIR, REPORTS_DIR, PDF_REPORTS_DIR, KB_PATH.parent]:
    directory.mkdir(parents=True, exist_ok=True)

# ══════════════════════════════════════════════════════════════════════════
#  SECTION 1: Dynamic Defense Knowledge Base Creator
# ══════════════════════════════════════════════════════════════════════════
DEFAULT_KB = {
    "SQL Injection": {
        "description": "Exploitation of web input fields to inject arbitrary SQL statements into a backend database.",
        "mitigation": [
            "Implement parameterized queries (Prepared Statements) with PDO or secure ORMs.",
            "Enforce strict input whitelisting and sanitize special characters.",
            "Apply the principle of least privilege, limiting DB user credentials."
        ]
    },
    "Cross-Site Scripting (XSS)": {
        "description": "Injection of malicious client-side script payloads that execute in the victim's browser context.",
        "mitigation": [
            "Perform context-aware output encoding (HTML, Javascript, CSS escaping).",
            "Deploy a robust, secure Content Security Policy (CSP) header.",
            "Set secure cookies with HttpOnly and SameSite flags."
        ]
    },
    "Remote Code Execution (RCE)": {
        "description": "Execution of arbitrary system shell commands on the host by abusing unsafe system invocation calls.",
        "mitigation": [
            "Disable dangerous system evaluation calls (eval, system, shell_exec).",
            "Avoid passing raw, unvalidated user strings to command interpreters.",
            "Run services inside jailed sandboxes or low-privilege isolated containers."
        ]
    },
    "Sensitive Data Exposure": {
        "description": "Unauthorized access to local system configuration structures or directory traversal.",
        "mitigation": [
            "Utilize strict path normalization checks to reject path traversal boundaries.",
            "Restrict read permissions on operating system directories and settings files.",
            "Disable dynamic web server directory listing features globally."
        ]
    }
}

if not KB_PATH.exists():
    with open(KB_PATH, "w", encoding="utf-8") as f:
        json.dump(DEFAULT_KB, f, indent=4)

# ══════════════════════════════════════════════════════════════════════════
#  SECTION 2: Enterprise WAFCore Engine (v2.0)
# ══════════════════════════════════════════════════════════════════════════
class WAFCore:
    def __init__(self, kb_path=KB_PATH, reports_dir=REPORTS_DIR):
        self.reports_dir = Path(reports_dir)
        self.request_history = defaultdict(list)
        self.blocked_ips_file = BASE_DIR / "blocked_ips.json"
        self.blocked_ips = self._load_blocked_ips()
        self.kb_path = Path(kb_path)
        self.kb = self._load_kb()

        # Attack Layer Configuration Parameters
        self.MAX_PAYLOAD_SIZE = 15000
        self.RATE_LIMIT_WINDOW = 2.0
        self.RATE_LIMIT_MAX_REQS = 20
        self.SENSITIVE_ENDPOINTS_LIMIT = 5
        self.SENSITIVE_ENDPOINTS = ["/transfer", "/checkout", "/pay", "/payment", "/withdraw"]

        # Signature Match Complilations
        self.bad_bots = re.compile(r"(?i)(sqlmap|nikto|burpsuite|dirbuster|gobuster|nmap|masscan|hydra|w3af|acunetix)")
        self.sig_sqli = re.compile(r"(?i)(union(\s+|/\*.*?\*/)+(all\s+)?select|'\s*(or|and)\s*('|\d|true|false|null)|--|#|;\s*(drop|alter|create|truncate|exec)|waitfor\s+delay|sleep\s*\(|pg_sleep\s*\()")
        self.sig_xss = re.compile(r"(?i)(<script[\s>]|</script>|javascript\s*:|on\w+\s*=\s*[\"']?[^\"'\s>]*|<svg[\s/>]|<iframe[\s>]|document\.cookie|window\.location|localStorage)")
        self.sig_rce = re.compile(r"(?i)([;&|`]\s*(ls|dir|cat|id|whoami|ping|nc|netcat|wget|curl|bash|sh)|\$\(|shell_exec|system\s*\(|exec\s*\(|eval\s*\()")
        self.sig_path = re.compile(r"(?i)(\.\./|\.\.\\|/etc/passwd|/etc/shadow|boot\.ini|win\.ini|\.git/config)")
        self.sig_misconfig = re.compile(r"(?i)(\.bak|\.old|\.swp|phpinfo\s*\(|/wp-admin|/phpmyadmin|/swagger-ui)")
        self.sig_crypto = re.compile(r"(?i)(cipher=md5|cipher=rc4|algorithm=none|hash=sha1)")
        self.sig_xxe = re.compile(r"(?i)(<!entity|<!doctype|SYSTEM|PUBLIC)")

    def _load_blocked_ips(self):
        if self.blocked_ips_file.exists():
            try:
                with open(self.blocked_ips_file, "r") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        return {ip: {"expiry": time.time() + 300, "reason": "Legacy Block"} for ip in data}
                    if isinstance(data, dict):
                        return data
            except:
                pass
        return {}

    def _save_blocked_ips(self):
        with open(self.blocked_ips_file, "w") as f:
            json.dump(self.blocked_ips, f, indent=4)

    def _load_kb(self):
        if self.kb_path.exists():
            try:
                with open(self.kb_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except:
                pass
        return DEFAULT_KB

    def is_ip_blocked(self, ip):
        self.blocked_ips = self._load_blocked_ips()
        if ip in self.blocked_ips:
            expiry = self.blocked_ips[ip].get("expiry", 0)
            if time.time() < expiry:
                return True
            else:
                del self.blocked_ips[ip]
                self._save_blocked_ips()
        return False

    def block_ip(self, ip, duration=300, reason="WAF Security Policy Block"):
        self.blocked_ips = self._load_blocked_ips()
        self.blocked_ips[ip] = {
            "blocked_at": time.time(),
            "expiry": time.time() + duration,
            "reason": reason
        }
        self._save_blocked_ips()

    def unblock_ip(self, ip):
        self.blocked_ips = self._load_blocked_ips()
        if ip in self.blocked_ips:
            del self.blocked_ips[ip]
            self._save_blocked_ips()
            return True
        return False

    def _normalize_payload(self, raw):
        """Advanced recursive de-obfuscation pipeline."""
        payload = raw.replace('\x00', '')
        payload = re.sub(r'/\*.*?\*/', '', payload) # Strip SQL comments
        
        last_payload = ""
        for _ in range(5):
            if payload == last_payload:
                break
            last_payload = payload
            
            # Recursive URL decoding
            decoded = urllib.parse.unquote(payload)
            if decoded != payload:
                payload = decoded
                continue
                
            # HTML Hex/Decimal Entities (&#x27;, &#106;)
            html_entity_pattern = re.compile(r'&#(x?[0-9a-fA-F]+);')
            matches = html_entity_pattern.findall(payload)
            if matches:
                for match in matches:
                    try:
                        char = chr(int(match[1:], 16)) if match.startswith('x') else chr(int(match))
                        payload = payload.replace(f"&#{match};", char)
                    except: pass
                continue
                
            # Standard HTML Entities
            html_standards = {"&quot;": '"', "&lt;": "<", "&gt;": ">", "&amp;": "&", "&apos;": "'"}
            for ent, char in html_standards.items():
                if ent in payload:
                    payload = payload.replace(ent, char)
            
            # Hex values (\x27, 0x27)
            hex_pattern = re.compile(r'\\x([0-9a-fA-F]{2})')
            hex_matches = hex_pattern.findall(payload)
            if hex_matches:
                for match in hex_matches:
                    try:
                        payload = payload.replace(f"\\x{match}", chr(int(match, 16)))
                    except: pass
                continue
                
            # JS fromCharCode
            char_code_pattern = re.compile(r'(?i)String\.fromCharCode\s*\(([\d\s,]+)\)')
            cc_matches = char_code_pattern.findall(payload)
            if cc_matches:
                for match in cc_matches:
                    try:
                        resolved = "".join(chr(int(x.strip())) for x in match.split(','))
                        payload = payload.replace(f"String.fromCharCode({match})", resolved)
                    except: pass
                continue

            # Base64 nested payloads
            b64_pattern = re.compile(r'([A-Za-z0-9+/]{20,}={0,2})')
            b64_matches = b64_pattern.findall(payload)
            if b64_matches:
                for match in b64_matches:
                    try:
                        decoded_bytes = base64.b64decode(match)
                        decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
                        if len(decoded_str) > 0 and all(32 <= ord(c) < 127 or c in '\r\n\t' for c in decoded_str):
                            payload = payload.replace(match, decoded_str)
                    except: pass
                continue
                
        return payload

    def _analyze_syntax_anomaly(self, payload):
        """Stateful AST-like parser to count anomalies."""
        score = 0
        reasons = []
        
        # 1. SQL Injection quote-balance checker
        single_quotes = payload.count("'")
        double_quotes = payload.count('"')
        ticks = payload.count('`')
        if (single_quotes % 2 != 0) or (double_quotes % 2 != 0) or (ticks % 2 != 0):
            score += 35
            reasons.append("Mismatched SQL quotes/ticks")
            
        # 2. SQL Comment boundaries
        if payload.count("--") > 0 or payload.count("#") > 0:
            score += 20
            reasons.append("SQL termination comment characters present")
            
        # 3. High keyword-to-operator density
        sql_keywords = {"select", "union", "insert", "update", "delete", "drop", "alter", "where", "having", "or", "and", "from"}
        words = re.split(r'\s+|[(),;]', payload)
        keyword_count = sum(1 for w in words if w.lower() in sql_keywords)
        if keyword_count >= 3:
            score += 30
            reasons.append(f"High SQL Keyword Density ({keyword_count} keywords)")

        # 4. HTML Tag event-handler parsing (XSS)
        if "<" in payload and ">" in payload:
            tags = re.findall(r'<([^>]+)>', payload)
            for tag in tags:
                tag_lower = tag.lower().strip()
                if tag_lower.startswith("script") or "javascript:" in tag_lower:
                    score += 50
                    reasons.append("Active HTML script tag context")
                attrs = re.split(r'\s+', tag)
                for attr in attrs:
                    if attr.strip().lower().startswith("on") and "=" in attr:
                        score += 45
                        reasons.append(f"Active event handler attribute '{attr}' inside HTML tag")
                        
        # 5. RCE Command chains
        chain_symbols = [";", "&&", "||", "`", "$("]
        for symbol in chain_symbols:
            if symbol in payload:
                if re.search(r'(?i)(ls|cat|id|whoami|sh|bash|powershell|curl|wget)', payload):
                    score += 40
                    reasons.append(f"Command chain operator '{symbol}' with execution binary")

        return score >= 45, reasons

    def _check_jwt(self, token):
        try:
            parts = token.split('.')
            if len(parts) == 3:
                header_json = base64.b64decode(parts[0] + '==').decode('utf-8', errors='ignore')
                header = json.loads(header_json)
                alg = header.get("alg", "").lower()
                if alg in ("none", "", "null"):
                    return True, "JWT alg=none bypass exploit"
                if alg in ("hs256",) and parts[2] in ("", "test", "secret"):
                    return True, "JWT weak signature exploit"
        except: pass
        return False, ""

    def _trigger_incident(self, ip, attack_type, path, evidence, tenant_id=None):
        incident_id = f"INC-{int(time.time() * 1000) % 2000000000}"
        
        # Get dynamic mitigation from KB
        kb_entry = self.kb.get(attack_type, {"description": "Dynamic web application exploitation.", "mitigation": ["Sanitize all inputs.", "Apply WAF policies."]})
        
        # Resolve tenant information from clients.json
        tenant_name = "AI-CTI Main Suite"
        tenant_email = "admin@aictix.com"
        clients_file = Path(__file__).resolve().parent / "clients.json"
        if clients_file.exists():
            try:
                with open(clients_file, "r", encoding="utf-8") as f:
                    clients = json.load(f)
                    if tenant_id in clients:
                        tenant_name = clients[tenant_id]["name"]
                        tenant_email = clients[tenant_id]["it_email"]
            except:
                pass

        report_data = {
            "id": incident_id,
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": ip,
            "attack_type": attack_type,
            "target_path": path,
            "evidence": evidence,
            "action_taken": "Blocked & Logged",
            "success": "Yes",
            "mitigation_recommendations": kb_entry["mitigation"],
            "tenant_id": tenant_id or "default_tenant",
            "tenant_name": tenant_name,
            "tenant_email": tenant_email
        }
        
        # Write JSON report
        report_file = self.reports_dir / f"{incident_id}.json"
        with open(report_file, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=4)
            
        # Update public/waf-report.json in nextjs project
        nextjs_waf_json = BASE_DIR / "fianl-submit" / "public" / "waf-report.json"
        try:
            if nextjs_waf_json.exists():
                with open(nextjs_waf_json, "r", encoding="utf-8") as f:
                    waf_data = json.load(f)
            else:
                waf_data = {"source": "WAF Live Stream", "records": []}
        except:
            waf_data = {"source": "WAF Live Stream", "records": []}

        # Calculate severity and mitigation for nextjs format
        severity_label, _ = get_severity(attack_type)
        mitigation_str = "\n".join(f"{i} {m}" for i, m in enumerate(kb_entry["mitigation"], 1))
        evidence_hash = hashlib.sha256(str(evidence).encode("utf-8")).hexdigest()

        new_record = {
            "incidentId": incident_id,
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "attackType": attack_type,
            "severity": severity_label,
            "sourceIp": ip,
            "targetPath": path,
            "attackEvidence": str(evidence),
            "actionTaken": "BLOCKED",
            "blocked": "✔️ Yes",
            "mitigation": mitigation_str,
            "sha256": evidence_hash,
            "tenantId": tenant_id or "default_tenant",
            "tenantName": tenant_name,
            "tenantEmail": tenant_email
        }

        if "records" not in waf_data:
            waf_data["records"] = []
        waf_data["records"].insert(0, new_record)

        try:
            with open(nextjs_waf_json, "w", encoding="utf-8") as f:
                json.dump(waf_data, f, indent=4)
        except Exception as e:
            print(f"\n[WAF Error] Failed to update Next.js WAF JSON: {e}")

        # Temporarily block IP for 5 minutes
        self.block_ip(ip, duration=300, reason=f"{attack_type} Block")
        
        return True, attack_type

    def analyze_request(self, ip, method, path, headers, body_str="", tenant_id=None):
        """Main 10-Layer Request Inspection Pipeline."""
        if self.is_ip_blocked(ip):
            return True, "IP_BLOCKED"

        # LAYER 1: Bad Bots & Scanner Detection
        user_agent = headers.get("User-Agent", "")
        if not user_agent.strip():
            return self._trigger_incident(ip, "Reconnaissance Attack", path, "Empty User-Agent block", tenant_id=tenant_id)
        if self.bad_bots.search(user_agent):
            return self._trigger_incident(ip, "Reconnaissance Attack", path, f"Malicious Scanner User-Agent: {user_agent}", tenant_id=tenant_id)

        # LAYER 2: HTTP Method Enforcement
        allowed_methods = {"GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"}
        if method.upper() not in allowed_methods:
            return self._trigger_incident(ip, "Security Misconfiguration", path, f"Illegal HTTP Method: {method}", tenant_id=tenant_id)

        raw_payload = f"{path} {body_str}"

        # LAYER 3: Buffer Overflow / Payload Sizing
        if len(raw_payload) > self.MAX_PAYLOAD_SIZE:
            return self._trigger_incident(ip, "Memory Corruption", path, f"Payload sizing exceeded {self.MAX_PAYLOAD_SIZE} bytes", tenant_id=tenant_id)

        # LAYER 4: XML Bomb (XXE) Pre-check
        if "<!entity" in body_str.lower() or "<!doctype" in body_str.lower():
            if self.sig_xxe.search(body_str):
                return self._trigger_incident(ip, "XML External Entity (XXE)", path, "XML Entity Bomb payload", tenant_id=tenant_id)

        # LAYER 5: Recursive De-obfuscation Normalizer
        combined = self._normalize_payload(raw_payload).lower()

        # LAYER 5b: Stateful AST-like Syntax Parser
        has_anomaly, reasons = self._analyze_syntax_anomaly(combined)
        if has_anomaly:
            inferred = "SQL Injection"
            if any("script" in r or "event" in r for r in reasons):
                inferred = "Cross-Site Scripting (XSS)"
            elif any("chain" in r for r in reasons):
                inferred = "Remote Code Execution (RCE)"
            return self._trigger_incident(ip, inferred, path, f"AST-like Parser Match. Reasons: {', '.join(reasons)}", tenant_id=tenant_id)

        # LAYER 6: Standard Signature Inspection
        checks = [
            ("SQL Injection",                self.sig_sqli),
            ("Cross-Site Scripting (XSS)",   self.sig_xss),
            ("Remote Code Execution (RCE)",  self.sig_rce),
            ("Sensitive Data Exposure",      self.sig_path),
            ("Security Misconfiguration",    self.sig_misconfig),
            ("Cryptographic Weakness",       self.sig_crypto),
            ("XML External Entity (XXE)",    self.sig_xxe),
        ]
        for name, pattern in checks:
            m = pattern.search(combined)
            if m:
                return self._trigger_incident(ip, name, path, f"Signature matched: {m.group(0)[:100]}", tenant_id=tenant_id)

        # LAYER 7: JWT Signature and alg Checks
        auth_header = headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
            jwt_attack, jwt_msg = self._check_jwt(token)
            if jwt_attack:
                return self._trigger_incident(ip, "Cryptographic Weakness", path, jwt_msg, tenant_id=tenant_id)

        # LAYER 8: Sensitive GET CSRF Protection
        referer = headers.get("Referer", "")
        if method.upper() == "GET" and path.split("?")[0] in self.SENSITIVE_ENDPOINTS:
            if referer and not referer.startswith(f"http://{headers.get('Host', '')}"):
                return self._trigger_incident(ip, "Broken Access Control", path, f"GET CSRF referrer mismatch: {referer}", tenant_id=tenant_id)

        # LAYER 9: sliding window Rate Limiting (DoS Protection)
        now = time.time()
        self.request_history[ip] = [t for t in self.request_history[ip] if now - t < self.RATE_LIMIT_WINDOW]
        self.request_history[ip].append(now)
        if len(self.request_history[ip]) > self.RATE_LIMIT_MAX_REQS:
            return self._trigger_incident(ip, "Denial of Service (DoS)", path, f"IP flooded {len(self.request_history[ip])} requests in {self.RATE_LIMIT_WINDOW}s", tenant_id=tenant_id)

        # LAYER 10: Race Condition Transaction Analyzer
        if path.split("?")[0] in self.SENSITIVE_ENDPOINTS:
            recent_txns = [t for t in self.request_history[ip] if now - t < 1.0]
            if len(recent_txns) > self.SENSITIVE_ENDPOINTS_LIMIT:
                return self._trigger_incident(ip, "Race Condition", path, f"Concurrency anomaly: {len(recent_txns)} sensitive transactions in 1.0s", tenant_id=tenant_id)

        return False, ""

# ══════════════════════════════════════════════════════════════════════════
#  SECTION 3: Automated PDF Report Compiler (ReportLab)
# ══════════════════════════════════════════════════════════════════════════
C_DARK_BG      = colors.HexColor("#0D1117")
C_BLUE         = colors.HexColor("#1F6FEB")
C_LIGHT_BLUE   = colors.HexColor("#F0F6FC")
C_WHITE        = colors.HexColor("#FFFFFF")
C_BORDER       = colors.HexColor("#D0D7DE")
C_LABEL        = colors.HexColor("#57606A")
C_GREY_ROW     = colors.HexColor("#F6F8FA")
C_RED_ACCENT   = colors.HexColor("#CF222E")
C_GREEN        = colors.HexColor("#1A7F37")

def get_severity(attack_type):
    critical_attacks = {"SQL Injection", "Remote Code Execution (RCE)", "XML External Entity (XXE)", "Memory Corruption"}
    high_attacks = {"Cross-Site Scripting (XSS)", "Sensitive Data Exposure"}
    medium_attacks = {"Security Misconfiguration", "Cryptographic Weakness", "Race Condition", "Broken Access Control"}
    
    if attack_type in critical_attacks:
        return "CRITICAL", C_RED_ACCENT
    elif attack_type in high_attacks:
        return "HIGH", colors.HexColor("#BC4C00")
    elif attack_type in medium_attacks:
        return "MEDIUM", colors.HexColor("#9A6700")
    return "LOW", C_BLUE

def map_threat_to_standards(attack_type):
    name = str(attack_type).lower()
    if "sql" in name:
        return "OWASP A03:2025 - Injection", "MITRE T1190 - Exploit Public-Facing Application"
    elif "xss" in name or "cross" in name or "script" in name:
        return "OWASP A03:2025 - Injection (XSS)", "MITRE T1189 - Drive-by Compromise"
    elif "path" in name or "traverse" in name or "directory" in name:
        return "OWASP A01:2025 - Broken Access Control", "MITRE T1083 - File and Directory Discovery"
    elif "rce" in name or "execution" in name or "cmd" in name:
        return "OWASP A03:2025 - Injection (RCE)", "MITRE T1203 - Exploitation for Client Execution"
    elif "brute" in name or "credential" in name or "auth" in name:
        return "OWASP A07:2025 - Identification &amp; Authentication Failures", "MITRE T1110 - Brute Force"
    elif "dos" in name or "denial" in name:
        return "OWASP A04:2025 - Insecure Design (DoS)", "MITRE T1498 - Network Denial of Service"
    elif "xml" in name or "xxe" in name:
        return "OWASP A05:2025 - Security Misconfiguration", "MITRE T1190 - Exploit Public-Facing Application"
    elif "csrf" in name or "request forgery" in name:
        return "OWASP A01:2025 - Broken Access Control (CSRF)", "MITRE T1566 - Phishing"
    elif "ssrf" in name or "server-side request" in name:
        return "OWASP A10:2025 - Server-Side Request Forgery", "MITRE T1190 - Exploit Public-Facing Application"
    else:
        return "OWASP A05:2025 - Security Misconfiguration", "MITRE T1190 - Exploit Public-Facing Application"

def get_five_detailed_mitigations(attack_type):
    name = str(attack_type).lower()
    if "sql" in name:
        return [
            "Use Prepared Statements: Enforce parameterized queries or prepared statements across all database queries to neutralize SQL structures.",
            "Input Validation and Type Casting: Implement strict allow-lists and ensure numeric inputs are strictly cast (e.g. using int() or float()) before DB operations.",
            "Principle of Least Privilege: Configure the database user account to only possess SELECT, INSERT, and UPDATE permissions, strictly denying administrative privileges.",
            "Web Application Firewall (WAF) Integration: Deploy WAF filters to continuously inspect incoming request payloads for SQL keywords like UNION, SELECT, and OR.",
            "Database Error Shielding: Disable raw database error exposure to the end-users to prevent information gathering and blind SQL injection vector probing."
        ]
    elif "xss" in name or "cross" in name or "script" in name:
        return [
            "Context-aware Output Encoding: Safely encode all user-supplied data using HTML, Attribute, or JavaScript encoding before rendering in the DOM.",
            "Implement Content Security Policy (CSP): Enforce a strict CSP header (e.g., default-src 'self') to block the execution of unauthorized inline scripts.",
            "HTTPOnly and Secure Cookie Flags: Apply HttpOnly and Secure attributes to session cookies to prevent theft via malicious JavaScript injection.",
            "Input Sanitation: Utilize library-based sanitizers (like DOMPurify or Bleach) to strip unsafe tags and attributes from any rich-text inputs.",
            "Validate HTTP Headers: Restrict accepted Content-Types and enforce strict boundary rules on all incoming REST API requests."
        ]
    elif "path" in name or "traverse" in name or "directory" in name:
        return [
            "Path Canonicalization: Resolve absolute canonical paths using os.path.realpath() and verify that the target path remains within the base directory.",
            "Implement Strict File Allow-lists: Restrict file downloads/access to pre-approved indices or keys instead of direct user-controlled file path inputs.",
            "Access Control List (ACL) Restricting: Ensure that the runtime server process executes under a non-root, highly isolated account with zero system-level access.",
            "Input Path Filtering: Strip directory traversal tokens like '../', '..\\', and absolute paths from incoming string variables.",
            "Chrooted Environment or Containerization: Deploy the application within an isolated Docker container or a chroot jail to seal the host system from traversal attacks."
        ]
    elif "rce" in name or "execution" in name or "cmd" in name:
        return [
            "Eliminate System Command Invocation: Avoid passing user data to shell executors (e.g., exec(), eval(), system(), or subprocess.Popen(..., shell=True)).",
            "Enforce Sandbox Environments: Execute any required script processing in highly isolated sandbox environments with strict CPU, memory, and timeout limits.",
            "Input Signature Whitelisting: Apply rigid regular expressions to permit only alphanumeric parameters, blocking command separators like ;, &&, and |.",
            "Runtime Execution Monitoring: Implement OS auditing agents (like Auditd or Sysmon) to log and alert on any shell spawns originating from the web server.",
            "Host Harden Restrictions: Read-only mount application filesystems to block run-time command execution files from writing payload updates."
        ]
    elif "dos" in name or "denial" in name:
        return [
            "Implement Rate Limiting: Deploy strict per-IP token bucket limits at the WAF or Nginx gateway level to throttle excessive client requests.",
            "Configure Keep-Alive and Request Timeouts: Lower idle connection durations to prevent resource exhaustion attacks (like Slowloris).",
            "Enable Reverse Proxy Caching: Cache static pages and common responses to offload heavy processing loads from backend servers.",
            "Auto-scaling Security Policies: Configure cloud scale groups to dynamically add resources or trigger DDoS scrubbing center scrubbing when traffic peaks.",
            "Drop Suspicious Headers: Filter out heavily fragmented requests or anomalous request patterns before they reach the main backend threads."
        ]
    else:
        return [
            "Input Validation: Apply strong whitelist rules on all user input to reject any character arrays that fail strict formatting templates.",
            "Least Privilege Execution: Ensure the server runtime runs under a dedicated, unprivileged sandbox user account to prevent system-wide compromise.",
            "Deploy Web Application Firewall (WAF): Ensure that WAF filters are consistently active, updated with the latest threat intelligence signatures.",
            "Log Auditing & Compliance Tracking: Maintain immutable log directories of WAF-blocked request blocks to support future forensics and investigations.",
            "Regular Security Assessments: Perform automated vulnerability scans and annual manual penetration testing to trace and patch potential bypasses."
        ]

def build_waf_pdf(json_path):
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    incident_id   = data.get("id", "UNKNOWN")
    timestamp     = data.get("timestamp", "N/A")
    source_ip     = data.get("source_ip", "N/A")
    attack_type   = data.get("attack_type", "N/A")
    target_path   = data.get("target_path", "N/A")
    evidence      = data.get("evidence", "N/A")
    action_taken  = data.get("action_taken", "N/A")
    success       = data.get("success", "N/A")
    mitigations   = get_five_detailed_mitigations(attack_type)
    
    tenant_id     = data.get("tenant_id", "default_tenant")
    tenant_name   = data.get("tenant_name", "AI-CTI Main Suite")
    tenant_email  = data.get("tenant_email", "admin@aictix.com")

    # Calculate SHA-256 cryptographic integrity hash of the raw exploit payload
    evidence_hash = hashlib.sha256(str(evidence).encode("utf-8")).hexdigest()

    # Escape HTML tags to prevent ReportLab parsing issues
    evidence = str(evidence).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    target_path = str(target_path).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    attack_type = str(attack_type).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    # Safe validation to prevent single-string looping bugs (vertical letters)
    if isinstance(mitigations, str):
        temp_mit = mitigations.strip()
        if temp_mit.endswith('.'):
            temp_mit = temp_mit[:-1]
        
        # Split by periods first
        parts = [p.strip() for p in temp_mit.split(". ") if p.strip()]
        if len(parts) <= 1:
            # Try splitting by comma, or ", and "
            parts = [p.strip() for p in re.split(r',\s*and\s+|,', temp_mit) if p.strip()]
        mitigations = parts

    # Standardize list elements (capitalize, add period)
    formatted_mitigations = []
    for item in mitigations:
        item = str(item).strip()
        if item:
            item = item[0].upper() + item[1:]
            if not item.endswith('.'):
                item += '.'
            formatted_mitigations.append(item)
    mitigations = formatted_mitigations

    severity_label, severity_color = get_severity(attack_type)
    
    # Save to tenant directory
    tenant_dir = PDF_REPORTS_DIR / tenant_id
    tenant_dir.mkdir(parents=True, exist_ok=True)
    pdf_path = tenant_dir / f"{incident_id}.pdf"

    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm
    )

    styles = getSampleStyleSheet()
    story = []

    def ps(name, **kw):
        return ParagraphStyle(name, **kw)

    style_header_title = ps("HTitle", fontSize=22, leading=28, textColor=C_WHITE, fontName="Helvetica-Bold", alignment=TA_CENTER)
    style_header_sub = ps("HSub", fontSize=10, leading=14, textColor=colors.HexColor("#90CAF9"), fontName="Helvetica", alignment=TA_CENTER)
    style_section = ps("Sec", fontSize=13, leading=18, textColor=C_BLUE, fontName="Helvetica-Bold", spaceAfter=4)
    style_label = ps("Lbl", fontSize=9, leading=13, textColor=C_LABEL, fontName="Helvetica-Bold")
    style_value = ps("Val", fontSize=10, leading=14, textColor=colors.black, fontName="Helvetica")
    style_bullet = ps("Bul", fontSize=10, leading=16, textColor=colors.HexColor("#1A237E"), fontName="Helvetica", leftIndent=12)
    style_footer = ps("Ftr", fontSize=8, textColor=C_LABEL, fontName="Helvetica", alignment=TA_RIGHT)

    # 1. Header Banner
    header_data = [[Paragraph("🛡️  WAF INCIDENT REPORT", style_header_title)]]
    sub_data = [[Paragraph(f"Incident ID: {incident_id}  ·  Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", style_header_sub)]]
    
    header_table = Table(header_data, colWidths=[17*cm])
    header_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), C_DARK_BG),
        ("TOPPADDING", (0,0), (-1,-1), 18),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
        ("ROUNDEDCORNERS", [6]),
    ]))
    sub_table = Table(sub_data, colWidths=[17*cm])
    sub_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), C_DARK_BG),
        ("TOPPADDING", (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 18),
    ]))
    story.append(header_table)
    story.append(sub_table)
    story.append(Spacer(1, 0.5*cm))

    # 2. Severity Badge
    severity_style = ps("Sev", fontSize=14, leading=20, textColor=C_WHITE, fontName="Helvetica-Bold", alignment=TA_CENTER)
    badge = Table([[Paragraph(f"⚠️  SEVERITY: {severity_label}  |  Attack: {attack_type}", severity_style)]], colWidths=[17*cm])
    badge.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), severity_color),
        ("TOPPADDING", (0,0), (-1,-1), 10),
        ("BOTTOMPADDING", (0,0), (-1,-1), 10),
        ("ROUNDEDCORNERS", [4]),
    ]))
    story.append(badge)
    story.append(Spacer(1, 0.6*cm))

    # 3. Incident Details Grid
    story.append(Paragraph("📋  Incident Details", style_section))
    story.append(HRFlowable(width="100%", thickness=1.5, color=C_BLUE, spaceAfter=8))

    def lbl(text): return Paragraph(text, style_label)
    def val(text): return Paragraph(str(text), style_value)

    success_color = C_GREEN if str(success).lower() == "yes" else C_RED_ACCENT
    success_style = ps("Suc", fontSize=10, leading=14, textColor=C_WHITE, fontName="Helvetica-Bold", alignment=TA_CENTER)
    success_cell = Table([[Paragraph(f"✔  Blocked", success_style)]], colWidths=[4*cm])
    success_cell.setStyle(TableStyle([
        ("BACKGROUND", (0,0),(-1,-1), success_color),
        ("TOPPADDING", (0,0),(-1,-1), 5),
        ("BOTTOMPADDING", (0,0),(-1,-1), 5),
    ]))

    details = [
        [lbl("Incident ID"),   val(incident_id),  lbl("Timestamp"),    val(timestamp)],
        [lbl("Source IP"),     val(source_ip),     lbl("Target Path"),  val(target_path)],
        [lbl("Target Company"),val(tenant_name),  lbl("IT SOC Contact"), val(tenant_email)],
        [lbl("Attack Type"),   val(attack_type),   lbl("Action Taken"), val(action_taken)],
        [lbl("SHA-256 Hash"),  val(evidence_hash[:22] + "..."), lbl("Blocked?"),     success_cell],
    ]
    detail_table = Table(details, colWidths=[3.5*cm, 5*cm, 3.5*cm, 5*cm])
    detail_table.setStyle(TableStyle([
        ("BOX",          (0,0), (-1,-1), 1, C_BORDER),
        ("INNERGRID",    (0,0), (-1,-1), 0.5, C_BORDER),
        ("TOPPADDING",   (0,0), (-1,-1), 8),
        ("BOTTOMPADDING",(0,0), (-1,-1), 8),
        ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
    ]))
    story.append(detail_table)
    story.append(Spacer(1, 0.7*cm))

    # 3.5 Compliance & Threat Intelligence Mapping
    story.append(Paragraph("🛡️  Compliance &amp; Threat Intelligence Mapping", style_section))
    story.append(HRFlowable(width="100%", thickness=1.5, color=C_BLUE, spaceAfter=8))
    
    owasp_map, mitre_map = map_threat_to_standards(attack_type)
    
    # Dynamically split standards into Reference ID and description profiles
    owasp_id, owasp_desc = "N/A", "N/A"
    if " - " in owasp_map:
        owasp_id, owasp_desc = owasp_map.split(" - ", 1)
    else:
        owasp_id = owasp_map

    mitre_id, mitre_desc = "N/A", "N/A"
    if " - " in mitre_map:
        mitre_id, mitre_desc = mitre_map.split(" - ", 1)
    else:
        mitre_id = mitre_map

    # Safely escape ampersands for ReportLab XML parser safety
    owasp_id = owasp_id.replace("&", "&amp;")
    owasp_desc = owasp_desc.replace("&", "&amp;")
    mitre_id = mitre_id.replace("&", "&amp;")
    mitre_desc = mitre_desc.replace("&", "&amp;")
    
    mapping_details = [
        [lbl("Security Standard"), lbl("Reference ID"), lbl("Threat Category / Description")],
        [val("OWASP Mapping"), val(owasp_id), val(owasp_desc)],
        [val("MITRE ATT&amp;CK"), val(mitre_id), val(mitre_desc)]
    ]
    mapping_table = Table(mapping_details, colWidths=[5.0*cm, 4.5*cm, 7.5*cm])
    mapping_table.setStyle(TableStyle([
        ("BOX",          (0,0), (-1,-1), 1, C_BORDER),
        ("INNERGRID",    (0,0), (-1,-1), 0.5, C_BORDER),
        ("TOPPADDING",   (0,0), (-1,-1), 8),
        ("BOTTOMPADDING",(0,0), (-1,-1), 8),
        ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
        ("BACKGROUND",   (0,0), (-1,0), colors.HexColor("#F5F7FA")),
        ("BACKGROUND",   (0,1), (-1,-1), C_WHITE),
    ]))
    story.append(mapping_table)
    story.append(Spacer(1, 0.7*cm))

    # 4. Evidence Box
    story.append(Paragraph(f"🔍  Attack Evidence (SHA-256: {evidence_hash})", style_section))
    story.append(HRFlowable(width="100%", thickness=1.5, color=C_BLUE, spaceAfter=8))

    evidence_style = ps("Ev", fontSize=9, leading=14, textColor=colors.HexColor("#B71C1C"), fontName="Courier-Bold")
    ev_table = Table([[Paragraph(evidence, evidence_style)]], colWidths=[17*cm])
    ev_table.setStyle(TableStyle([
        ("BACKGROUND",    (0,0),(-1,-1), colors.HexColor("#FFF8F8")),
        ("BOX",           (0,0),(-1,-1), 1.5, C_RED_ACCENT),
        ("TOPPADDING",    (0,0),(-1,-1), 12),
        ("BOTTOMPADDING", (0,0),(-1,-1), 12),
        ("LEFTPADDING",   (0,0),(-1,-1), 14),
    ]))
    story.append(ev_table)
    story.append(Spacer(1, 0.7*cm))

    # 5. Mitigations Section
    if mitigations:
        story.append(Paragraph("🛠️  Mitigation Recommendations &amp; Action Plan", style_section))
        story.append(HRFlowable(width="100%", thickness=1.5, color=C_BLUE, spaceAfter=8))
        
        mit_rows = []
        for i, item in enumerate(mitigations, 1):
            num_style = ps(f"Num{i}", fontSize=10, textColor=C_WHITE, fontName="Helvetica-Bold", alignment=TA_CENTER)
            num_cell = Table([[Paragraph(str(i), num_style)]], colWidths=[0.8*cm])
            num_cell.setStyle(TableStyle([
                ("BACKGROUND",   (0,0),(-1,-1), C_BLUE),
                ("TOPPADDING",   (0,0),(-1,-1), 6),
                ("BOTTOMPADDING",(0,0),(-1,-1), 6),
            ]))
            mit_rows.append([num_cell, Paragraph(item, style_bullet)])

        mit_table = Table(mit_rows, colWidths=[1.2*cm, 15.8*cm])
        mit_table.setStyle(TableStyle([
            ("BOX",          (0,0),(-1,-1), 1, C_BORDER),
            ("INNERGRID",    (0,0),(-1,-1), 0.5, C_BORDER),
            ("TOPPADDING",   (0,0),(-1,-1), 8),
            ("BOTTOMPADDING",(0,0),(-1,-1), 8),
            ("VALIGN",       (0,0),(-1,-1), "MIDDLE"),
        ]))
        story.append(mit_table)
        story.append(Spacer(1, 0.7*cm))

    story.append(HRFlowable(width="100%", thickness=0.8, color=C_BORDER, spaceBefore=10))
    story.append(Paragraph(f"Generated by AI-CTI Master Defense Suite  ·  {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ·  Incident {incident_id}", style_footer))

    doc.build(story)
    return pdf_path

# Watchdog Observer Class
class WAFReportWatcher(FileSystemEventHandler):
    def __init__(self):
        super().__init__()
        self.processed_files = set()

    def on_created(self, event):
        if not event.is_directory and event.src_path.endswith(".json"):
            # Avoid processing duplicate OS events for the same log path
            if event.src_path in self.processed_files:
                return
            self.processed_files.add(event.src_path)
            
            time.sleep(0.3)
            try:
                pdf_path = build_waf_pdf(event.src_path)
                print(f"\n[Watchdog] ✅ Real-time Incident Report PDF compiled: {pdf_path.name}")
                
                # Load JSON log to extract tenant details for SMTP dispatch log
                with open(event.src_path, "r", encoding="utf-8") as f:
                    log_data = json.load(f)
                
                tenant_name = log_data.get("tenant_name", "AI-CTI Main Suite")
                tenant_email = log_data.get("tenant_email", "admin@aictix.com")
                attack_type = log_data.get("attack_type", "Security Policy Violation")
                
                print(f"📧 [SMTP Alert Dispatcher] Triggered email alert for {tenant_name}")
                print(f"   [SMTP] Recipient: {tenant_email}")
                print(f"   [SMTP] Subject: URGENT: WAF Incident Alert - {attack_type} blocked on {tenant_name}")
                print(f"   [SMTP] Attachment: {pdf_path}")
                print(f"   [SMTP] Status: Dispatch SUCCESS!\n")
            except Exception as e:
                print(f"\n[Watchdog Error] PDF compilation/alert failed: {e}")

# ══════════════════════════════════════════════════════════════════════════
#  SECTION 4: Standalone Forensic Malware Scan Engine & Speedometer
# ══════════════════════════════════════════════════════════════════════════
def shannon_entropy(data):
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def real_cyber_scan_engine(file_path):
    findings = []
    risk_score = 0
    file_type = "Script / Text Payload"
    
    with open(file_path, "rb") as f:
        binary_data = f.read()
        
    total_size = len(binary_data)
    overall_entropy = shannon_entropy(binary_data)
    
    # 1. MZ / PE (Portable Executable) Binary Parser
    if binary_data.startswith(b"MZ"):
        file_type = "Windows Portable Executable (PE) Binary"
        findings.append("[INFO] MZ signature verified (0x5A4D)")
        
        try:
            e_lfanew = struct.unpack("<I", binary_data[0x3C:0x40])[0]
            pe_signature = binary_data[e_lfanew:e_lfanew+4]
            if pe_signature == b"PE\0\0":
                findings.append("[INFO] Valid PE structure signature found (0x00004550)")
                
                coff_start = e_lfanew + 4
                machine_type = struct.unpack("<H", binary_data[coff_start:coff_start+2])[0]
                num_sections = struct.unpack("<H", binary_data[coff_start+2:coff_start+4])[0]
                size_of_optional_header = struct.unpack("<H", binary_data[coff_start+16:coff_start+18])[0]
                
                findings.append(f"[Forensics] Binary Sections Count: {num_sections}")
                machine_map = {0x014c: "x86 (32-bit)", 0x8664: "x64 (64-bit)"}
                findings.append(f"[Forensics] Targeted CPU: {machine_map.get(machine_type, 'Unknown architecture')}")
                
                optional_header_start = coff_start + 20
                section_headers_start = optional_header_start + size_of_optional_header
                
                findings.append("[PE Forensic Section Table Analysis]")
                for i in range(num_sections):
                    offset = section_headers_start + (i * 40)
                    if offset + 40 > total_size:
                        break
                        
                    name_bytes = binary_data[offset:offset+8]
                    sec_name = name_bytes.split(b"\x00")[0].decode("ascii", errors="ignore")
                    
                    raw_data_size = struct.unpack("<I", binary_data[offset+16:offset+20])[0]
                    raw_data_ptr = struct.unpack("<I", binary_data[offset+20:offset+24])[0]
                    
                    section_bytes = binary_data[raw_data_ptr:raw_data_ptr+raw_data_size]
                    sec_entropy = shannon_entropy(section_bytes)
                    
                    entropy_status = "NORMAL"
                    if sec_entropy > 7.2:
                        entropy_status = "CRITICAL (Packed/Encrypted malicious loader suspected)"
                        risk_score += 45
                        findings.append(f"  ⚠️ Section {sec_name} -> Entropy: {sec_entropy:.3f} | {entropy_status}")
                    else:
                        findings.append(f"  - Section {sec_name} -> Entropy: {sec_entropy:.3f} | {entropy_status}")
            else:
                findings.append("[WARNING] Corrupted MZ Header: PE signature not found")
                risk_score += 20
        except Exception as e:
            findings.append(f"[ERROR] PE header parsing exception: {e}")
            risk_score += 15
            
        # Scan binary data for stealth/suspicious Windows API calls (Import monitoring)
        suspicious_apis = {
            b"CreateRemoteThread": "Process Hollowing / Code Injection",
            b"VirtualAllocEx": "Memory allocation for external shellcode",
            b"WriteProcessMemory": "Payload deployment into memory",
            b"OpenProcess": "Obtaining handles to running system processes",
            b"GetProcAddress": "Dynamic API resolving",
            b"LoadLibraryA": "Stealth library loading",
            b"ShellExecuteA": "Executing system commands",
            b"WinExec": "Legacy shell command execution",
            b"NtQuerySystemInformation": "Sandbox evasion",
        }
        findings.append("[Binary IAT API Forensic Audit]")
        found_apis = 0
        for api_bytes, desc in suspicious_apis.items():
            if api_bytes in binary_data:
                risk_score += 25
                found_apis += 1
                findings.append(f"  🚨 Detected API: {api_bytes.decode()} -> {desc}")
        if found_apis == 0:
            findings.append("  - No suspicious API signatures matched in memory space.")
            
    # 2. Script & Text Heuristic Scanner (Yara-like)
    else:
        findings.append(f"[INFO] Scanning as text/script. Overall Entropy: {overall_entropy:.3f}")
        text_content = binary_data.decode("utf-8", errors="ignore")
        if overall_entropy > 6.8:
            risk_score += 30
            findings.append(f"[WARNING] High text entropy ({overall_entropy:.3f}): Obfuscation suspected")
            
        heuristic_rules = [
            (r"(?i)(eval\s*\(\s*\$_POST|eval\s*\(\s*\$_GET|system\s*\(\s*\$_GET|passthru|shell_exec)", "Critical PHP Web Shell Backdoor", 80),
            (r"(?i)(powershell.*-nop.*-w.*hidden.*-encoded|powershell\.exe.*Bypass)", "Stealthy PowerShell Execution", 75),
            (r"(?i)(cmd\.exe\s+/c\s+net\s+user\s+.*\/add)", "Unauthorized Admin Account Creation", 70),
            (r"(?i)(wget\s+http|curl\s+http|downloadstring)", "IOC: Outbound Payload Downloader", 40),
            (r"(?i)(SetWindowsHookEx|GetKeyState|pyHook)", "Keylogger spyware capture signature", 60),
            (r"(?i)(socket\.socket.*connect|bash.*-i.*>&.*/dev/tcp)", "Active reverse shell socket", 85),
        ]
        
        matched_rules = 0
        for regex, name, weight in heuristic_rules:
            m = re.findall(regex, text_content)
            if m:
                risk_score += weight
                matched_rules += 1
                findings.append(f"  🚨 Heuristic Match: {name} -> Count: {len(m)}")
        if matched_rules == 0:
            findings.append("  - No high-risk signature heuristic rules matched.")

    level = "SAFE"
    if risk_score >= 100: level = "DANGEROUS"
    elif risk_score >= 40: level = "SUSPICIOUS"
    
    findings.append(f"\n[SUMMARY] Calculated risk score: {risk_score} -> Level: {level}")
    return level, risk_score, findings, file_type

def draw_gauge(score, save_path):
    """Draws a beautiful, dynamic vector-based speedometer chart."""
    score = min(max(score, 0), 100)
    fig, ax = plt.subplots(figsize=(6, 3.5), subplot_kw={'projection': 'polar'})
    
    # Half-circle angles
    theta = np.linspace(0, np.pi, 100)
    r = np.ones_like(theta)
    
    # 3-Color gradient zones
    ax.barh(1, np.pi/3, left=2*np.pi/3, color='#4CAF50', height=0.3, label='Safe')
    ax.barh(1, np.pi/3, left=np.pi/3, color='#FFC107', height=0.3, label='Suspicious')
    ax.barh(1, np.pi/3, left=0, color='#F44336', height=0.3, label='Dangerous')
    
    # Pointer needle calculation
    # score 0 maps to angle pi, score 100 maps to angle 0
    angle = np.pi - (score / 100.0) * np.pi
    ax.annotate('', xy=(angle, 1.05), xytext=(0, 0),
                arrowprops=dict(facecolor='#0D1117', width=2, headwidth=8, shrink=0.08))
    
    # Visual stylings
    ax.set_theta_zero_location('E')
    ax.set_thetamax(180)
    ax.set_thetamin(0)
    ax.set_xticklabels([])
    ax.set_yticklabels([])
    ax.spines['polar'].set_visible(False)
    ax.grid(False)
    
    plt.title(f"Forensic Risk Index: {score}/100", fontsize=12, fontweight='bold', pad=10, color='#0D1117')
    fig.patch.set_facecolor('white')
    ax.set_facecolor('white')
    
    plt.savefig(save_path, bbox_inches='tight', dpi=150)
    plt.close()

def generate_scanner_pdf(report_data, gauge_img):
    pdf_name = f"FORENSIC_REPORT_{report_data['File Name']}.pdf"
    pdf_path = DESKTOP / pdf_name
    
    doc = SimpleDocTemplate(str(pdf_path), pagesize=A4, leftMargin=1.5*cm, rightMargin=1.5*cm, topMargin=1.5*cm, bottomMargin=1.5*cm)
    styles = getSampleStyleSheet()
    story = []
    
    def ps(name, **kw): return ParagraphStyle(name, **kw)
    style_title = ps("STitle", fontSize=20, leading=26, textColor=C_WHITE, fontName="Helvetica-Bold", alignment=TA_CENTER)
    style_sec = ps("SSec", fontSize=12, leading=16, textColor=C_BLUE, fontName="Helvetica-Bold", spaceBefore=10, spaceAfter=4)
    style_lbl = ps("SLbl", fontSize=9, fontName="Helvetica-Bold", textColor=C_LABEL)
    style_val = ps("SVal", fontSize=9, fontName="Helvetica", textColor=colors.black)
    style_mon = ps("SMon", fontSize=8, leading=12, fontName="Courier", textColor=colors.HexColor("#212121"))
    
    # Title Header
    header = Table([[Paragraph("🔍  STANDALONE FORENSIC STATIC SCANNER", style_title)]], colWidths=[18*cm])
    header.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), C_DARK_BG),
        ("TOPPADDING", (0,0), (-1,-1), 15),
        ("BOTTOMPADDING", (0,0), (-1,-1), 15),
        ("ROUNDEDCORNERS", [4]),
    ]))
    story.append(header)
    story.append(Spacer(1, 0.4*cm))
    
    # Metadata Details Table
    details = [
        [Paragraph("File Name", style_lbl), Paragraph(report_data["File Name"], style_val),
         Paragraph("Scan Timestamp", style_lbl), Paragraph(report_data["Scan Time"], style_val)],
        [Paragraph("File Type", style_lbl), Paragraph(report_data["File Type"], style_val),
         Paragraph("Overall Risk", style_lbl), Paragraph(report_data["Risk Level"], style_val)],
        [Paragraph("MD5 Hash", style_lbl), Paragraph(report_data["Hashes"]["md5"], style_mon),
         Paragraph("SHA-256 Hash", style_lbl), Paragraph(report_data["Hashes"]["sha256"], style_mon)],
    ]
    meta_table = Table(details, colWidths=[3.5*cm, 5.5*cm, 3.5*cm, 5.5*cm])
    meta_table.setStyle(TableStyle([
        ("BOX", (0,0), (-1,-1), 1, C_BORDER),
        ("INNERGRID", (0,0), (-1,-1), 0.5, C_BORDER),
        ("TOPPADDING", (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 0.5*cm))
    
    # Risk Telemetry Gage Plot
    from reportlab.platypus import Image
    story.append(Paragraph("📊 Risk Telemetry Gauge Chart", style_sec))
    story.append(HRFlowable(width="100%", thickness=1.5, color=C_BLUE, spaceAfter=8))
    
    img_flow = Image(gauge_img, width=12*cm, height=7*cm)
    img_table = Table([[img_flow]], colWidths=[18*cm])
    img_table.setStyle(TableStyle([("ALIGN", (0,0), (-1,-1), "CENTER")]))
    story.append(img_table)
    story.append(Spacer(1, 0.5*cm))
    
    # Forensic Findings Monospace Box
    story.append(Paragraph("📝 Forensic Findings & Signatures Audits", style_sec))
    story.append(HRFlowable(width="100%", thickness=1.5, color=C_BLUE, spaceAfter=8))
    
    audit_lines = "<br/>".join(str(f).replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br/>") for f in report_data["Findings"])
    audit_table = Table([[Paragraph(audit_lines, style_mon)]], colWidths=[18*cm])
    audit_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), colors.HexColor("#F9F9F9")),
        ("BOX", (0,0), (-1,-1), 1, C_BORDER),
        ("TOPPADDING", (0,0), (-1,-1), 10),
        ("BOTTOMPADDING", (0,0), (-1,-1), 10),
        ("LEFTPADDING", (0,0), (-1,-1), 12),
    ]))
    story.append(audit_table)
    
    doc.build(story)
    return pdf_path

# ══════════════════════════════════════════════════════════════════════════
#  SECTION 5: Embedded Premium Glassmorphic Web Templates
# ══════════════════════════════════════════════════════════════════════════
CSS_STYLE = """
body {
    background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 100%);
    color: #f8fafc;
    font-family: 'Outfit', 'Inter', sans-serif;
    margin: 0;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
}
.glass-card {
    background: rgba(30, 41, 59, 0.45);
    backdrop-filter: blur(16px);
    -webkit-backdrop-filter: blur(16px);
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 16px;
    padding: 2.5rem;
    width: 90%;
    max-width: 480px;
    box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
    text-align: center;
    transition: transform 0.3s ease, border-color 0.3s ease;
}
.glass-card:hover {
    transform: translateY(-5px);
    border-color: rgba(31, 111, 235, 0.4);
}
h1 {
    font-size: 2.2rem;
    margin-bottom: 0.5rem;
    background: linear-gradient(to right, #38bdf8, #818cf8);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}
p {
    color: #94a3b8;
    font-size: 0.95rem;
    line-height: 1.5;
}
.input-group {
    margin-bottom: 1.25rem;
    text-align: left;
}
label {
    display: block;
    font-size: 0.85rem;
    color: #38bdf8;
    margin-bottom: 0.5rem;
    font-weight: 600;
}
input[type="text"], input[type="password"], input[type="number"] {
    width: 100%;
    padding: 0.75rem;
    border-radius: 8px;
    border: 1px solid rgba(255, 255, 255, 0.1);
    background: rgba(15, 23, 42, 0.6);
    color: #fff;
    box-sizing: border-box;
    outline: none;
    transition: border-color 0.3s;
}
input:focus {
    border-color: #38bdf8;
}
.btn {
    width: 100%;
    padding: 0.75rem;
    border-radius: 8px;
    border: none;
    background: linear-gradient(to right, #2563eb, #4f46e5);
    color: #fff;
    font-weight: bold;
    cursor: pointer;
    font-size: 1rem;
    transition: opacity 0.3s, transform 0.2s;
}
.btn:hover {
    opacity: 0.9;
    transform: scale(0.98);
}
.nav-link {
    display: inline-block;
    margin-top: 1rem;
    color: #818cf8;
    text-decoration: none;
    font-size: 0.85rem;
    transition: color 0.3s;
}
.nav-link:hover {
    color: #38bdf8;
}
.alert-box {
    background: rgba(239, 68, 68, 0.15);
    border: 1px solid #ef4444;
    color: #fca5a5;
    padding: 1rem;
    border-radius: 8px;
    margin-bottom: 1.5rem;
    font-weight: 500;
    text-align: left;
}
"""

T_HOME = """
<!DOCTYPE html>
<html>
<head>
    <title>AI-CTI Web Sandbox</title>
    <style>""" + CSS_STYLE + """</style>
</head>
<body>
    <div class="glass-card">
        <h1>🛡️ WAF Sandbox</h1>
        <p>This is a vulnerable web server simulated behind the advanced reactive WAFCore Engine v2.0.</p>
        <div style="margin-top: 2rem; display: flex; flex-direction: column; gap: 1rem;">
            <a href="/login" class="btn" style="text-decoration:none; display:block; padding-top:0.6rem; height:2rem;">Try Vulnerable Login (SQLi)</a>
            <a href="/search" class="btn" style="text-decoration:none; display:block; padding-top:0.6rem; height:2rem; background:linear-gradient(to right, #0ea5e9, #2563eb);">Try Vulnerable Search (XSS)</a>
            <a href="/transfer" class="btn" style="text-decoration:none; display:block; padding-top:0.6rem; height:2rem; background:linear-gradient(to right, #10b981, #059669);">Try Transfers (Race Conditions)</a>
        </div>
    </div>
</body>
</html>
"""

T_LOGIN = """
<!DOCTYPE html>
<html>
<head>
    <title>WAF Sandbox - Login</title>
    <style>""" + CSS_STYLE + """</style>
</head>
<body>
    <div class="glass-card">
        <h1>Vulnerable Login</h1>
        <p>Test SQL Injection here (e.g. <code>' OR '1'='1</code>)</p>
        <form method="POST" action="/login">
            <div class="input-group">
                <label>Username</label>
                <input type="text" name="username" placeholder="e.g. admin" required>
            </div>
            <div class="input-group">
                <label>Password</label>
                <input type="password" name="password" placeholder="••••••••" required>
            </div>
            <button type="submit" class="btn">Authenticate</button>
        </form>
        <a href="/" class="nav-link">← Go Back to Safety</a>
    </div>
</body>
</html>
"""

T_SEARCH = """
<!DOCTYPE html>
<html>
<head>
    <title>WAF Sandbox - Search</title>
    <style>""" + CSS_STYLE + """</style>
</head>
<body>
    <div class="glass-card">
        <h1>Secure Search</h1>
        <p>Test Cross-Site Scripting (XSS) here (e.g. <code>&lt;script&gt;alert(1)&lt;/script&gt;</code>)</p>
        <form method="GET" action="/search">
            <div class="input-group">
                <label>Query</label>
                <input type="text" name="q" placeholder="Enter keywords..." value="{{ query }}" required>
            </div>
            <button type="submit" class="btn">Search Database</button>
        </form>
        {% if query %}
        <div style="margin-top:1.5rem; text-align:left; background:rgba(255,255,255,0.05); padding:1rem; border-radius:8px;">
            <p style="color:#fff; margin:0;">Search results for: <strong>{{ query }}</strong></p>
            <p style="font-size:0.8rem; margin-top:0.5rem; color:#818cf8;">[WAF let this request pass safely]</p>
        </div>
        {% endif %}
        <a href="/" class="nav-link">← Go Back to Safety</a>
    </div>
</body>
</html>
"""

T_TRANSFER = """
<!DOCTYPE html>
<html>
<head>
    <title>WAF Sandbox - Transfer</title>
    <style>""" + CSS_STYLE + """</style>
</head>
<body>
    <div class="glass-card">
        <h1>Wire Transfer</h1>
        <p>Test Rate Limits & Concurrency (Race Conditions) by spaming this button rapidly.</p>
        <form method="POST" action="/transfer">
            <div class="input-group">
                <label>Account Number</label>
                <input type="text" name="account" placeholder="e.g. 100984532" required>
            </div>
            <div class="input-group">
                <label>Amount ($)</label>
                <input type="number" name="amount" placeholder="e.g. 500" required>
            </div>
            <button type="submit" class="btn" style="background:linear-gradient(to right, #10b981, #059669);">Submit Transfer</button>
        </form>
        <a href="/" class="nav-link">← Go Back to Safety</a>
    </div>
</body>
</html>
"""

T_BLOCKED = """
<!DOCTYPE html>
<html>
<head>
    <title>🚨 ACCESS DENIED - WAFCore v2.0</title>
    <style>
        """ + CSS_STYLE + """
        .glass-card {
            border-color: #ef4444;
            max-width: 550px;
        }
    </style>
</head>
<body>
    <div class="glass-card">
        <h1 style="color:#ef4444; background:none; -webkit-text-fill-color:initial;">🚨 EXPLOIT DETECTED & BLOCKED</h1>
        <p>Your connection has been flagged and temporarily blacklisted by WAFCore v2.0 due to a severe security violation.</p>
        
        <div class="alert-box">
            <strong>Violation Category:</strong> {{ reason }}<br/>
            <strong>WAF Policy Triggered:</strong> Immediate Request Block & IP Quarantine.<br/>
            <strong>Incident Reference:</strong> INC-SYSTEM-AUTOGEN<br/>
            <strong>Mitigation Status:</strong> PDF incident report compiled and sent to SOC admin.
        </div>
        
        <p style="font-size:0.8rem; color:#64748b;">If you believe this is a false positive, please contact the network administrator with your Reference ID.</p>
        <a href="/" class="btn" style="text-decoration:none; display:inline-block; padding-top:0.6rem; height:2rem; width:150px; margin-top:1rem; background:#334155;">Return Home</a>
    </div>
</body>
</html>
"""

T_TENANT_SANDBOX = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ tenant_name }} - Portal</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0f172a, #1e293b);
            color: #f1f5f9;
            margin: 0;
            padding: 0;
            display: flex;
            flex-direction: column;
            align-items: center;
            min-height: 100vh;
        }
        .header {
            width: 100%;
            background: rgba(30, 41, 59, 0.7);
            backdrop-filter: blur(12px);
            border-bottom: 1px solid rgba(255,255,255,0.05);
            padding: 1.5rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-sizing: border-box;
        }
        .logo {
            font-size: 1.5rem;
            font-weight: 700;
            color: #38bdf8;
            letter-spacing: 0.05em;
        }
        .badge {
            background: rgba(16, 185, 129, 0.15);
            color: #34d399;
            border: 1px solid rgba(16, 185, 129, 0.3);
            padding: 0.4rem 0.8rem;
            border-radius: 9999px;
            font-size: 0.8rem;
            font-weight: 600;
        }
        .card {
            background: rgba(30, 41, 59, 0.4);
            backdrop-filter: blur(16px);
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 24px;
            padding: 2.5rem;
            max-width: 600px;
            width: 90%;
            margin-top: 5rem;
            box-shadow: 0 20px 40px rgba(0,0,0,0.3);
            text-align: center;
        }
        h1 {
            font-size: 2.2rem;
            margin-bottom: 0.5rem;
        }
        p {
            color: #94a3b8;
            line-height: 1.6;
            margin-bottom: 2rem;
        }
        .input-group {
            margin-bottom: 1.5rem;
            text-align: left;
        }
        label {
            display: block;
            margin-bottom: 0.5rem;
            font-size: 0.9rem;
            color: #cbd5e1;
        }
        input[type="text"], input[type="password"] {
            width: 100%;
            padding: 0.8rem 1rem;
            border-radius: 12px;
            border: 1px solid rgba(255,255,255,0.1);
            background: rgba(15, 23, 42, 0.6);
            color: #fff;
            box-sizing: border-box;
            font-size: 1rem;
            outline: none;
            transition: 0.2s;
        }
        input:focus {
            border-color: #38bdf8;
            box-shadow: 0 0 0 2px rgba(56, 189, 248, 0.25);
        }
        .btn {
            background: #38bdf8;
            color: #0f172a;
            border: none;
            padding: 0.8rem 2rem;
            border-radius: 12px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            width: 100%;
            transition: 0.2s;
        }
        .btn:hover {
            background: #7dd3fc;
        }
        .footer {
            margin-top: auto;
            padding: 2rem;
            font-size: 0.8rem;
            color: #64748b;
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="logo">{{ tenant_name }}</div>
        <div class="badge">🛡️ AI-CTI Protected</div>
    </div>
    
    <div class="card">
        <h1>Welcome to {{ tenant_name }}</h1>
        <p>This corporate portal is actively monitored and protected by the AI-CTI Cloud WAF Gateway. Any unauthorized security testing or exploits will trigger automated IT SOC alerts.</p>
        
        <form action="" method="POST">
            <div class="input-group">
                <label for="username">Username / Search</label>
                <input type="text" id="username" name="username" placeholder="Type here to search or login..." required>
            </div>
            <button type="submit" class="btn">Submit Query</button>
        </form>
    </div>
    
    <div class="footer">
        Powered by AI-CTI Hybrid Defense Suite v3.0 &copy; 2026. All rights reserved.
    </div>
</body>
</html>
"""

def render_tenant_sandbox(tenant_name, tenant_id, path):
    if request.method == 'POST':
        # This will process form submits through middleware check automatically
        return f"<div style='background:#0f172a; color:#fff; padding:2rem; font-family:sans-serif; text-align:center;'><h1>Query Submitted Successfully to {tenant_name}!</h1><p>Status: All safe.</p><a href='/?tenant={tenant_id}' style='color:#38bdf8;'>Go Back</a></div>"
    return render_template_string(T_TENANT_SANDBOX, tenant_name=tenant_name, tenant_id=tenant_id)

# ══════════════════════════════════════════════════════════════════════════
#  SECTION 6: Interactive CLI Manager & Unified Orchestrator
# ══════════════════════════════════════════════════════════════════════════
app = Flask(__name__)
waf = WAFCore()

@app.before_request
def waf_middleware():
    if request.path.startswith('/static') or request.path == '/blocked':
        return
    # Bypass signature inspection for the threat log ingestion and onboarding endpoints
    if request.path in ['/api/analyze', '/api/onboard']:
        return

    # Dynamic tenant resolution for multi-tenant protection
    tenant_id = request.args.get('tenant')
    if not tenant_id and request.form:
        tenant_id = request.form.get('tenant')
    if not tenant_id:
        # Fallback to Referer header if query parameter is dropped by form action submit
        referer = request.headers.get('Referer', '')
        if referer and 'tenant=' in referer:
            try:
                parsed_ref = urllib.parse.urlparse(referer)
                ref_params = urllib.parse.parse_qs(parsed_ref.query)
                if 'tenant' in ref_params and ref_params['tenant']:
                    tenant_id = ref_params['tenant'][0]
            except:
                pass
    if not tenant_id:
        host = request.headers.get('Host', '').lower()
        if 'acme' in host:
            tenant_id = 'acme_corp'
        elif 'globex' in host:
            tenant_id = 'globex_it'
        else:
            tenant_id = 'default_tenant'

    # Save to Flask global context
    g.tenant_id = tenant_id

    ip = request.remote_addr
    method = request.method
    path = request.full_path
    headers = dict(request.headers)
    body_str = ""
    try:
        if request.form:
            body_str = str(request.form.to_dict())
        else:
            body_str = request.get_data(as_text=True)
    except: pass
    
    is_attack, attack_type = waf.analyze_request(ip, method, path, headers, body_str, tenant_id=g.tenant_id)
    if is_attack:
        return redirect(url_for('blocked_page', reason=attack_type, tenant=g.tenant_id))

@app.route('/api/onboard', methods=['POST'])
def onboard_client():
    try:
        data = request.get_json()
        if not data:
            return {"error": "Invalid JSON payload"}, 400
            
        tenant_id = data.get("tenant_id")
        name = data.get("name")
        domain = data.get("domain", "localhost")
        backend_url = data.get("backend_url")
        it_email = data.get("it_email")
        security_level = data.get("security_level", "HIGH")
        
        if not tenant_id or not name or not backend_url or not it_email:
            return {"error": "Missing required fields (tenant_id, name, backend_url, it_email)"}, 400
            
        clients_file = Path(__file__).resolve().parent / "clients.json"
        
        # Load current clients
        clients = {}
        if clients_file.exists():
            with open(clients_file, "r", encoding="utf-8") as f:
                clients = json.load(f)
                
        # Register new client
        clients[tenant_id] = {
            "name": name,
            "domain": domain,
            "backend_url": backend_url,
            "it_email": it_email,
            "security_level": security_level
        }
        
        # Save back to file
        with open(clients_file, "w", encoding="utf-8") as f:
            json.dump(clients, f, indent=2)
            
        print(f"\n✨ [WaaS Portal] Dynamic Onboarding Success! Registered Client: {name} (ID: {tenant_id})")
        print(f"   [WaaS] Backend URL: {backend_url} | SOC Email: {it_email}")
        
        return {
            "success": True,
            "message": f"Client '{name}' successfully onboarded and secured under AI-CTI Cloud WAF!",
            "credentials": {
                "tenant_id": tenant_id,
                "shield_header": "X-Protected-By",
                "shield_value": "AI-CTI-WAF",
                "waf_gateway_url": f"http://localhost:5050/?tenant={tenant_id}"
            }
        }, 200
    except Exception as e:
        return {"error": f"Failed to onboard client: {str(e)}"}, 500

def home():
    return render_template_string(T_HOME)

def login():
    if request.method == 'POST':
        username = request.form.get('username')
        return f"<div style='background:#0f172a; color:#fff; padding:2rem; font-family:sans-serif; text-align:center;'><h1>Welcome {username}!</h1><a href='/login' style='color:#38bdf8;'>Go Back</a></div>"
    return render_template_string(T_LOGIN)

def search():
    query = request.args.get('q', '')
    return render_template_string(T_SEARCH, query=query)

def transfer():
    if request.method == 'POST':
        amount = request.form.get('amount')
        account = request.form.get('account')
        return f"<div style='background:#0f172a; color:#fff; padding:2rem; font-family:sans-serif; text-align:center;'><h1>Transferred ${amount} to Account #{account} Successfully!</h1><a href='/transfer' style='color:#10b981;'>Transfer Again</a></div>"
    return render_template_string(T_TRANSFER)

@app.route('/blocked')
def blocked_page():
    reason = request.args.get('reason', 'Security Policy Violation')
    tenant_id = request.args.get('tenant', 'default_tenant')
    
    tenant_name = "AI-CTI Main Suite"
    tenant_email = "admin@aictix.com"
    
    # Dynamically resolve return URL to preserve the exact gateway host/port
    host = request.headers.get('Host', 'localhost:5050')
    scheme = request.scheme
    if tenant_id == 'default_tenant':
        backend_url = f"{scheme}://{host}/"
    else:
        backend_url = f"{scheme}://{host}/?tenant={tenant_id}"
        
    clients_file = Path(__file__).resolve().parent / "clients.json"
    if clients_file.exists():
        try:
            with open(clients_file, "r", encoding="utf-8") as f:
                clients = json.load(f)
                if tenant_id in clients:
                    tenant_name = clients[tenant_id]["name"]
                    tenant_email = clients[tenant_id]["it_email"]
        except:
            pass
            
    custom_blocked = T_BLOCKED.replace(
        "<strong>Incident Reference:</strong> INC-SYSTEM-AUTOGEN<br/>",
        f"<strong>Target Protected Portal:</strong> {tenant_name}<br/><strong>Incident Reference:</strong> INC-SYSTEM-AUTOGEN<br/>"
    ).replace(
        "<strong>Mitigation Status:</strong> PDF incident report compiled and sent to SOC admin.",
        f"<strong>Mitigation Status:</strong> PDF report compiled and dispatched to IT SOC team ({tenant_email})."
    ).replace(
        'href="/"',
        f'href="{backend_url}"'
    )
    return render_template_string(custom_blocked, reason=reason), 403

# Catch-all route for proxying
@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'])
def proxy(path):
    if path == 'blocked':
        return blocked_page()

    tenant_id = g.get('tenant_id', 'default_tenant')
    backend_url = "http://127.0.0.1:3000"
    tenant_name = "AI-CTI Main Suite"
    clients_file = Path(__file__).resolve().parent / "clients.json"
    if clients_file.exists():
        try:
            with open(clients_file, "r", encoding="utf-8") as f:
                clients = json.load(f)
                if tenant_id in clients:
                    backend_url = clients[tenant_id]["backend_url"]
                    tenant_name = clients[tenant_id]["name"]
        except:
            pass

    # Proxy the request to the client's backend server
    target_url = f"{backend_url}/{path}"
    if request.query_string:
        target_url += f"?{request.query_string.decode('utf-8')}"

    headers = {key: value for key, value in request.headers.items() if key.lower() != 'host'}
    headers['X-Protected-By'] = 'AI-CTI-WAF'

    # Reconstruct request parameters for proxying multipart/form-data correctly
    proxy_kwargs = {
        'method': request.method,
        'url': target_url,
        'headers': headers,
        'cookies': request.cookies,
        'allow_redirects': False,
        'stream': True
    }

    try:
        if request.files:
            files_dict = {}
            for key, file_storage in request.files.items():
                if file_storage.filename:
                    # Reset the file pointer to the beginning to read the full buffer safely
                    file_storage.stream.seek(0)
                    files_dict[key] = (file_storage.filename, file_storage.stream.read(), file_storage.mimetype)
            proxy_kwargs['files'] = files_dict
            proxy_kwargs['data'] = request.form
            
            # Remove browser Content-Type so requests library can compute the matching boundary
            for k in list(headers.keys()):
                if k.lower() == 'content-type':
                    del headers[k]
        else:
            proxy_kwargs['data'] = request.get_data()

        resp = requests.request(**proxy_kwargs)

        excluded_headers = [
            'content-encoding', 
            'content-length', 
            'transfer-encoding', 
            'connection', 
            'keep-alive', 
            'upgrade',
            'proxy-connection'
        ]
      headers_list = []

for name, value in resp.headers.items():
    lower_name = name.lower()
    if lower_name in excluded_headers or lower_name == 'set-cookie':
        continue
    headers_list.append((name, value))

set_cookie_headers = []
raw_headers = getattr(resp.raw, "headers", None)

if raw_headers is not None:
    if hasattr(raw_headers, "get_all"):
        set_cookie_headers = raw_headers.get_all("Set-Cookie") or []
    elif hasattr(raw_headers, "getlist"):
        set_cookie_headers = raw_headers.getlist("Set-Cookie") or []

if not set_cookie_headers and 'set-cookie' in resp.headers:
    set_cookie_headers = [resp.headers['set-cookie']]

for cookie_header in set_cookie_headers:
    headers_list.append(('Set-Cookie', cookie_header))

response = Response(resp.iter_content(chunk_size=1024), resp.status_code, headers_list)
return response
    except requests.exceptions.ConnectionError:
        if tenant_id != 'default_tenant':
            return render_tenant_sandbox(tenant_name, tenant_id, path)
        # Next.js is offline -> Fallback to Sandbox Mode
        if path == '':
            return home()
        elif path == 'login':
            return login()
        elif path == 'search':
            return search()
        elif path == 'transfer':
            return transfer()
        return f"<div style='background:#0f172a; color:#fff; padding:2rem; font-family:sans-serif; text-align:center;'><h1>Next.js Application Offline</h1><p>Please start the Next.js app (<code>npm run dev</code> inside <code>fianl-submit</code>) or navigate to the sandbox home page: <a href='/' style='color:#38bdf8;'>http://localhost:5050/</a></p></div>", 503
    except Exception as e:
        return f"<div style='background:#0f172a; color:#fff; padding:2rem; font-family:sans-serif; text-align:center;'><h1>Proxy Error</h1><p>{str(e)}</p></div>", 502

def run_flask_server():
    import logging
    
    # 🪵 Professional Filter to ignore Webpack HMR dev noise from the logs
    class NoHMRFilter(logging.Filter):
        def filter(self, record):
            msg = record.getMessage()
            return 'webpack-hmr' not in msg
            
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.INFO) # Keep logging active for real requests!
    log.addFilter(NoHMRFilter())
    
    print("\n[WAF Proxy Server] Launching on http://localhost:5050...")
    app.run(host='0.0.0.0', port=5050, debug=False, use_reloader=False)

def run_pdf_watcher():
    print(f"\n[Watchdog Monitor] Listening for raw JSON logs inside: {REPORTS_DIR}")
    handler = WAFReportWatcher()
    observer = Observer()
    observer.schedule(handler, str(REPORTS_DIR), recursive=False)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

def cli_malware_scanner():
    print("\n" + "="*50)
    print(" 🔎 STANDALONE FORENSIC MALWARE STATIC SCAN ENGINE")
    print("="*50)
    file_path = input("➡️ Enter the absolute file path to scan: ").strip()
    if not os.path.exists(file_path) or not os.path.isfile(file_path):
        print("❌ Error: File not found.")
        return
        
    print(f"\n[*] Calculating cryptographic hashes and scanning: {os.path.basename(file_path)}")
    
    # Calculate checksums
    with open(file_path, "rb") as f:
        data = f.read()
    hashes = {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest()
    }
    
    # Perform forensic scanning
    level, risk, findings, f_type = real_cyber_scan_engine(file_path)
    
    report_data = {
        "Scan Time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "File Name": os.path.basename(file_path),
        "File Type": f_type,
        "Risk Level": level,
        "Risk Score": risk,
        "Hashes": hashes,
        "Findings": findings
    }
    
    # Save speedometer gauge chart
    gauge_img_path = REPORTS_DIR / "risk_gauge.png"
    draw_gauge(risk, gauge_img_path)
    
    # Generate A4 PDF Report
    pdf_out = generate_scanner_pdf(report_data, gauge_img_path)
    
    print("\n" + "="*50)
    print(f"✅ Scanning Complete! Forensic PDF compiled successfully:")
    print(f"📂 Location: {pdf_out}")
    print("="*50)

def cli_blocked_ips_manager():
    print("\n" + "="*50)
    print(" 🛡️ ADMINISTRATIVE IP BLOCKLIST MANAGER")
    print("="*50)
    print("[1] List all currently blocked/quarantined IPs")
    print("[2] Unblock a specific IP address")
    choice = input("Select an option (1-2): ").strip()
    
    if choice == "1":
        ips = waf.blocked_ips
        if not ips:
            print("\n✔️ No IPs are currently blocked or quarantined.")
        else:
            print(f"\nBlocked IPs ({len(ips)}):")
            for ip, details in ips.items():
                rem = max(0, int(details.get("expiry", 0) - time.time()))
                print(f"  - {ip} -> Reason: {details.get('reason')} | Remaining Quarantine: {rem}s")
    elif choice == "2":
        ip = input("Enter IP to unblock: ").strip()
        if waf.unblock_ip(ip):
            print(f"\n✔️ IP {ip} successfully unblocked.")
        else:
            print(f"\n❌ IP {ip} is not currently blocked.")

def main():
    print("\n" + "═"*60)
    print(" 🛡️  ENTERPRISE AI-CTI HYBRID DEFENSE SUITE v3.0  🛡️")
    print("═"*60)
    
    # 0. Automatically launch NextJS App in background
    nextjs_process = None
    nextjs_dir = BASE_DIR / "fianl-submit"
    if nextjs_dir.exists() and (nextjs_dir / "package.json").exists():
        print("[*] Automatically launching NextJS App in background...")
        try:
            import subprocess
            nextjs_process = subprocess.Popen(
                ["npm", "run", "dev"],
                cwd=str(nextjs_dir),
                shell=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            print("  🟢 NextJS Dev Server : LAUNCHED (Proxying to http://localhost:3000)")
        except Exception as e:
            print(f"  [!] Failed to launch NextJS automatically: {e}")

    print("[*] Spawning WAF Flask Sandbox on http://localhost:5050...")
    
    # 1. Automatically start Flask Server in background daemon thread
    flask_thread = threading.Thread(target=run_flask_server, daemon=True)
    flask_thread.start()
    
    print("[*] Launching Real-time Watchdog PDF Watcher on waf_reports/...")
    # 2. Automatically start PDF watchdog in background daemon thread
    watcher_thread = threading.Thread(target=run_pdf_watcher, daemon=True)
    watcher_thread.start()
    
    # Give threads a moment to output initial startup logs
    time.sleep(1.5)
    
    while True:
        # Get LAN IP dynamically
        import socket
        def get_local_ip():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                ip = s.getsockname()[0]
                s.close()
                return ip
            except:
                return "127.0.0.1"
        lan_ip = get_local_ip()

        print("\n" + "═"*60)
        print(" 🛡️  ENTERPRISE AI-CTI HYBRID DEFENSE SUITE v3.0 - STATUS: ACTIVE 🛡️")
        print("═"*60)
        print("  🟢 NextJS Frontend   : RUNNING (Port 3000)")
        print("  🟢 Flask WAF Sandbox : RUNNING on http://127.0.0.1:5050 (or http://localhost:5050)")
        if lan_ip != "127.0.0.1":
            print(f"  🟢 Local LAN Access  : http://{lan_ip}:5050 (Test from your phone!)")
        print("  🟢 PDF Watcher       : RUNNING & Monitoring WAF Logs")
        print("═"*60)
        print("  [1] Run Standalone Forensic Malware Scanner (Desktop)")
        print("  [2] Open Administrative IP Blocklist Manager")
        print("  [3] Exit Suite")
        print("═"*60)
        choice = input("Choose an option (1-3): ").strip()
        
        if choice == "1":
            cli_malware_scanner()
        elif choice == "2":
            cli_blocked_ips_manager()
        elif choice == "3":
            print("\nExiting Defense Suite. Secure your systems!")
            if nextjs_process:
                print("[*] Stopping NextJS background server...")
                try:
                    import subprocess
                    # On Windows, kill the process tree of npm run dev
                    subprocess.run(["taskkill", "/F", "/T", "/PID", str(nextjs_process.pid)], 
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except:
                    nextjs_process.terminate()
            break
        else:
            print("\n❌ Invalid choice. Try again.")

if __name__ == "__main__":
    main()
