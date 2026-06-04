import { describe, expect, it } from 'vitest'
import {
  extractDomains,
  extractEmails,
  extractHashes,
  extractIps,
  extractUrls,
  normalizeText,
  runPipeline,
  segmentReport,
} from './pipeline'
import { parseStructuredFindings } from './server/report-parser'

const BENCHMARK_REPORT = `
INTERNAL AND EXTERNAL SECURITY ASSESSMENT REPORT
Client: ACME Manufacturing
Assessment Window: 2026-04-12 to 2026-04-15
Prepared By: Red Team Operations

EXECUTIVE SUMMARY

The assessment identified multiple security weaknesses across internet-facing and internal assets. The most severe issues include missing MFA on privileged access, outdated software with public vulnerability exposure, and public cloud storage exposure. Additional weaknesses in password policy, verbose application errors, and suspicious outbound communication increase the likelihood of compromise, lateral movement, and data exposure.

Overall risk is considered HIGH because several findings affect externally reachable systems and privileged workflows. Immediate remediation should focus on access control hardening, patch management, and reduction of public exposure.

SCOPE

Assets assessed:
- admin.acme.local
- portal.acme.local
- vpn.acme.local
- web-gateway-02.acme.local
- storage.acme.local
- app.acme.local

Methodology:
- External attack surface review
- AuthN / AuthZ testing
- Configuration review
- Service fingerprinting
- Cloud exposure validation
- Controlled exploitation and evidence capture

FINDING 1: Missing MFA for Privileged Access
Severity: Critical
Affected Asset: admin.acme.local
Status: Open

Summary:
Administrative access to the internal management portal does not require multi-factor authentication. A valid username and password may be sufficient to access privileged workflows.

Impact:
An attacker with reused, phished, or exposed credentials could gain administrative access and perform sensitive actions without an additional verification factor.

Evidence:
Testing confirmed that the admin portal accepted valid credentials for privileged users without prompting for MFA. A valid username and password may be sufficient to access privileged workflows.

Remediation:
Enforce MFA for all privileged and administrative accounts. Review conditional access policies and verify that MFA cannot be bypassed for trusted locations or legacy login flows.

FINDING 2: Outdated Apache Server With Public CVE Exposure
Severity: High
Affected Asset: web-gateway-02.acme.local
Status: Open
Reference: CVE-2023-25690

Summary:
The external gateway is running an outdated Apache version with publicly documented security advisories. The observed version is no longer aligned with current patch guidance.

Impact:
Known vulnerabilities in outdated software increase exploitation likelihood on an internet-facing system and may allow attacker access, service abuse, or follow-on compromise.

Evidence:
Service fingerprinting and package validation confirmed an outdated Apache deployment on web-gateway-02.acme.local. Public references include CVE-2023-25690.

Remediation:
Upgrade Apache to a supported and fully patched version. Validate module compatibility and retest externally exposed routes after patching.

FINDING 3: Public Storage Exposure
Severity: High
Affected Asset: storage.acme.local
Status: In Review

Summary:
Cloud object storage permissions allow anonymous access to internal files and operational artifacts. Public storage exposure was confirmed without authentication.

Impact:
Sensitive internal data, deployment files, and archived documents may be viewed or copied by unauthorized parties. This creates business, compliance, and incident response risk.

Evidence:
Anonymous access tests returned internal documents and deployment artifacts from storage.acme.local. Public bucket behavior was confirmed during validation.

Remediation:
Restrict bucket access policies, remove public permissions, review historical access logs, and rotate any secrets that may have been exposed through stored artifacts.

FINDING 4: Weak Password Policy on VPN Access
Severity: Medium
Affected Asset: vpn.acme.local
Status: Open

Summary:
The VPN password policy allows short and weak passwords and does not enforce adequate complexity controls for remote access accounts.

Impact:
Weak authentication controls increase the likelihood of brute-force attacks, password spraying, and credential stuffing against external access services.

Evidence:
Testing confirmed that short passwords were accepted for remote access accounts. The current password policy does not sufficiently restrict weak credentials.

Remediation:
Increase minimum password length, block common weak passwords, enable adaptive lockout controls, and review whether MFA is enforced for all remote access users.

FINDING 5: Verbose Error Disclosure in Portal
Severity: Low
Affected Asset: portal.acme.local
Status: Resolved

Summary:
The portal reveals stack traces, internal paths, and framework-specific exception details when malformed requests are submitted.

Impact:
Verbose error handling may help attackers fingerprint the technology stack, map internal components, and refine later exploit attempts.

Evidence:
Unhandled exceptions exposed stack traces and internal application paths in HTTP responses from portal.acme.local.

Remediation:
Replace verbose exception output with generic user-safe errors and centralize detailed logs on the server side.

FINDING 6: Suspicious External Communication
Severity: Medium
Affected Asset: app.acme.local
Status: Open

Summary:
The application server initiated outbound communication to an unapproved external host during testing. The behavior is inconsistent with expected business traffic.

Impact:
Unexpected outbound traffic may indicate weak egress controls, unauthorized update mechanisms, or potential staging for command and control communication.

Evidence:
Observed external IP: 185.199.110.153
Observed domain: update-sync-login.net
Observed URL: https://update-sync-login.net/health/check
Observed email indicator: soc-review@acme-security.example
Observed SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

Remediation:
Review application egress policies, validate approved outbound destinations, inspect the process responsible for the traffic, and retain logs for forensic review.

OVERALL IMPACT

If combined, the identified weaknesses could allow an attacker to obtain privileged access, exploit known vulnerabilities on exposed services, access internal storage artifacts, and maintain a foothold through weak identity and monitoring controls. The most urgent remediation priorities are MFA enforcement, patching of outdated internet-facing software, and public exposure reduction.

RECOMMENDED ACTION PLAN

1. Enforce MFA for all privileged and remote access workflows.
2. Patch outdated Apache services associated with CVE-2023-25690.
3. Remove anonymous access from public storage and review exposed artifacts.
4. Strengthen VPN password policy and add rate-limiting and lockout protections.
5. Remove verbose error disclosure from the portal.
6. Investigate suspicious outbound communication and tighten egress controls.
7. Retest all remediated assets to confirm closure of the identified findings.
`

describe('pipeline extractors', () => {
  it('extracts urls correctly', () => {
    const text = 'See https://example.com/path and http://test.org.'
    expect(extractUrls(text, 50)).toEqual([
      'https://example.com/path',
      'http://test.org',
    ])
  })

  it('extracts public ips and ignores invalid ones in strict mode', () => {
    const text = 'IPs: 8.8.8.8 999.1.1.1 192.168.1.10'
    expect(extractIps(text, 60)).toEqual(['8.8.8.8'])
  })

  it('extracts emails correctly', () => {
    const text = 'Contact soc@example.com or ir@test.org'
    expect(extractEmails(text)).toEqual([
      'soc@example.com',
      'ir@test.org',
    ])
  })

  it('extracts domains and ignores denied internal tlds', () => {
    const text = 'Domains: example.com app.test.org internal.local corp.internal'
    expect(extractDomains(text, 50)).toEqual([
      'example.com',
      'app.test.org',
    ])
  })

  it('extracts md5, sha1, and sha256 hashes', () => {
    const text =
      'Hashes: d41d8cd98f00b204e9800998ecf8427e ' +
      'a9993e364706816aba3e25717850c26c9cd0d89d ' +
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'

    expect(extractHashes(text, 50)).toEqual([
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      'a9993e364706816aba3e25717850c26c9cd0d89d',
      'd41d8cd98f00b204e9800998ecf8427e',
    ])
  })
})

describe('pipeline normalization and segmentation', () => {
  it('normalizes whitespace and newlines', () => {
    const input = 'Hello\r\n\r\nWorld\u00A0\u00A0test'
    expect(normalizeText(input)).toBe('Hello\n\nWorld test')
  })

  it('segments headings, bullets, and sentences', () => {
    const normalized = normalizeText(`
EXECUTIVE SUMMARY

This is the first sentence. This is the second sentence.

- Bullet one
- Bullet two
    `)

    const result = segmentReport(normalized)

    expect(result.sectionCount).toBe(3)
    expect(result.segments.map((item) => item.text)).toEqual([
      'EXECUTIVE SUMMARY',
      'This is the first sentence.',
      'This is the second sentence.',
      '- Bullet one',
      '- Bullet two',
    ])
  })
})

describe('runPipeline', () => {
  it('builds a complete pipeline run with stats and indicators', () => {
    const input = `
EXECUTIVE SUMMARY

Analysts observed communication with https://example.com/path and 8.8.8.8.
Contact soc@example.com for response coordination.
    `

    const result = runPipeline(input, 'quick', 60)

    expect(result.version).toBe(1)
    expect(result.mode).toBe('quick')
    expect(result.strictness).toBe(60)
    expect(result.normalized.length).toBeGreaterThan(0)
    expect(result.stats.sectionCount).toBeGreaterThan(0)
    expect(result.stats.sentenceCount).toBeGreaterThan(0)
    expect(result.stats.indicatorCount).toBeGreaterThan(0)

    expect(
      result.indicators.some(
        (item) => item.type === 'URL' && item.value === 'https://example.com/path'
      )
    ).toBe(true)

    expect(
      result.indicators.some(
        (item) => item.type === 'IP' && item.value === '8.8.8.8'
      )
    ).toBe(true)

    expect(
      result.indicators.some(
        (item) => item.type === 'Email' && item.value === 'soc@example.com'
      )
    ).toBe(true)
  })
})

describe('structured report parser regressions', () => {
  it('extracts exactly 6 structured findings from the benchmark report', () => {
    const findings = parseStructuredFindings(BENCHMARK_REPORT)

    expect(findings).toHaveLength(6)
    expect(findings.map((item) => item.title)).toEqual([
      'Missing MFA for Privileged Access',
      'Outdated Apache Server With Public CVE Exposure',
      'Public Storage Exposure',
      'Weak Password Policy on VPN Access',
      'Verbose Error Disclosure in Portal',
      'Suspicious External Communication',
    ])
  })

  it('preserves severity, asset, and status from labeled fields', () => {
    const findings = parseStructuredFindings(BENCHMARK_REPORT)

    expect(findings[0]).toMatchObject({
      severity: 'Critical',
      asset: 'admin.acme.local',
      status: 'Open',
    })

    expect(findings[1]).toMatchObject({
      severity: 'High',
      asset: 'web-gateway-02.acme.local',
      status: 'Open',
      cve: 'CVE-2023-25690',
    })

    expect(findings[2]).toMatchObject({
      severity: 'High',
      asset: 'storage.acme.local',
      status: 'In Review',
    })

    expect(findings[4]).toMatchObject({
      severity: 'Low',
      asset: 'portal.acme.local',
      status: 'Resolved',
    })
  })

  it('does not bleed OVERALL IMPACT or RECOMMENDED ACTION PLAN into the last finding', () => {
    const findings = parseStructuredFindings(BENCHMARK_REPORT)
    const finding6 = findings[5]

    expect(finding6.title).toBe('Suspicious External Communication')
    expect(finding6.cve).toBeUndefined()

    expect(finding6.remediation).toContain(
      'Review application egress policies, validate approved outbound destinations'
    )

    expect(finding6.remediation).not.toContain('OVERALL IMPACT')
    expect(finding6.remediation).not.toContain('RECOMMENDED ACTION PLAN')

    expect(finding6.provenance?.sourceText).not.toContain('OVERALL IMPACT')
    expect(finding6.provenance?.sourceText).not.toContain('RECOMMENDED ACTION PLAN')
  })

  it('keeps the suspicious external communication evidence intact', () => {
    const findings = parseStructuredFindings(BENCHMARK_REPORT)
    const finding6 = findings[5]

    expect(finding6.evidence).toContain('185.199.110.153')
    expect(finding6.evidence).toContain('update-sync-login.net')
    expect(finding6.evidence).toContain('soc-review@acme-security.example')
    expect(finding6.evidence).toContain(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    )
  })
})