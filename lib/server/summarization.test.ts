import { describe, expect, it } from 'vitest'
import { generateReportSummary } from './ai-summarization'
import { analyzeContent } from './analysis-engine'
import { summarizeReport } from './summarization'

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
`

function buildBenchmark() {
  const { report, findings } = analyzeContent({
    reportId: 'R-TEST',
    reportName: 'Analyzed Report',
    uploadedAt: '2026-04-17',
    input: BENCHMARK_REPORT,
    sourceType: 'TXT',
  })

  return { report, findings }
}

describe('summarization core', () => {
  it('builds correct summary stats from benchmark findings', () => {
    const { report, findings } = buildBenchmark()
    const result = summarizeReport(report, findings)

    expect(result.stats.totalFindings).toBe(6)
    expect(result.stats.criticalCount).toBe(1)
    expect(result.stats.highCount).toBe(2)
    expect(result.stats.mediumCount).toBe(2)
    expect(result.stats.lowCount).toBe(1)
    expect(result.stats.openCount).toBe(4)
    expect(result.stats.resolvedCount).toBe(1)
    expect(result.stats.distinctAssets).toBe(6)
  })

  it('builds grounded stats with full coverage for the benchmark report', () => {
    const { report, findings } = buildBenchmark()
    const result = summarizeReport(report, findings)

    expect(result.grounding.findingsWithSummary).toBe(6)
    expect(result.grounding.findingsWithImpact).toBe(6)
    expect(result.grounding.findingsWithEvidence).toBe(6)
    expect(result.grounding.findingsWithRemediation).toBe(6)
    expect(result.grounding.fullyGroundedFindings).toBe(6)
    expect(result.grounding.partiallyGroundedFindings).toBe(0)
    expect(result.grounding.averageFieldCoverage).toBe(100)
  })

 it('orders top risks sensibly', () => {
  const { report, findings } = buildBenchmark()
  const result = summarizeReport(report, findings)

  expect(result.topRisks[0].title).toBe('Missing MFA for Privileged Access')
  expect(result.topRisks[1].title).toBe(
    'Outdated Apache Server With Public CVE Exposure'
  )
  expect(result.topRisks[0].severity).toBe('Critical')
  expect(result.topRisks[1].reason).toContain('linked CVE (CVE-2023-25690)')
})

  it('builds affected assets without drift', () => {
    const { report, findings } = buildBenchmark()
    const result = summarizeReport(report, findings)

    expect(result.affectedAssets).toHaveLength(6)
    expect(result.affectedAssets.map((item) => item.asset)).toEqual([
      'admin.acme.local',
      'web-gateway-02.acme.local',
      'storage.acme.local',
      'vpn.acme.local',
      'app.acme.local',
      'portal.acme.local',
    ])
  })

  it('keeps recommendations grounded in real remediation content', () => {
    const { report, findings } = buildBenchmark()
    const result = summarizeReport(report, findings)

    expect(
      result.recommendations.some((item) =>
        item.includes('Enforce MFA for all privileged and administrative accounts')
      )
    ).toBe(true)

    expect(
      result.recommendations.some((item) =>
        item.includes('Upgrade Apache to a supported and fully patched version')
      )
    ).toBe(true)

    expect(
      result.recommendations.some((item) =>
        item.includes('Review application egress policies')
      )
    ).toBe(true)

    expect(result.recommendations.join(' ')).not.toContain('OVERALL IMPACT')
    expect(result.recommendations.join(' ')).not.toContain('RECOMMENDED ACTION PLAN')
  })
})

describe('ai summarization wrapper', () => {
 it('returns grounded executive and narrative summaries', async () => {
  const { report, findings } = buildBenchmark()
  const result = await generateReportSummary(report, findings)

  expect(result.executiveSummary).toContain('urgent risk')
  expect(result.executiveSummary).toContain('6 findings')
  expect(result.narrativeSummary).toContain('Highest-priority risks currently include')
  expect(result.narrativeSummary).toContain('Risk concentration is highest around')
  expect(result.grounding.averageFieldCoverage).toBe(100)
})
  it('preserves or improves confidence without breaking stats', async () => {
    const { report, findings } = buildBenchmark()

    const base = summarizeReport(report, findings)
    const wrapped = await generateReportSummary(report, findings)

    expect(wrapped.stats.totalFindings).toBe(base.stats.totalFindings)
    expect(wrapped.severityOverview).toEqual(base.severityOverview)
    expect(wrapped.grounding.averageFieldCoverage).toBe(100)
    expect(wrapped.confidence).toBeGreaterThanOrEqual(base.confidence)
  })

  it('keeps the summary focused on the benchmark findings', async () => {
    const { report, findings } = buildBenchmark()
    const result = await generateReportSummary(report, findings)

    expect(result.executiveSummary).toContain('admin.acme.local')
    expect(result.executiveSummary).toContain('web-gateway-02.acme.local')
    expect(result.executiveSummary).not.toContain('RECOMMENDED ACTION PLAN')
    expect(result.narrativeSummary).not.toContain('OVERALL IMPACT')
  })
})