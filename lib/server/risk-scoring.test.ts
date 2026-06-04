import { describe, expect, it } from 'vitest'
import { generateReportRisk } from './ai-risk-scoring'
import { generateReportSummary } from './ai-summarization'
import { analyzeContent } from './analysis-engine'
import {
    scoreFindingRisk,
    scoreReportRisk,
} from './risk-scoring'

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
    reportId: 'R-RISK',
    reportName: 'Analyzed Report',
    uploadedAt: '2026-04-17',
    input: BENCHMARK_REPORT,
    sourceType: 'TXT',
  })

  const reportForRisk = {
    ...report,
    content: BENCHMARK_REPORT,
    summary: report.summary,
  }

  return { report, reportForRisk, findings }
}

describe('risk scoring core', () => {
  it('scores the low-severity portal issue as low risk', () => {
    const { findings } = buildBenchmark()
    const portalFinding = findings.find(
      (item) => item.title === 'Verbose Error Disclosure in Portal'
    )

    expect(portalFinding).toBeDefined()

    const result = scoreFindingRisk(portalFinding!)
    expect(result.severity).toBe('Low')
    expect(result.riskBand).toBe('Low')
    expect(result.riskScore).toBeLessThan(40)
  })

  it('does not over-escalate medium findings to critical in the core model', () => {
    const { findings } = buildBenchmark()
    const scored = findings.map(scoreFindingRisk)

    const mediumFindings = scored.filter((item) => item.severity === 'Medium')
    expect(mediumFindings.length).toBeGreaterThan(0)

    for (const item of mediumFindings) {
      expect(item.riskBand).not.toBe('Critical')
      expect(item.riskScore).toBeLessThan(90)
    }
  })

  it('keeps the CVE-backed Apache finding above the storage finding in the core ranking', () => {
    const { report, reportForRisk, findings } = buildBenchmark()
    const summaryLike = undefined
    const result = scoreReportRisk(report, findings, summaryLike)

    const apache = result.allFindings.find((item) =>
      item.title.includes('Outdated Apache Server With Public CVE Exposure')
    )
    const storage = result.allFindings.find((item) =>
      item.title.includes('Public Storage Exposure')
    )

    expect(apache).toBeDefined()
    expect(storage).toBeDefined()
    expect(apache!.riskScore).toBeGreaterThan(storage!.riskScore)
  })
})

describe('ai risk scoring wrapper', () => {
  it('returns a calibrated overall report risk', async () => {
    const { report, reportForRisk, findings } = buildBenchmark()
    const summary = await generateReportSummary(report, findings)
    const risk = await generateReportRisk(reportForRisk, findings, summary)

    expect(risk.overallRiskScore).toBeGreaterThanOrEqual(60)
    expect(risk.overallRiskScore).toBeLessThan(75)
    expect(risk.overallRiskBand).toBe('Medium')
  })

  it('keeps only one finding in the critical-risk band after calibration', async () => {
    const { report, reportForRisk, findings } = buildBenchmark()
    const summary = await generateReportSummary(report, findings)
    const risk = await generateReportRisk(reportForRisk, findings, summary)

    const criticalRiskFindings = risk.allFindings.filter(
      (item) => item.riskBand === 'Critical'
    )

    expect(criticalRiskFindings).toHaveLength(1)
    expect(criticalRiskFindings[0].title).toBe('Missing MFA for Privileged Access')
    expect(criticalRiskFindings[0].riskScore).toBeGreaterThanOrEqual(90)
  })

  it('keeps the apache CVE finding as high risk rather than critical', async () => {
    const { report, reportForRisk, findings } = buildBenchmark()
    const summary = await generateReportSummary(report, findings)
    const risk = await generateReportRisk(reportForRisk, findings, summary)

    const apache = risk.allFindings.find((item) =>
      item.title.includes('Outdated Apache Server With Public CVE Exposure')
    )

    expect(apache).toBeDefined()
    expect(apache!.riskBand).toBe('High')
    expect(apache!.riskScore).toBeGreaterThanOrEqual(70)
    expect(apache!.riskScore).toBeLessThan(90)
  })

  it('keeps rationale text in sync with the final calibrated band', async () => {
    const { report, reportForRisk, findings } = buildBenchmark()
    const summary = await generateReportSummary(report, findings)
    const risk = await generateReportRisk(reportForRisk, findings, summary)

    for (const item of risk.allFindings) {
      expect(item.rationale.join(' ')).toContain(
        `Calibrated risk band is ${item.riskBand}.`
      )
    }
  })

  it('keeps the low portal issue in the low band after wrapper adjustments', async () => {
    const { report, reportForRisk, findings } = buildBenchmark()
    const summary = await generateReportSummary(report, findings)
    const risk = await generateReportRisk(reportForRisk, findings, summary)

    const portal = risk.allFindings.find((item) =>
      item.title.includes('Verbose Error Disclosure in Portal')
    )

    expect(portal).toBeDefined()
    expect(portal!.riskBand).toBe('Low')
    expect(portal!.riskScore).toBeLessThan(40)
  })
})