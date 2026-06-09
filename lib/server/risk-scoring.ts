import type { Finding, Severity } from '@/lib/mock-data'
import type { ReportSummaryResult } from '@/lib/server/summarization'
import type { StoredFinding, StoredReport } from '@/lib/server/types'

export type RiskBand = 'Low' | 'Medium' | 'High' | 'Critical'

export type RiskFactorBreakdown = {
  severity: number
  status: number
  cvePresence: number
  exploitability: number
  exposure: number
  assetCriticality: number
  confidence: number
  mitigationPenalty: number
}

export type FindingRiskResult = {
  findingId: string
  reportId: string
  title: string
  asset: string
  cve: string
  severity: Severity
  originalScore: number
  riskScore: number
  riskBand: RiskBand
  rationale: string[]
  factors: RiskFactorBreakdown

  /** Phase 3 threat-aware fields. Optional for backward compatibility with older callers. */
  reportCvss?: number | null
  reportCvssVector?: string | null
  intelCvss?: number | null
  intelCvssSeverity?: string | null
  intelCvssVector?: string | null
  knownExploited?: boolean
  cisaKev?: boolean
  mispMatches?: number
  exploitAvailable?: boolean
  attackVector?: string | null
  finalRiskScore?: number
  riskFactors?: string[]
  recommendations?: string[]
  recommendationSources?: string[]
  riskModelVersion?: string
}

export type ReportRiskResult = {
  reportId: string
  reportName: string
  generatedAtIso: string
  overallRiskScore: number
  overallRiskBand: RiskBand
  rationale: string[]
  stats: {
    totalFindings: number
    criticalFindings: number
    highFindings: number
    mediumFindings: number
    lowFindings: number
    openFindings: number
    findingsWithCve: number
    distinctAssets: number
    knownExploitedFindings?: number
  }
  topRiskFindings: FindingRiskResult[]
  allFindings: FindingRiskResult[]
}

type RiskScoringOptions = {
  maxTopFindings?: number
}

const DEFAULT_OPTIONS: Required<RiskScoringOptions> = {
  maxTopFindings: 5,
}

const severityBase: Record<Severity, number> = {
  Critical: 44,
  High: 30,
  Medium: 16,
  Low: 5,
}

function clamp(min: number, max: number, value: number): number {
  return Math.max(min, Math.min(max, value))
}

function normalizeText(value: string | null | undefined): string {
  return String(value ?? '')
    .replace(/\s+/g, ' ')
    .trim()
}

function isRealCve(value: string): boolean {
  return /^CVE-\d{4}-\d{4,}$/i.test(normalizeText(value))
}

function containsOne(text: string, patterns: RegExp[]): boolean {
  return patterns.some((pattern) => pattern.test(text))
}

function toRiskBand(score: number): RiskBand {
  if (score >= 90) return 'Critical'
  if (score >= 70) return 'High'
  if (score >= 40) return 'Medium'
  return 'Low'
}

function compareSeverity(a: Severity, b: Severity): number {
  return (
    ({ Critical: 4, High: 3, Medium: 2, Low: 1 }[b] ?? 0) -
    ({ Critical: 4, High: 3, Medium: 2, Low: 1 }[a] ?? 0)
  )
}

function scoreStatus(status: Finding['status']): number {
  switch (status) {
    case 'Open':
      return 10
    case 'In Review':
      return 4
    case 'Resolved':
      return -15
    default:
      return 0
  }
}

function scoreCvePresence(cve: string): number {
  return isRealCve(cve) ? 6 : 0
}

function scoreExploitability(
  finding: Pick<StoredFinding, 'title' | 'summary' | 'impact' | 'evidence'>
): number {
  const text = [
    normalizeText(finding.title),
    normalizeText(finding.summary),
    normalizeText(finding.impact),
    normalizeText(finding.evidence),
  ]
    .join(' ')
    .toLowerCase()

  if (
    containsOne(text, [
      /remote code execution/,
      /\brce\b/,
      /sql injection/,
      /authentication bypass/,
      /privilege escalation/,
      /command injection/,
      /admin takeover/,
      /full compromise/,
    ])
  ) {
    return 12
  }

  if (
    containsOne(text, [
      /outdated/,
      /known vulnerabilities/,
      /public exposure/,
      /sensitive data exposure/,
      /weak credentials/,
      /brute-force/,
      /credential stuffing/,
      /misconfig/,
      /public bucket/,
      /exposed/,
      /missing mfa/,
      /anonymous access/,
    ])
  ) {
    return 6
  }

  if (
    containsOne(text, [
      /verbose error/,
      /information disclosure/,
      /banner disclosure/,
      /weak policy/,
      /configuration/,
      /outbound communication/,
      /suspicious communication/,
    ])
  ) {
    return 2
  }

  return 1
}

function scoreExposure(
  finding: Pick<StoredFinding, 'asset' | 'title' | 'summary' | 'impact'>
): number {
  const text = [
    normalizeText(finding.asset),
    normalizeText(finding.title),
    normalizeText(finding.summary),
    normalizeText(finding.impact),
  ]
    .join(' ')
    .toLowerCase()

  if (
    containsOne(text, [
      /public/,
      /internet/,
      /external/,
      /web/,
      /portal/,
      /gateway/,
      /vpn/,
      /auth\./,
      /admin\./,
      /api\./,
    ])
  ) {
    return 8
  }

  if (
    containsOne(text, [
      /internal/,
      /intranet/,
      /role/,
      /access control/,
      /privileged workflow/,
      /admin/,
    ])
  ) {
    return 4
  }

  return 1
}

function scoreAssetCriticality(asset: string): number {
  const text = normalizeText(asset).toLowerCase()

  if (
    containsOne(text, [
      /admin/,
      /auth/,
      /gateway/,
      /vpn/,
      /payment/,
      /prod/,
      /production/,
      /identity/,
      /sso/,
      /storage/,
      /db/,
      /database/,
    ])
  ) {
    return 8
  }

  if (
    containsOne(text, [
      /portal/,
      /api/,
      /web/,
      /server/,
      /app/,
    ])
  ) {
    return 5
  }

  return 2
}

function scoreConfidence(originalScore: number): number {
  if (originalScore >= 90) return 6
  if (originalScore >= 75) return 4
  if (originalScore >= 60) return 3
  if (originalScore >= 45) return 2
  return 1
}

function scoreMitigationPenalty(remediation: string): number {
  const text = normalizeText(remediation).toLowerCase()

  if (!text) return 0

  if (
    containsOne(text, [
      /upgrade/,
      /patch/,
      /restrict/,
      /enforce/,
      /disable/,
      /validate/,
      /review/,
      /retest/,
      /rotate/,
      /remove exposure/,
      /remove public permissions/,
    ])
  ) {
    return -6
  }

  return -3
}

function applySeverityCap(
  finding: StoredFinding,
  rawScore: number,
  factors: RiskFactorBreakdown
): number {
  switch (finding.severity) {
    case 'Critical':
      return clamp(0, 100, rawScore)

    case 'High': {
      const cap =
        finding.status === 'Open' &&
        (isRealCve(finding.cve) || factors.exposure >= 8)
          ? 95
          : 90

      return clamp(0, cap, rawScore)
    }

    case 'Medium': {
      const cap =
        finding.status === 'Open' &&
        isRealCve(finding.cve) &&
        factors.exposure >= 8
          ? 84
          : 78

      return clamp(0, cap, rawScore)
    }

    case 'Low':
      return clamp(0, 55, rawScore)

    default:
      return clamp(0, 100, rawScore)
  }
}

function buildRationale(params: {
  severity: Severity
  status: Finding['status']
  cve: string
  exploitabilityScore: number
  exposureScore: number
  assetCriticalityScore: number
  mitigationPenalty: number
  riskBand: RiskBand
}): string[] {
  const lines: string[] = []

  lines.push(`Severity is ${params.severity}.`)
  lines.push(`Current workflow status is ${params.status}.`)
  lines.push(`Calibrated risk band is ${params.riskBand}.`)

  if (isRealCve(params.cve)) {
    lines.push(`Public CVE reference detected: ${params.cve}.`)
  }

  if (params.exploitabilityScore >= 10) {
    lines.push('Exploitability indicators are strong and increase urgency.')
  } else if (params.exploitabilityScore >= 6) {
    lines.push('Exploitability indicators are moderate.')
  }

  if (params.exposureScore >= 8) {
    lines.push('The affected asset appears externally exposed or internet-facing.')
  } else if (params.exposureScore >= 4) {
    lines.push('The affected asset appears operationally important or reachable within privileged workflows.')
  }

  if (params.assetCriticalityScore >= 8) {
    lines.push('The asset looks security-sensitive or business-critical.')
  } else if (params.assetCriticalityScore >= 5) {
    lines.push('The asset appears operationally important.')
  }

  if (params.mitigationPenalty <= -5) {
    lines.push('A strong remediation path already exists, which reduces net risk slightly.')
  } else if (params.mitigationPenalty < 0) {
    lines.push('A remediation path already exists, which slightly reduces net risk.')
  }

  return lines
}

export function scoreFindingRisk(finding: StoredFinding): FindingRiskResult {
  const remediationText = finding.reported?.remediation || finding.remediation
  const summaryText = finding.reported?.summary || finding.summary
  const impactText = finding.reported?.impact || finding.impact
  const evidenceText = finding.reported?.evidence || finding.evidence

  const factors: RiskFactorBreakdown = {
    severity: severityBase[finding.severity],
    status: scoreStatus(finding.status),
    cvePresence: scoreCvePresence(finding.cve),
    exploitability: scoreExploitability({
      ...finding,
      summary: summaryText,
      impact: impactText,
      evidence: evidenceText,
    }),
    exposure: scoreExposure({
      ...finding,
      summary: summaryText,
      impact: impactText,
    }),
    assetCriticality: scoreAssetCriticality(finding.asset),
    confidence: scoreConfidence(finding.score),
    mitigationPenalty: scoreMitigationPenalty(remediationText),
  }

  const rawScore =
    factors.severity +
    factors.status +
    factors.cvePresence +
    factors.exploitability +
    factors.exposure +
    factors.assetCriticality +
    factors.confidence +
    factors.mitigationPenalty

  const riskScore = applySeverityCap(finding, rawScore, factors)
  const riskBand = toRiskBand(riskScore)

  return {
    findingId: finding.id,
    reportId: finding.reportId,
    title: normalizeText(finding.title),
    asset: normalizeText(finding.asset) || 'unknown-asset',
    cve: normalizeText(finding.cve),
    severity: finding.severity,
    originalScore: finding.score,
    riskScore,
    riskBand,
    rationale: buildRationale({
      severity: finding.severity,
      status: finding.status,
      cve: finding.cve,
      exploitabilityScore: factors.exploitability,
      exposureScore: factors.exposure,
      assetCriticalityScore: factors.assetCriticality,
      mitigationPenalty: factors.mitigationPenalty,
      riskBand,
    }),
    factors,
  }
}

function average(values: number[]): number {
  if (values.length === 0) return 0
  return Math.round(values.reduce((sum, value) => sum + value, 0) / values.length)
}

function buildReportRationale(params: {
  overallRiskBand: RiskBand
  criticalFindings: number
  highFindings: number
  openFindings: number
  findingsWithCve: number
  distinctAssets: number
  topRiskFindings: FindingRiskResult[]
  summary?: ReportSummaryResult
}): string[] {
  const lines: string[] = []

  lines.push(`Overall report risk is classified as ${params.overallRiskBand}.`)

  if (params.criticalFindings > 0) {
    lines.push(`There are ${params.criticalFindings} Critical-severity findings in the report.`)
  }

  if (params.highFindings > 0) {
    lines.push(`There are ${params.highFindings} High-severity findings materially contributing to risk.`)
  }

  if (params.openFindings > 0) {
    lines.push(`There are ${params.openFindings} open findings that still require remediation.`)
  }

  if (params.findingsWithCve > 0) {
    lines.push(`The report includes ${params.findingsWithCve} finding(s) linked to public CVEs.`)
  }

  if (params.distinctAssets > 1) {
    lines.push(`Risk is distributed across ${params.distinctAssets} distinct assets.`)
  }

  const topTitles = params.topRiskFindings.slice(0, 2).map((item) => item.title)
  if (topTitles.length > 0) {
    lines.push(`Top priority issues include ${topTitles.map((item) => `"${item}"`).join(' and ')}.`)
  }

  if (params.summary && params.summary.confidence >= 85) {
    lines.push(
      `Summary confidence is ${params.summary.confidence}%, which supports stronger prioritization confidence.`
    )
  }

  return lines
}

export function scoreReportRisk(
  report: Pick<StoredReport, 'id' | 'name'>,
  findings: StoredFinding[],
  summary?: ReportSummaryResult,
  options?: RiskScoringOptions
): ReportRiskResult {
  const config = { ...DEFAULT_OPTIONS, ...options }

  const scoredFindings = findings
    .map(scoreFindingRisk)
    .sort((a, b) => b.riskScore - a.riskScore)

  const criticalFindings = scoredFindings.filter((item) => item.severity === 'Critical').length
  const highFindings = scoredFindings.filter((item) => item.severity === 'High').length
  const mediumFindings = scoredFindings.filter((item) => item.severity === 'Medium').length
  const lowFindings = scoredFindings.filter((item) => item.severity === 'Low').length
  const openFindings = findings.filter((item) => item.status === 'Open').length
  const findingsWithCve = findings.filter((item) => isRealCve(item.cve)).length
  const distinctAssets = new Set(
    findings.map((item) => normalizeText(item.asset) || 'unknown-asset')
  ).size

  const averageFindingRisk = average(scoredFindings.map((item) => item.riskScore))
  const highestFindingRisk = scoredFindings[0]?.riskScore ?? 0

  let overallRaw =
    Math.round(averageFindingRisk * 0.7 + highestFindingRisk * 0.3) +
    criticalFindings * 2 +
    highFindings * 1 +
    Math.min(openFindings, 3) +
    Math.min(findingsWithCve, 2)

  if (summary) {
    if (summary.confidence >= 90) overallRaw += 1
    if (summary.severityOverview.Critical > 0) overallRaw += 2
    if (summary.severityOverview.High >= 2) overallRaw += 1
    if (summary.grounding.averageFieldCoverage >= 95) overallRaw += 1
  }

  const overallRiskScore = clamp(0, 100, overallRaw)
  const overallRiskBand = toRiskBand(overallRiskScore)
  const topRiskFindings = scoredFindings.slice(0, config.maxTopFindings)

  return {
    reportId: report.id,
    reportName: report.name,
    generatedAtIso: new Date().toISOString(),
    overallRiskScore,
    overallRiskBand,
    rationale: buildReportRationale({
      overallRiskBand,
      criticalFindings,
      highFindings,
      openFindings,
      findingsWithCve,
      distinctAssets,
      topRiskFindings,
      summary,
    }),
    stats: {
      totalFindings: findings.length,
      criticalFindings,
      highFindings,
      mediumFindings,
      lowFindings,
      openFindings,
      findingsWithCve,
      distinctAssets,
    },
    topRiskFindings,
    allFindings: scoredFindings,
  }
}

export function rankFindingsByRisk(findings: StoredFinding[]): FindingRiskResult[] {
  return findings
    .map(scoreFindingRisk)
    .sort((a, b) => {
      if (b.riskScore !== a.riskScore) return b.riskScore - a.riskScore
      return compareSeverity(a.severity, b.severity)
    })
}