import { generateFindingRecommendations } from '@/lib/server/recommendations'
import type {
  FindingRiskResult,
  ReportRiskResult,
  RiskBand,
} from '@/lib/server/risk-scoring'
import type { ReportSummaryResult } from '@/lib/server/summarization'
import type { StoredFinding, StoredReport } from '@/lib/server/types'

export type ThreatIntelFindingContext = {
  cveId: string
  cvssScore: number | null
  cvssSeverity: string | null
  cvssVector?: string | null
  knownExploited: boolean
  cisaKev?: boolean
  mispMatches: number
  source?: string
}

export type ThreatIntelInput =
  | null
  | undefined
  | {
      results?: Array<{
        cveId?: string
        cvssScore?: number | null
        cvssSeverity?: string | null
        cvssVector?: string | null
        knownExploited?: boolean
        cisaKev?: boolean
        mispMatches?: number | null
      }>
      cves?: Array<{
        cveId?: string
        cvssScore?: number | null
        cvssSeverity?: string | null
        cvssVector?: string | null
        knownExploited?: boolean
        kev?: unknown
        mispItems?: unknown[]
      }>
    }

export type ThreatAwareRiskOptions = {
  threatIntel?: ThreatIntelInput
  generatedAtIso?: string
}

const MODEL_VERSION = 'risk-scoring-v3-threat-aware-deterministic'

function normalizeText(value: string | null | undefined): string {
  return String(value ?? '')
    .replace(/\s+/g, ' ')
    .trim()
}

function unique(values: string[]): string[] {
  return Array.from(new Set(values.map(normalizeText).filter(Boolean)))
}

function clamp(min: number, max: number, value: number): number {
  return Math.max(min, Math.min(max, value))
}

function toRiskBand(score: number): RiskBand {
  if (score >= 90) return 'Critical'
  if (score >= 70) return 'High'
  if (score >= 40) return 'Medium'
  return 'Low'
}

function isRealCve(value: string | null | undefined): boolean {
  return /^CVE-\d{4}-\d{4,}$/i.test(normalizeText(value))
}

function toNumber(value: unknown): number | null {
  const parsed = Number(value)
  return Number.isFinite(parsed) ? parsed : null
}

function normalizeCve(value: string | null | undefined): string {
  const match = normalizeText(value).match(/\bCVE-\d{4}-\d{4,}\b/i)
  return match ? match[0].toUpperCase() : ''
}

function buildThreatIntelIndex(input: ThreatIntelInput): Map<string, ThreatIntelFindingContext> {
  const map = new Map<string, ThreatIntelFindingContext>()

  for (const item of input?.results ?? []) {
    const cveId = normalizeCve(item.cveId)
    if (!cveId) continue

    map.set(cveId, {
      cveId,
      cvssScore: toNumber(item.cvssScore),
      cvssSeverity: item.cvssSeverity ?? null,
      cvssVector: item.cvssVector ?? null,
      knownExploited: Boolean(item.knownExploited || item.cisaKev),
      cisaKev: Boolean(item.cisaKev || item.knownExploited),
      mispMatches: Math.max(0, Math.floor(Number(item.mispMatches ?? 0))),
      source: 'post-analysis-threat-intel',
    })
  }

  for (const item of input?.cves ?? []) {
    const cveId = normalizeCve(item.cveId)
    if (!cveId) continue

    const existing = map.get(cveId)
    map.set(cveId, {
      cveId,
      cvssScore: toNumber(item.cvssScore) ?? existing?.cvssScore ?? null,
      cvssSeverity: item.cvssSeverity ?? existing?.cvssSeverity ?? null,
      cvssVector: item.cvssVector ?? existing?.cvssVector ?? null,
      knownExploited: Boolean(item.knownExploited || item.kev || existing?.knownExploited),
      cisaKev: Boolean(item.kev || existing?.cisaKev),
      mispMatches: Math.max(
        existing?.mispMatches ?? 0,
        Array.isArray(item.mispItems) ? item.mispItems.length : 0
      ),
      source: 'neo4j-threat-intel',
    })
  }

  return map
}

function findingText(finding: StoredFinding): string {
  return [
    finding.title,
    finding.cve,
    finding.asset,
    finding.summary,
    finding.impact,
    finding.evidence,
    finding.remediation,
    finding.reported?.summary,
    finding.reported?.impact,
    finding.reported?.evidence,
    finding.reported?.remediation,
    ...(finding.reported?.exploitationSteps ?? []),
  ]
    .map(normalizeText)
    .join(' ')
}

function extractReportCvss(finding: StoredFinding): number | null {
  const text = findingText(finding)
  const patterns = [
    /\bCVSS(?:\s*(?:score|base score))?\s*[:=]?\s*(10(?:\.0)?|[0-9](?:\.[0-9])?)\b/i,
    /\bcvss_scores?\s*[:=]?\s*(10(?:\.0)?|[0-9](?:\.[0-9])?)\b/i,
  ]

  for (const pattern of patterns) {
    const match = text.match(pattern)
    const value = toNumber(match?.[1])
    if (value !== null && value >= 0 && value <= 10) return value
  }

  if (finding.score >= 0 && finding.score <= 100) {
    const approximate = Number((finding.score / 10).toFixed(1))
    if (approximate > 0) return approximate
  }

  return null
}

function extractAttackVector(finding: StoredFinding): string | null {
  const text = findingText(finding)
  const match = text.match(/\bAttack vectors?\s*[:=]?\s*(Network|Adjacent|Local|Physical)\b/i)
  if (match?.[1]) return match[1][0].toUpperCase() + match[1].slice(1).toLowerCase()

  if (/\b(network|remote|internet|public|external|https?|api|upload|login)\b/i.test(text)) {
    return 'Network'
  }

  if (/\blocal\b/i.test(text)) return 'Local'

  return null
}

function hasExploitEvidence(finding: StoredFinding): boolean {
  const text = findingText(finding).toLowerCase()

  return Boolean(
    (finding.reported?.exploitationSteps?.length ?? 0) > 0 ||
      /proof of concept|\bpoc\b|exploitation steps|exploit available|trigger ognl|crafted post request|execute arbitrary operating system commands/.test(text)
  )
}

function hasInternetExposure(finding: StoredFinding): boolean {
  const text = findingText(finding).toLowerCase()
  return /https?:\/\/|\b(api|login|upload|internet|external|public|network|vpn|gateway|portal)\b/.test(text)
}

function impactDelta(finding: StoredFinding): { delta: number; factors: string[] } {
  const text = [finding.title, finding.impact, finding.summary, finding.evidence]
    .map(normalizeText)
    .join(' ')
    .toLowerCase()

  if (/remote code execution|\brce\b|execute arbitrary|system compromise|full control/.test(text)) {
    return { delta: 6, factors: ['Impact indicates remote code execution or potential system compromise.'] }
  }

  if (/denial of service|\bdos\b|service disruption|availability|crash|panic|vpn connection failure|disconnect/.test(text)) {
    return { delta: 3, factors: ['Impact includes service availability or denial-of-service risk.'] }
  }

  if (/authentication bypass|extract sensitive|data exposure|data leakage|privilege escalation|modify database/.test(text)) {
    return { delta: 5, factors: ['Impact includes authentication bypass, sensitive data exposure, or privilege escalation.'] }
  }

  return { delta: 0, factors: [] }
}

function severityBaseScore(severity: StoredFinding['severity']): number {
  switch (severity) {
    case 'Critical':
      return 92
    case 'High':
      return 78
    case 'Medium':
      return 52
    case 'Low':
      return 25
    default:
      return 35
  }
}

function statusDelta(status: StoredFinding['status']): number {
  switch (status) {
    case 'Open':
      return 0
    case 'In Review':
      return -3
    case 'Resolved':
      return -25
    default:
      return 0
  }
}

function baseScoreFromReport(finding: StoredFinding, reportCvss: number | null): number {
  if (reportCvss !== null) return Math.round(reportCvss * 10)
  if (Number.isFinite(finding.score) && finding.score > 0) return clamp(0, 100, finding.score)
  return severityBaseScore(finding.severity)
}

function scoreOneFinding(
  finding: StoredFinding,
  intel: ThreatIntelFindingContext | undefined
): FindingRiskResult {
  const reportCvss = extractReportCvss(finding)
  const intelCvss = intel?.cvssScore ?? null
  const attackVector = extractAttackVector(finding)
  const exploitAvailable = hasExploitEvidence(finding)
  const knownExploited = Boolean(intel?.knownExploited)
  const cisaKev = Boolean(intel?.cisaKev || intel?.knownExploited)
  const mispMatches = intel?.mispMatches ?? 0

  const factors: string[] = []
  let score = baseScoreFromReport(finding, reportCvss)

  factors.push(`Report severity is ${finding.severity}.`)
  if (reportCvss !== null) {
    factors.push(`Report CVSS is ${reportCvss}.`)
  } else {
    factors.push('No report CVSS was extracted, so severity and existing report score were used as the base.')
  }

  if (intelCvss !== null) {
    factors.push(`Threat intelligence CVSS is ${intelCvss}.`)
    if (reportCvss !== null && intelCvss > reportCvss) {
      const delta = Math.min(10, Math.round((intelCvss - reportCvss) * 3))
      score += delta
      if (delta > 0) {
        factors.push('Threat intelligence CVSS is higher than the report CVSS, increasing urgency.')
      }
    } else if (reportCvss === null) {
      score = Math.max(score, Math.round(intelCvss * 10))
    }
  }

  if (knownExploited) {
    score += 10
    factors.push('CISA KEV or threat intelligence confirms known exploitation.')
  }

  if (mispMatches > 0) {
    score += Math.min(5, 1 + mispMatches)
    factors.push(`MISP returned ${mispMatches} matching intelligence item${mispMatches === 1 ? '' : 's'}.`)
  }

  if (exploitAvailable) {
    score += 5
    factors.push('The report contains proof-of-concept or exploitation-step evidence.')
  }

  if (attackVector === 'Network') {
    score += 4
    factors.push('Attack vector is Network.')
  } else if (attackVector) {
    score += 1
    factors.push(`Attack vector is ${attackVector}.`)
  }

  if (hasInternetExposure(finding)) {
    score += 3
    factors.push('The affected component appears remotely reachable or exposed through an application endpoint.')
  }

  const impact = impactDelta(finding)
  score += impact.delta
  factors.push(...impact.factors)

  const statusAdjustment = statusDelta(finding.status)
  if (statusAdjustment !== 0) {
    score += statusAdjustment
    factors.push(`Workflow status is ${finding.status}, adjusting urgency accordingly.`)
  } else {
    factors.push(`Workflow status is ${finding.status}.`)
  }

  const finalRiskScore = clamp(0, 100, Math.round(score))
  const riskBand = toRiskBand(finalRiskScore)
  const recommendationResult = generateFindingRecommendations({
    finding,
    knownExploited,
    attackVector,
    exploitAvailable,
  })

  return {
    findingId: finding.id,
    reportId: finding.reportId,
    title: normalizeText(finding.title),
    asset: normalizeText(finding.asset) || 'unknown-asset',
    cve: normalizeText(finding.cve),
    severity: finding.severity,
    originalScore: finding.score,
    riskScore: finalRiskScore,
    riskBand,
    rationale: unique(factors).slice(0, 10),
    factors: {
      severity: severityBaseScore(finding.severity),
      status: statusAdjustment,
      cvePresence: isRealCve(finding.cve) ? 1 : 0,
      exploitability: exploitAvailable ? 5 : 0,
      exposure: attackVector === 'Network' ? 4 : 0,
      assetCriticality: hasInternetExposure(finding) ? 3 : 0,
      confidence: reportCvss !== null ? 4 : 2,
      mitigationPenalty: finding.status === 'Resolved' ? -25 : 0,
    },
    reportCvss,
    reportCvssVector: null,
    intelCvss,
    intelCvssSeverity: intel?.cvssSeverity ?? null,
    intelCvssVector: intel?.cvssVector ?? null,
    knownExploited,
    cisaKev,
    mispMatches,
    exploitAvailable,
    attackVector,
    finalRiskScore,
    riskFactors: unique(factors).slice(0, 10),
    recommendations: recommendationResult.recommendations,
    recommendationSources: recommendationResult.sources,
    riskModelVersion: MODEL_VERSION,
  }
}

function average(values: number[]): number {
  if (values.length === 0) return 0
  return Math.round(values.reduce((sum, value) => sum + value, 0) / values.length)
}

function buildStats(findings: StoredFinding[], scored: FindingRiskResult[]) {
  return {
    totalFindings: findings.length,
    criticalFindings: findings.filter((item) => item.severity === 'Critical').length,
    highFindings: findings.filter((item) => item.severity === 'High').length,
    mediumFindings: findings.filter((item) => item.severity === 'Medium').length,
    lowFindings: findings.filter((item) => item.severity === 'Low').length,
    openFindings: findings.filter((item) => item.status === 'Open').length,
    findingsWithCve: findings.filter((item) => isRealCve(item.cve)).length,
    distinctAssets: new Set(findings.map((item) => normalizeText(item.asset) || 'unknown-asset')).size,
    knownExploitedFindings: scored.filter((item) => item.knownExploited).length,
  }
}

function buildReportRationale(scored: FindingRiskResult[], overallRiskBand: RiskBand): string[] {
  const lines: string[] = [`Overall report risk is classified as ${overallRiskBand}.`]
  const knownExploited = scored.filter((item) => item.knownExploited)
  const critical = scored.filter((item) => item.riskBand === 'Critical')
  const top = scored[0]

  if (knownExploited.length > 0) {
    lines.push(`${knownExploited.length} finding${knownExploited.length === 1 ? '' : 's'} include known-exploited CVE intelligence.`)
  }

  if (critical.length > 0) {
    lines.push(`${critical.length} finding${critical.length === 1 ? '' : 's'} reached Critical final risk after threat-aware scoring.`)
  }

  if (top) {
    lines.push(`Top priority finding is "${top.title}" with final risk score ${top.finalRiskScore ?? top.riskScore}.`)
  }

  return unique(lines).slice(0, 6)
}

export function scoreThreatAwareReportRisk(
  report: Pick<StoredReport, 'id' | 'name'>,
  findings: StoredFinding[],
  summary?: ReportSummaryResult,
  options?: ThreatAwareRiskOptions
): ReportRiskResult {
  const intelIndex = buildThreatIntelIndex(options?.threatIntel)

  const scoredFindings = findings
    .map((finding) => scoreOneFinding(finding, intelIndex.get(normalizeCve(finding.cve))))
    .sort((a, b) => b.riskScore - a.riskScore)

  const topRiskFindings = scoredFindings.slice(0, 5)
  const averageRisk = average(scoredFindings.map((item) => item.riskScore))
  const maxRisk = scoredFindings[0]?.riskScore ?? 0
  const knownExploitedCount = scoredFindings.filter((item) => item.knownExploited).length

  let overallRiskScore = Math.round(averageRisk * 0.65 + maxRisk * 0.35)

  if (knownExploitedCount > 0) overallRiskScore += Math.min(8, knownExploitedCount * 4)
  if ((summary?.severityOverview.Critical ?? 0) > 0) overallRiskScore += 2

  overallRiskScore = clamp(0, 100, overallRiskScore)
  const overallRiskBand = toRiskBand(overallRiskScore)

  return {
    reportId: report.id,
    reportName: report.name,
    generatedAtIso: options?.generatedAtIso ?? new Date().toISOString(),
    overallRiskScore,
    overallRiskBand,
    rationale: buildReportRationale(scoredFindings, overallRiskBand),
    stats: buildStats(findings, scoredFindings) as ReportRiskResult['stats'],
    topRiskFindings,
    allFindings: scoredFindings,
  }
}

export function applyRiskToFindings<T extends StoredFinding>(
  findings: T[],
  risk: ReportRiskResult
): T[] {
  const byId = new Map(risk.allFindings.map((item) => [item.findingId, item]))

  return findings.map((finding) => {
    const item = byId.get(finding.id)
    if (!item) return finding

    return {
      ...finding,
      reportCvss: item.reportCvss ?? null,
      reportCvssVector: item.reportCvssVector ?? null,
      intelCvss: item.intelCvss ?? null,
      intelCvssSeverity: item.intelCvssSeverity ?? null,
      intelCvssVector: item.intelCvssVector ?? null,
      knownExploited: Boolean(item.knownExploited),
      cisaKev: Boolean(item.cisaKev),
      mispMatches: item.mispMatches ?? 0,
      exploitAvailable: Boolean(item.exploitAvailable),
      attackVector: item.attackVector ?? null,
      finalRiskScore: item.finalRiskScore ?? item.riskScore,
      riskBand: item.riskBand,
      riskFactors: item.riskFactors ?? item.rationale,
      recommendations: item.recommendations ?? [],
      recommendationSources: item.recommendationSources ?? [],
    }
  })
}
