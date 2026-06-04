import type { Finding, Severity } from '@/lib/mock-data'
import type { StoredFinding, StoredReport } from '@/lib/server/types'

export type SeverityOverview = Record<Severity, number>

export type SummaryKeyFinding = {
  id: string
  title: string
  severity: Severity
  asset: string
  score: number
  cve: string
  status: Finding['status']
  summary: string
  impact: string
  remediation: string
  priority: number
}

export type SummaryAffectedAsset = {
  asset: string
  findingsCount: number
  highestSeverity: Severity
  highestScore: number
}

export type SummaryTopRisk = {
  id: string
  title: string
  severity: Severity
  score: number
  asset: string
  reason: string
}

export type SummaryGroundingStats = {
  findingsWithSummary: number
  findingsWithImpact: number
  findingsWithEvidence: number
  findingsWithRemediation: number
  fullyGroundedFindings: number
  partiallyGroundedFindings: number
  averageFieldCoverage: number
}

export type ReportSummaryResult = {
  reportId: string
  reportName: string
  generatedAtIso: string
  executiveSummary: string
  narrativeSummary: string
  keyFindings: SummaryKeyFinding[]
  affectedAssets: SummaryAffectedAsset[]
  severityOverview: SeverityOverview
  topRisks: SummaryTopRisk[]
  recommendations: string[]
  confidence: number
  grounding: SummaryGroundingStats
  stats: {
    totalFindings: number
    criticalCount: number
    highCount: number
    mediumCount: number
    lowCount: number
    openCount: number
    resolvedCount: number
    distinctAssets: number
  }
}

type SummaryOptions = {
  maxKeyFindings?: number
  maxTopRisks?: number
  maxRecommendations?: number
  maxAssets?: number
}

const DEFAULT_OPTIONS: Required<SummaryOptions> = {
  maxKeyFindings: 5,
  maxTopRisks: 5,
  maxRecommendations: 5,
  maxAssets: 6,
}

const severityWeight: Record<Severity, number> = {
  Critical: 4,
  High: 3,
  Medium: 2,
  Low: 1,
}

const remediationThemeRules: Array<{ label: string; patterns: RegExp[] }> = [
  {
    label: 'identity and access hardening',
    patterns: [/mfa/, /authentication/, /access control/, /privilege/, /password/, /credentials?/],
  },
  {
    label: 'patching and software updates',
    patterns: [/patch/, /upgrade/, /outdated/, /version/, /cve-/],
  },
  {
    label: 'public exposure reduction',
    patterns: [/public/, /exposed/, /bucket/, /storage/, /internet-facing/, /anonymous access/],
  },
  {
    label: 'application hardening and secure error handling',
    patterns: [/verbose error/, /stack trace/, /exception/, /headers?/, /harden/],
  },
  {
    label: 'monitoring and investigation',
    patterns: [/forensic/, /logs?/, /investigate/, /monitor/, /egress/, /outbound/],
  },
]

function normalizeText(value: string | null | undefined): string {
  return String(value ?? '')
    .replace(/\s+/g, ' ')
    .replace(/[•*]\s*/g, ' ')
    .trim()
}

function truncate(value: string, max = 220): string {
  const cleaned = normalizeText(value)
  if (cleaned.length <= max) return cleaned
  return `${cleaned.slice(0, max - 1).trim()}…`
}

function uniqueStrings(values: string[]): string[] {
  return Array.from(new Set(values.map((item) => normalizeText(item)).filter(Boolean)))
}

function isRealCve(value: string): boolean {
  const normalized = normalizeText(value)
  return /^CVE-\d{4}-\d{4,}$/i.test(normalized)
}

function compareSeverity(a: Severity, b: Severity): number {
  return severityWeight[b] - severityWeight[a]
}

function getHighestSeverity(findings: Array<Pick<Finding, 'severity'>>): Severity {
  const ordered = [...findings].sort((a, b) => compareSeverity(a.severity, b.severity))
  return ordered[0]?.severity ?? 'Low'
}

function buildSeverityOverview(findings: Array<Pick<Finding, 'severity'>>): SeverityOverview {
  const base: SeverityOverview = {
    Critical: 0,
    High: 0,
    Medium: 0,
    Low: 0,
  }

  for (const finding of findings) {
    base[finding.severity] += 1
  }

  return base
}

function scoreFindingPriority(
  finding: Pick<StoredFinding, 'severity' | 'score' | 'status' | 'cve' | 'impact' | 'title'>
): number {
  let priority = finding.score
  priority += severityWeight[finding.severity] * 20

  if (finding.status === 'Open') priority += 10
  if (finding.status === 'In Review') priority += 4
  if (finding.status === 'Resolved') priority -= 8
  if (isRealCve(finding.cve)) priority += 8

  const impact = normalizeText(finding.impact).toLowerCase()
  const title = normalizeText(finding.title).toLowerCase()

  if (
    /remote code execution|rce|authentication bypass|privilege escalation|sql injection|admin takeover|full compromise/.test(
      impact
    ) ||
    /remote code execution|rce|authentication bypass|privilege escalation|sql injection/.test(
      title
    )
  ) {
    priority += 10
  }

  return priority
}

function summarizeFinding(finding: StoredFinding): SummaryKeyFinding {
  return {
    id: finding.id,
    title: normalizeText(finding.title),
    severity: finding.severity,
    asset: normalizeText(finding.asset) || 'unknown-asset',
    score: finding.score,
    cve: normalizeText(finding.cve) || '—',
    status: finding.status,
    summary: truncate(finding.reported?.summary || finding.summary, 220),
    impact: truncate(finding.reported?.impact || finding.impact, 220),
    remediation: truncate(finding.reported?.remediation || finding.remediation, 220),
    priority: scoreFindingPriority(finding),
  }
}

function buildAffectedAssets(findings: StoredFinding[], maxAssets: number): SummaryAffectedAsset[] {
  const grouped = new Map<string, StoredFinding[]>()

  for (const finding of findings) {
    const asset = normalizeText(finding.asset) || 'unknown-asset'
    const bucket = grouped.get(asset) ?? []
    bucket.push(finding)
    grouped.set(asset, bucket)
  }

  return Array.from(grouped.entries())
    .map(([asset, assetFindings]) => ({
      asset,
      findingsCount: assetFindings.length,
      highestSeverity: getHighestSeverity(assetFindings),
      highestScore: Math.max(...assetFindings.map((item) => item.score)),
    }))
    .sort((a, b) => {
      const severityDiff = compareSeverity(a.highestSeverity, b.highestSeverity)
      if (severityDiff !== 0) return severityDiff
      if (b.findingsCount !== a.findingsCount) return b.findingsCount - a.findingsCount
      return b.highestScore - a.highestScore
    })
    .slice(0, maxAssets)
}

function buildTopRisks(
  summarizedFindings: SummaryKeyFinding[],
  maxTopRisks: number
): SummaryTopRisk[] {
  return summarizedFindings
    .slice()
    .sort((a, b) => b.priority - a.priority)
    .slice(0, maxTopRisks)
    .map((item) => ({
      id: item.id,
      title: item.title,
      severity: item.severity,
      score: item.score,
      asset: item.asset,
      reason: buildRiskReason(item),
    }))
}

function buildRiskReason(finding: SummaryKeyFinding): string {
  const reasons: string[] = []

  reasons.push(`${finding.severity} severity`)
  reasons.push(`risk score ${finding.score}`)

  if (finding.status === 'Open') reasons.push('still open')
  if (isRealCve(finding.cve)) reasons.push(`linked CVE (${finding.cve})`)
  if (finding.asset && finding.asset !== 'unknown-asset') reasons.push(`affects ${finding.asset}`)

  return reasons.join(', ')
}

function deriveRecommendationTheme(findings: SummaryKeyFinding[]): string | null {
  const text = findings
    .map((item) => [item.title, item.summary, item.impact, item.remediation].join(' '))
    .join(' ')
    .toLowerCase()

  for (const rule of remediationThemeRules) {
    if (rule.patterns.some((pattern) => pattern.test(text))) {
      return rule.label
    }
  }

  return null
}

function buildRecommendations(
  findings: SummaryKeyFinding[],
  maxRecommendations: number
): string[] {
  const ordered = findings
    .slice()
    .sort((a, b) => b.priority - a.priority)

  const directRecommendations = uniqueStrings(
    ordered
      .map((item) => item.remediation)
      .filter((item) => normalizeText(item).length >= 20)
  )

  const fallbackRecommendations: string[] = []

  if (ordered.some((item) => item.severity === 'Critical' || item.severity === 'High')) {
    fallbackRecommendations.push(
      'Prioritize remediation for Critical and High findings before lower-severity items.'
    )
  }

  if (ordered.some((item) => item.status === 'Open')) {
    fallbackRecommendations.push(
      'Create an action plan for all Open findings and assign ownership with target closure dates.'
    )
  }

  if (ordered.some((item) => isRealCve(item.cve))) {
    fallbackRecommendations.push(
      'Validate patch status for findings linked to public CVEs and retest the affected services.'
    )
  }

  const theme = deriveRecommendationTheme(ordered.slice(0, 3))
  if (theme) {
    fallbackRecommendations.push(`Focus the next remediation wave on ${theme}.`)
  }

  return uniqueStrings([...directRecommendations, ...fallbackRecommendations]).slice(
    0,
    maxRecommendations
  )
}

function buildExecutiveSummary(params: {
  reportName: string
  findings: SummaryKeyFinding[]
  severityOverview: SeverityOverview
  affectedAssets: SummaryAffectedAsset[]
}): string {
  const { reportName, findings, severityOverview, affectedAssets } = params
  const total = findings.length
  const topAssets = affectedAssets.slice(0, 3).map((item) => item.asset)
  const topOpen = findings
    .filter((item) => item.status === 'Open')
    .slice(0, 2)
    .map((item) => `"${item.title}"`)

  const riskHeadline =
    severityOverview.Critical > 0
      ? `The report "${reportName}" indicates urgent security exposure because ${severityOverview.Critical} Critical finding${severityOverview.Critical > 1 ? 's are' : ' is'} present.`
      : severityOverview.High > 0
        ? `The report "${reportName}" indicates elevated risk driven by ${severityOverview.High} High-severity finding${severityOverview.High > 1 ? 's' : ''}.`
        : `The report "${reportName}" indicates moderate overall risk with no Critical findings.`

  const breakdownSentence = `A total of ${total} finding${total !== 1 ? 's were' : ' was'} identified (${severityOverview.Critical} Critical, ${severityOverview.High} High, ${severityOverview.Medium} Medium, ${severityOverview.Low} Low).`

  const assetSentence =
    topAssets.length > 0
      ? `The most affected assets are ${topAssets.join(', ')}.`
      : 'No affected assets were confidently identified.'

  const prioritySentence =
    topOpen.length > 0
      ? `Immediate attention should focus on ${topOpen.join(' and ')}.`
      : 'No open high-priority findings were identified in the current result set.'

  return [riskHeadline, breakdownSentence, assetSentence, prioritySentence]
    .filter(Boolean)
    .join(' ')
    .trim()
}

function buildNarrativeSummary(params: {
  findings: SummaryKeyFinding[]
  severityOverview: SeverityOverview
  affectedAssets: SummaryAffectedAsset[]
  recommendations: string[]
}): string {
  const { findings, severityOverview, affectedAssets, recommendations } = params

  const topOpen = findings
    .filter((item) => item.status === 'Open')
    .slice()
    .sort((a, b) => b.priority - a.priority)
    .slice(0, 2)

  const openSentence =
    topOpen.length > 0
      ? `Open issues remain concentrated around ${topOpen
          .map((item) => `"${item.title}" on ${item.asset}`)
          .join(' and ')}.`
      : 'There are no currently open high-priority issues in the selected result set.'

  const assetSentence =
    affectedAssets.length > 0
      ? `Risk concentration is highest around ${affectedAssets
          .slice(0, 2)
          .map((item) => item.asset)
          .join(' and ')}.`
      : 'Asset-level clustering was not strong enough to highlight concentration patterns.'

  const severitySentence =
    severityOverview.Critical + severityOverview.High > 0
      ? 'The distribution is weighted toward Critical and High findings, so immediate containment and remediation are justified.'
      : 'The current set is weighted toward Medium and Low findings, so remediation can focus on hardening and exposure reduction.'

  const recommendationSentence =
    recommendations.length > 0
      ? `Recommended next actions include ${recommendations.slice(0, 2).join(' ')}`
      : ''

  return [openSentence, assetSentence, severitySentence, recommendationSentence]
    .filter(Boolean)
    .join(' ')
    .trim()
}

function buildGroundingStats(findings: StoredFinding[]): SummaryGroundingStats {
  if (findings.length === 0) {
    return {
      findingsWithSummary: 0,
      findingsWithImpact: 0,
      findingsWithEvidence: 0,
      findingsWithRemediation: 0,
      fullyGroundedFindings: 0,
      partiallyGroundedFindings: 0,
      averageFieldCoverage: 0,
    }
  }

  let findingsWithSummary = 0
  let findingsWithImpact = 0
  let findingsWithEvidence = 0
  let findingsWithRemediation = 0
  let fullyGroundedFindings = 0
  let partiallyGroundedFindings = 0
  let totalCoverage = 0

  for (const finding of findings) {
    const summary = normalizeText(finding.reported?.summary || finding.summary)
    const impact = normalizeText(finding.reported?.impact || finding.impact)
    const evidence = normalizeText(finding.reported?.evidence || finding.evidence)
    const remediation = normalizeText(finding.reported?.remediation || finding.remediation)

    let coverage = 0

    if (summary) {
      findingsWithSummary += 1
      coverage += 1
    }

    if (impact) {
      findingsWithImpact += 1
      coverage += 1
    }

    if (evidence) {
      findingsWithEvidence += 1
      coverage += 1
    }

    if (remediation) {
      findingsWithRemediation += 1
      coverage += 1
    }

    totalCoverage += coverage / 4

    if (coverage === 4) {
      fullyGroundedFindings += 1
    } else if (coverage > 0) {
      partiallyGroundedFindings += 1
    }
  }

  return {
    findingsWithSummary,
    findingsWithImpact,
    findingsWithEvidence,
    findingsWithRemediation,
    fullyGroundedFindings,
    partiallyGroundedFindings,
    averageFieldCoverage: Math.round((totalCoverage / findings.length) * 100),
  }
}

function calculateConfidence(
  findings: StoredFinding[],
  grounding: SummaryGroundingStats
): number {
  if (findings.length === 0) return 0

  const structuredCount = findings.filter(
    (item) => item.provenance?.extractionMethod === 'structured-parser'
  ).length

  const structuredRatio = structuredCount / findings.length
  const openRatio =
    findings.filter((item) => item.status === 'Open').length / findings.length
  const cveBonus = findings.some((item) => isRealCve(item.cve)) ? 4 : 0

  const coverageComponent = grounding.averageFieldCoverage * 0.7
  const structuredComponent = structuredRatio * 20
  const openComponent = openRatio * 4

  const raw = Math.round(
    coverageComponent + structuredComponent + openComponent + cveBonus
  )

  return Math.max(50, Math.min(98, raw))
}

function buildEmptySummary(report?: Pick<StoredReport, 'id' | 'name'>): ReportSummaryResult {
  return {
    reportId: report?.id ?? '',
    reportName: report?.name ?? 'Unknown Report',
    generatedAtIso: new Date().toISOString(),
    executiveSummary: 'No findings are currently available for summarization.',
    narrativeSummary: 'The selected report does not yet contain extracted findings to summarize.',
    keyFindings: [],
    affectedAssets: [],
    severityOverview: {
      Critical: 0,
      High: 0,
      Medium: 0,
      Low: 0,
    },
    topRisks: [],
    recommendations: [],
    confidence: 0,
    grounding: {
      findingsWithSummary: 0,
      findingsWithImpact: 0,
      findingsWithEvidence: 0,
      findingsWithRemediation: 0,
      fullyGroundedFindings: 0,
      partiallyGroundedFindings: 0,
      averageFieldCoverage: 0,
    },
    stats: {
      totalFindings: 0,
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      openCount: 0,
      resolvedCount: 0,
      distinctAssets: 0,
    },
  }
}

export function summarizeReport(
  report: Pick<StoredReport, 'id' | 'name'>,
  findings: StoredFinding[],
  options?: SummaryOptions
): ReportSummaryResult {
  const config = { ...DEFAULT_OPTIONS, ...options }

  if (!findings || findings.length === 0) {
    return buildEmptySummary(report)
  }

  const summarizedFindings = findings
    .map(summarizeFinding)
    .sort((a, b) => b.priority - a.priority)

  const severityOverview = buildSeverityOverview(findings)
  const affectedAssets = buildAffectedAssets(findings, config.maxAssets)
  const keyFindings = summarizedFindings.slice(0, config.maxKeyFindings)
  const topRisks = buildTopRisks(summarizedFindings, config.maxTopRisks)
  const recommendations = buildRecommendations(
    summarizedFindings,
    config.maxRecommendations
  )
  const grounding = buildGroundingStats(findings)

  const executiveSummary = buildExecutiveSummary({
    reportName: report.name,
    findings: summarizedFindings,
    severityOverview,
    affectedAssets,
  })

  const narrativeSummary = buildNarrativeSummary({
    findings: summarizedFindings,
    severityOverview,
    affectedAssets,
    recommendations,
  })

  const stats = {
    totalFindings: findings.length,
    criticalCount: severityOverview.Critical,
    highCount: severityOverview.High,
    mediumCount: severityOverview.Medium,
    lowCount: severityOverview.Low,
    openCount: findings.filter((item) => item.status === 'Open').length,
    resolvedCount: findings.filter((item) => item.status === 'Resolved').length,
    distinctAssets: new Set(
      findings.map((item) => normalizeText(item.asset) || 'unknown-asset')
    ).size,
  }

  return {
    reportId: report.id,
    reportName: report.name,
    generatedAtIso: new Date().toISOString(),
    executiveSummary,
    narrativeSummary,
    keyFindings,
    affectedAssets,
    severityOverview,
    topRisks,
    recommendations,
    confidence: calculateConfidence(findings, grounding),
    grounding,
    stats,
  }
}

export function summarizeFindingsOnly(
  findings: StoredFinding[],
  options?: SummaryOptions
): Omit<ReportSummaryResult, 'reportId' | 'reportName'> {
  const result = summarizeReport(
    { id: 'ad-hoc-report', name: 'Ad Hoc Summary' } as Pick<
      StoredReport,
      'id' | 'name'
    >,
    findings,
    options
  )

  return {
    generatedAtIso: result.generatedAtIso,
    executiveSummary: result.executiveSummary,
    narrativeSummary: result.narrativeSummary,
    keyFindings: result.keyFindings,
    affectedAssets: result.affectedAssets,
    severityOverview: result.severityOverview,
    topRisks: result.topRisks,
    recommendations: result.recommendations,
    confidence: result.confidence,
    grounding: result.grounding,
    stats: result.stats,
  }
}