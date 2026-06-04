import { summarizeReport, type ReportSummaryResult } from '@/lib/server/summarization'
import type { StoredFinding, StoredReport } from '@/lib/server/types'

type ThemeBucket = {
  name: string
  count: number
}

function normalizeText(value: string | null | undefined): string {
  return String(value ?? '')
    .replace(/\s+/g, ' ')
    .trim()
}

function clip(value: string, max = 260): string {
  const normalized = normalizeText(value)
  if (normalized.length <= max) return normalized
  return `${normalized.slice(0, max).trim()}…`
}

function uniqueStrings(values: string[]): string[] {
  return Array.from(new Set(values.map((item) => normalizeText(item)).filter(Boolean)))
}

function containsOne(text: string, patterns: RegExp[]): boolean {
  return patterns.some((pattern) => pattern.test(text))
}

function getFindingText(finding: StoredFinding): string {
  return [
    finding.title,
    finding.reported?.summary || finding.summary,
    finding.reported?.impact || finding.impact,
    finding.reported?.evidence || finding.evidence,
    finding.reported?.remediation || finding.remediation,
    finding.cve,
  ]
    .map(normalizeText)
    .join(' ')
    .toLowerCase()
}

function detectThemes(findings: StoredFinding[]): ThemeBucket[] {
  const buckets = new Map<string, number>()

  const bump = (name: string) => {
    buckets.set(name, (buckets.get(name) ?? 0) + 1)
  }

  for (const finding of findings) {
    const text = getFindingText(finding)

    if (
      containsOne(text, [
        /mfa/,
        /authentication/,
        /authorization/,
        /role/,
        /privilege/,
        /access control/,
        /identity/,
        /credential/,
        /password/,
      ])
    ) {
      bump('Identity and access security')
    }

    if (
      containsOne(text, [
        /cve-/,
        /patch/,
        /upgrade/,
        /outdated/,
        /unsupported/,
        /apache/,
        /known vulnerabilities/,
        /version/,
      ])
    ) {
      bump('Patch and vulnerability management')
    }

    if (
      containsOne(text, [
        /public/,
        /internet-facing/,
        /external/,
        /gateway/,
        /portal/,
        /vpn/,
        /bucket/,
        /storage/,
        /exposed/,
        /anonymous access/,
      ])
    ) {
      bump('Exposure and attack surface reduction')
    }

    if (
      containsOne(text, [
        /verbose error/,
        /stack trace/,
        /exception/,
        /application/,
        /framework/,
        /hardening/,
      ])
    ) {
      bump('Application hardening')
    }

    if (
      containsOne(text, [
        /outbound/,
        /forensic/,
        /monitor/,
        /logs?/,
        /investigate/,
        /egress/,
        /command and control/,
      ])
    ) {
      bump('Monitoring and incident response')
    }
  }

  return Array.from(buckets.entries())
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count)
}

function getTopOpenFindings(findings: StoredFinding[]): Array<{ title: string; asset: string }> {
  return findings
    .filter((item) => item.status === 'Open')
    .sort((a, b) => b.score - a.score)
    .slice(0, 2)
    .map((item) => ({
      title: normalizeText(item.title),
      asset: normalizeText(item.asset) || 'unknown-asset',
    }))
}

function buildExecutiveSummary(params: {
  report: Pick<StoredReport, 'name'>
  findings: StoredFinding[]
  base: ReportSummaryResult
  themes: ThemeBucket[]
}): string {
  const { report, findings, base, themes } = params

  const total = findings.length
  const topAssets = base.affectedAssets.slice(0, 3).map((item) => item.asset)
  const topThemes = themes.slice(0, 2).map((item) => item.name)
  const topOpen = getTopOpenFindings(findings)

  const opening =
    base.severityOverview.Critical > 0
      ? `The report "${report.name}" indicates urgent risk because ${base.severityOverview.Critical} Critical finding${base.severityOverview.Critical > 1 ? 's are' : ' is'} present.`
      : base.severityOverview.High > 0
        ? `The report "${report.name}" indicates elevated risk driven by ${base.severityOverview.High} High-severity finding${base.severityOverview.High > 1 ? 's' : ''}.`
        : `The report "${report.name}" indicates moderate overall risk with no Critical findings.`

  const distribution = `The current result set contains ${total} finding${total !== 1 ? 's' : ''} across ${base.stats.distinctAssets} distinct asset${base.stats.distinctAssets !== 1 ? 's' : ''}.`

  const assetsSentence =
    topAssets.length > 0
      ? `The most affected assets are ${topAssets.join(', ')}.`
      : 'No affected assets were confidently identified.'

  const themesSentence =
    topThemes.length > 0
      ? `Dominant themes include ${topThemes.join(' and ')}.`
      : ''

  const attentionSentence =
    topOpen.length > 0
      ? `Immediate attention should focus on ${topOpen
          .map((item) => `"${item.title}" on ${item.asset}`)
          .join(' and ')}.`
      : ''

  return clip(
    [opening, distribution, assetsSentence, themesSentence, attentionSentence]
      .filter(Boolean)
      .join(' '),
    420
  )
}

function buildNarrativeSummary(params: {
  findings: StoredFinding[]
  base: ReportSummaryResult
  themes: ThemeBucket[]
}): string {
  const { findings, base, themes } = params

  const topRisks = base.topRisks.slice(0, 2)
  const topAssets = base.affectedAssets.slice(0, 2).map((item) => item.asset)
  const topThemes = themes.slice(0, 3).map((item) => item.name)

  const riskSentence =
    topRisks.length > 0
      ? `Highest-priority risks currently include ${topRisks
          .map((item) => `"${item.title}" affecting ${item.asset}`)
          .join(' and ')}.`
      : 'No high-priority risks were identified.'

  const assetSentence =
    topAssets.length > 0
      ? `Risk concentration is highest around ${topAssets.join(' and ')}.`
      : ''

  const statusSentence =
    base.stats.openCount > 0
      ? `${base.stats.openCount} finding${base.stats.openCount > 1 ? 's remain' : ' remains'} open, so remediation tracking should stay focused on active issues first.`
      : 'No active open findings remain in the current result set.'

  const themeSentence =
    topThemes.length > 0
      ? `From a control perspective, the report is mainly about ${topThemes.join(', ')}.`
      : ''

  const groundingSentence =
    base.grounding.averageFieldCoverage >= 90
      ? 'The summary is strongly grounded in extracted finding content.'
      : base.grounding.averageFieldCoverage >= 70
        ? 'The summary is reasonably grounded in extracted finding content, with some partial coverage.'
        : 'The summary should be reviewed carefully because grounding coverage is incomplete.'

  const evidenceSentence =
    findings.some((item) => normalizeText(item.reported?.evidence || item.evidence))
      ? 'Evidence-backed findings are available for analyst review.'
      : 'Evidence coverage is limited and should be improved.'

  return clip(
    [
      riskSentence,
      assetSentence,
      statusSentence,
      themeSentence,
      groundingSentence,
      evidenceSentence,
    ]
      .filter(Boolean)
      .join(' '),
    520
  )
}

function buildRefinedRecommendations(
  base: ReportSummaryResult,
  themes: ThemeBucket[]
): string[] {
  const themeDriven: string[] = []

  if (themes.some((item) => item.name === 'Identity and access security')) {
    themeDriven.push('Validate identity controls, privileged access paths, and MFA enforcement first.')
  }

  if (themes.some((item) => item.name === 'Patch and vulnerability management')) {
    themeDriven.push('Prioritize patch validation and retesting for findings tied to outdated or vulnerable software.')
  }

  if (themes.some((item) => item.name === 'Exposure and attack surface reduction')) {
    themeDriven.push('Reduce public exposure first for internet-facing assets and externally reachable services.')
  }

  if (themes.some((item) => item.name === 'Monitoring and incident response')) {
    themeDriven.push('Preserve logs and validate monitoring coverage for findings that imply investigation or suspicious activity.')
  }

  return uniqueStrings([...base.recommendations, ...themeDriven]).slice(0, 6)
}

function adjustConfidence(
  base: ReportSummaryResult,
  findings: StoredFinding[]
): number {
  let next = base.confidence

  const structuredRatio =
    findings.length === 0
      ? 0
      : findings.filter((item) => item.provenance?.extractionMethod === 'structured-parser')
          .length / findings.length

  if (structuredRatio === 1) next += 2
  if (base.grounding.averageFieldCoverage >= 95) next += 2
  if (base.grounding.averageFieldCoverage < 75) next -= 4
  if (base.stats.openCount > 0) next += 1

  return Math.max(50, Math.min(99, next))
}

export async function generateReportSummary(
  report: Pick<StoredReport, 'id' | 'name'>,
  findings: StoredFinding[]
): Promise<ReportSummaryResult> {
  const base = summarizeReport(report, findings)

  if (!findings || findings.length === 0) {
    return base
  }

  const themes = detectThemes(findings)

  return {
    ...base,
    executiveSummary: buildExecutiveSummary({
      report,
      findings,
      base,
      themes,
    }),
    narrativeSummary: buildNarrativeSummary({
      findings,
      base,
      themes,
    }),
    recommendations: buildRefinedRecommendations(base, themes),
    confidence: adjustConfidence(base, findings),
  }
}