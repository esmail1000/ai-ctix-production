import {
  scoreReportRisk,
  type FindingRiskResult,
  type ReportRiskResult,
  type RiskBand,
} from '@/lib/server/risk-scoring'
import type { ReportSummaryResult } from '@/lib/server/summarization'
import type { StoredFinding, StoredReport } from '@/lib/server/types'

function normalizeText(value: string | null | undefined): string {
  return String(value ?? '')
    .replace(/\s+/g, ' ')
    .trim()
}

function containsOne(text: string, patterns: RegExp[]): boolean {
  return patterns.some((pattern) => pattern.test(text))
}

function uniqueStrings(values: string[]): string[] {
  return Array.from(new Set(values.map((item) => normalizeText(item)).filter(Boolean)))
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

function average(values: number[]): number {
  if (values.length === 0) return 0
  return values.reduce((sum, value) => sum + value, 0) / values.length
}

function buildAssetCounts(findings: StoredFinding[]): Map<string, number> {
  const counts = new Map<string, number>()

  for (const finding of findings) {
    const asset = normalizeText(finding.asset) || 'unknown-asset'
    counts.set(asset, (counts.get(asset) ?? 0) + 1)
  }

  return counts
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

function scoreEvidenceStrength(finding: StoredFinding): number {
  const evidence = normalizeText(finding.reported?.evidence || finding.evidence)
  const impact = normalizeText(finding.reported?.impact || finding.impact)
  const text = getFindingText(finding)

  let delta = 0

  if (evidence.length >= 100) delta += 1
  if (impact.length >= 90) delta += 1

  if (
    containsOne(text, [
      /confirmed/,
      /testing confirmed/,
      /accepted payloads/,
      /anonymous access/,
      /bypass/,
      /exposed/,
      /public security advisories/,
      /fingerprinting confirmed/,
    ])
  ) {
    delta += 2
  }

  return delta
}

function scoreInternetExposure(finding: StoredFinding): number {
  const text = [
    finding.asset,
    finding.title,
    finding.reported?.summary || finding.summary,
    finding.reported?.impact || finding.impact,
  ]
    .map(normalizeText)
    .join(' ')
    .toLowerCase()

  if (
    containsOne(text, [
      /public/,
      /internet/,
      /external/,
      /portal/,
      /gateway/,
      /vpn/,
      /web/,
      /storage/,
      /admin\./,
      /auth\./,
      /api\./,
    ])
  ) {
    return 3
  }

  return 0
}

function scoreExploitUrgency(finding: StoredFinding): number {
  const text = getFindingText(finding)

  if (
    containsOne(text, [
      /remote code execution/,
      /\brce\b/,
      /sql injection/,
      /authentication bypass/,
      /privilege escalation/,
      /admin takeover/,
      /full compromise/,
    ])
  ) {
    return 5
  }

  if (
    containsOne(text, [
      /missing mfa/,
      /weak password/,
      /credential stuffing/,
      /public bucket/,
      /exposed/,
      /outdated/,
      /known vulnerabilities/,
      /anonymous access/,
    ])
  ) {
    return 2
  }

  return 0
}

function scoreRemediationRelief(finding: StoredFinding): number {
  const remediation = normalizeText(
    finding.reported?.remediation || finding.remediation
  ).toLowerCase()

  if (!remediation) return 0

  if (
    containsOne(remediation, [
      /patch/,
      /upgrade/,
      /restrict/,
      /rotate/,
      /enforce/,
      /disable/,
      /retest/,
      /review/,
      /least privilege/,
      /remove public permissions/,
    ])
  ) {
    return -2
  }

  return -1
}

function scoreAssetConcentration(
  finding: StoredFinding,
  assetCounts: Map<string, number>
): number {
  const asset = normalizeText(finding.asset) || 'unknown-asset'
  const count = assetCounts.get(asset) ?? 0

  if (count >= 3) return 3
  if (count >= 2) return 1
  return 0
}

function scoreSummaryAlignment(
  finding: StoredFinding,
  summary: ReportSummaryResult
): number {
  const keyFindingIds = new Set(summary.keyFindings.map((item) => item.id))
  const topRiskIds = new Set(summary.topRisks.map((item) => item.id))

  let delta = 0
  if (keyFindingIds.has(finding.id)) delta += 1
  if (topRiskIds.has(finding.id)) delta += 2

  return delta
}

function scoreGroundingQuality(
  finding: StoredFinding,
  summary: ReportSummaryResult
): number {
  let delta = 0

  const hasStructuredProvenance =
    finding.provenance?.extractionMethod === 'structured-parser'
  const hasEvidence =
    normalizeText(finding.reported?.evidence || finding.evidence).length > 0
  const hasRemediation =
    normalizeText(finding.reported?.remediation || finding.remediation).length > 0

  if (hasStructuredProvenance) delta += 1
  if (hasEvidence) delta += 1
  if (hasRemediation) delta += 1
  if (summary.grounding.averageFieldCoverage >= 95) delta += 1

  return delta
}

function buildAdjustment(
  finding: StoredFinding,
  summary: ReportSummaryResult,
  assetCounts: Map<string, number>
): { delta: number; notes: string[] } {
  const notes: string[] = []
  let delta = 0

  const exploitUrgency = scoreExploitUrgency(finding)
  if (exploitUrgency > 0) {
    delta += exploitUrgency
    notes.push('Local wrapper increased urgency due to exploitability signals.')
  }

  const exposure = scoreInternetExposure(finding)
  if (exposure > 0) {
    delta += exposure
    notes.push('The affected asset appears externally exposed or internet-facing.')
  }

  const evidence = scoreEvidenceStrength(finding)
  if (evidence > 0) {
    delta += evidence
    notes.push('The finding includes stronger-than-average supporting evidence.')
  }

  const concentration = scoreAssetConcentration(finding, assetCounts)
  if (concentration > 0) {
    delta += concentration
    notes.push('Multiple findings are concentrated on the same asset.')
  }

  const summaryAlignment = scoreSummaryAlignment(finding, summary)
  if (summaryAlignment > 0) {
    delta += summaryAlignment
    notes.push('This item is emphasized by the current summary and top-risk analysis.')
  }

  const grounding = scoreGroundingQuality(finding, summary)
  if (grounding > 0) {
    delta += grounding
    notes.push('Structured extraction and grounded content increase confidence in prioritization.')
  }

  const remediationRelief = scoreRemediationRelief(finding)
  if (remediationRelief < 0) {
    delta += remediationRelief
    notes.push('A concrete remediation path exists, which slightly reduces net risk.')
  }

  return {
    delta,
    notes: uniqueStrings(notes),
  }
}

function applyWrapperCap(
  severity: StoredFinding['severity'],
  riskScore: number
): number {
  switch (severity) {
    case 'Critical':
      return clamp(0, 100, riskScore)
    case 'High':
      return clamp(0, 94, riskScore)
    case 'Medium':
      return clamp(0, 82, riskScore)
    case 'Low':
      return clamp(0, 58, riskScore)
    default:
      return clamp(0, 100, riskScore)
  }
}

function buildOverallRationale(
  findings: FindingRiskResult[],
  summary: ReportSummaryResult,
  assetCounts: Map<string, number>
): string[] {
  const lines: string[] = []

  const top = findings[0]
  const repeatedAssets = Array.from(assetCounts.entries())
    .filter(([, count]) => count >= 2)
    .sort((a, b) => b[1] - a[1])

  const criticalCount = findings.filter((item) => item.riskBand === 'Critical').length
  const highCount = findings.filter((item) => item.riskBand === 'High').length

  if (criticalCount > 0) {
    lines.push(
      `Calibrated wrapper identified ${criticalCount} Critical-risk finding${
        criticalCount > 1 ? 's' : ''
      }.`
    )
  } else if (highCount > 0) {
    lines.push(
      `Calibrated wrapper is driven by ${highCount} High-risk finding${
        highCount > 1 ? 's' : ''
      }.`
    )
  }

  if (top) {
    lines.push(
      `The highest-priority item is "${top.title}" affecting ${top.asset} with a score of ${top.riskScore}.`
    )
  }

  if (repeatedAssets.length > 0) {
    lines.push(
      `Risk is concentrated on ${repeatedAssets
        .slice(0, 2)
        .map(([asset]) => asset)
        .join(' and ')}.`
    )
  }

  if (summary.grounding.averageFieldCoverage >= 90) {
    lines.push(
      'Grounding coverage is high, which increases confidence in the prioritization outcome.'
    )
  }

  if (summary.stats.openCount > 0) {
    lines.push(
      `${summary.stats.openCount} finding${
        summary.stats.openCount > 1 ? 's remain' : ' remains'
      } Open and should be addressed first.`
    )
  }

  return uniqueStrings(lines).slice(0, 6)
}
function syncRiskBandRationale(
  rationale: string[],
  riskBand: RiskBand
): string[] {
  const cleaned = rationale.filter(
    (line) => !/^Calibrated risk band is\s+/i.test(normalizeText(line))
  )

  const next = [...cleaned]
  next.splice(2, 0, `Calibrated risk band is ${riskBand}.`)

  return uniqueStrings(next)
}
export async function generateReportRisk(
  report: Pick<
    StoredReport,
    'id' | 'name' | 'type' | 'uploadedAt' | 'summary' | 'content'
  >,
  findings: StoredFinding[],
  summary: ReportSummaryResult
): Promise<ReportRiskResult> {
  const base = scoreReportRisk(report, findings, summary)

  if (findings.length === 0) {
    return {
      ...base,
      generatedAtIso: new Date().toISOString(),
    }
  }

  const rawFindingMap = new Map(findings.map((item) => [item.id, item]))
  const assetCounts = buildAssetCounts(findings)

  const allFindings = base.allFindings
    .map((item) => {
      const rawFinding = rawFindingMap.get(item.findingId)
      if (!rawFinding) return item

      const adjustment = buildAdjustment(rawFinding, summary, assetCounts)
      const adjustedScore = item.riskScore + adjustment.delta
      const riskScore = applyWrapperCap(
        rawFinding.severity,
        clamp(0, 100, adjustedScore)
      )

    const nextRiskBand = toRiskBand(riskScore)

return {
  ...item,
  riskScore,
  riskBand: nextRiskBand,
  rationale: syncRiskBandRationale(
    uniqueStrings([...item.rationale, ...adjustment.notes]).slice(0, 8),
    nextRiskBand
  ),
}
    })
    .sort((a, b) => b.riskScore - a.riskScore)

  const topSlice = allFindings.slice(0, 5)
  const averageTopRisk = average(topSlice.map((item) => item.riskScore))
  const averageAllRisk = average(allFindings.map((item) => item.riskScore))
  const repeatedAssetCount = Array.from(assetCounts.values()).filter(
    (count) => count >= 2
  ).length

  let overallRiskScore =
    Math.round(averageAllRisk * 0.7 + averageTopRisk * 0.3) +
    Math.min(repeatedAssetCount, 4)

  if (summary.stats.openCount >= 3) overallRiskScore += 1
  if (summary.stats.criticalCount > 0) overallRiskScore += 2
  if (summary.confidence >= 90) overallRiskScore += 1
  if (summary.grounding.averageFieldCoverage >= 95) overallRiskScore += 1

  overallRiskScore = clamp(0, 100, overallRiskScore)

  return {
    ...base,
    generatedAtIso: new Date().toISOString(),
    overallRiskScore,
    overallRiskBand: toRiskBand(overallRiskScore),
    rationale: buildOverallRationale(allFindings, summary, assetCounts),
    topRiskFindings: allFindings.slice(0, base.topRiskFindings.length || 5),
    allFindings,
  }
}