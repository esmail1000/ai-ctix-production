import type { Finding, Report } from '@/lib/mock-data'

type FindingLike = Pick<
  Finding,
  'evidence' | 'remediation' | 'summary' | 'impact' | 'cve' | 'score' | 'severity' | 'status' | 'reportId'
> & {
  provenance?: {
    extractionMethod?: string
    parserConfidence?: number
  }
}

export type ReviewBadge = {
  label: string
  tone: 'success' | 'warning' | 'danger' | 'neutral'
}

export function formatExtractionMethod(method: string | undefined): string {
  switch (method) {
    case 'nlp-hybrid':
      return 'NLP Hybrid'
    case 'structured-parser':
      return 'Structured Parser'
    case 'heuristic-fallback':
      return 'Heuristic Fallback'
    case 'manual':
      return 'Manual Review'
    case 'seed':
      return 'Seed Data'
    default:
      return 'Unknown'
  }
}

export function formatParserConfidence(value: number | undefined): string {
  if (typeof value !== 'number') return '—'
  return `${Math.round(value)}%`
}

export function confidenceTone(value: number | undefined): ReviewBadge['tone'] {
  if (typeof value !== 'number') return 'neutral'
  if (value >= 85) return 'success'
  if (value >= 70) return 'neutral'
  if (value >= 50) return 'warning'
  return 'danger'
}

export function hasUsefulValue(value: string | undefined | null) {
  const normalized = (value ?? '').trim().toLowerCase()
  return Boolean(
    normalized &&
      normalized !== '-' &&
      normalized !== '—' &&
      normalized !== 'n/a' &&
      normalized !== 'none' &&
      normalized !== 'unknown'
  )
}

export function isLowConfidence(finding: FindingLike) {
  const confidence = finding.provenance?.parserConfidence
  return typeof confidence === 'number' && confidence < 70
}

export function needsHumanReview(finding: FindingLike) {
  return (
    finding.provenance?.extractionMethod === 'heuristic-fallback' ||
    isLowConfidence(finding) ||
    !hasUsefulValue(finding.evidence) ||
    !hasUsefulValue(finding.remediation)
  )
}

export function getReviewBadges(finding: FindingLike): ReviewBadge[] {
  const badges: ReviewBadge[] = []

  if (finding.provenance?.extractionMethod === 'heuristic-fallback') {
    badges.push({ label: 'Fallback extraction', tone: 'warning' })
  }

  if (isLowConfidence(finding)) {
    badges.push({ label: 'Low confidence', tone: 'warning' })
  }

  if (!hasUsefulValue(finding.evidence)) {
    badges.push({ label: 'Missing evidence', tone: 'danger' })
  }

  if (!hasUsefulValue(finding.remediation)) {
    badges.push({ label: 'Missing remediation', tone: 'danger' })
  }

  if (badges.length === 0) {
    badges.push({ label: 'Ready', tone: 'success' })
  } else {
    badges.unshift({ label: 'Needs review', tone: 'warning' })
  }

  return badges
}

export function completenessScore(finding: FindingLike) {
  const checks = [
    hasUsefulValue(finding.summary),
    hasUsefulValue(finding.impact),
    hasUsefulValue(finding.evidence),
    hasUsefulValue(finding.remediation),
    hasUsefulValue(finding.cve),
  ]

  return Math.round((checks.filter(Boolean).length / checks.length) * 100)
}

export function average(values: number[]) {
  if (values.length === 0) return 0
  return Math.round(values.reduce((sum, value) => sum + value, 0) / values.length)
}

export function getWorkspaceQualityMetrics(findings: FindingLike[], reports: Report[] = []) {
  const confidenceValues = findings
    .map((finding) => finding.provenance?.parserConfidence)
    .filter((value): value is number => typeof value === 'number')

  const needsReview = findings.filter(needsHumanReview)
  const fallback = findings.filter(
    (finding) => finding.provenance?.extractionMethod === 'heuristic-fallback'
  )
  const missingEvidence = findings.filter((finding) => !hasUsefulValue(finding.evidence))
  const missingRemediation = findings.filter((finding) => !hasUsefulValue(finding.remediation))
  const lowConfidence = findings.filter(isLowConfidence)
  const exportReadyReports = reports.filter((report) => {
    const reportFindings = findings.filter((finding) => finding.reportId === report.id)
    return reportFindings.length > 0 && reportFindings.every((finding) => !needsHumanReview(finding))
  })

  return {
    averageConfidence: average(confidenceValues),
    confidenceSampleSize: confidenceValues.length,
    needsReviewCount: needsReview.length,
    fallbackCount: fallback.length,
    missingEvidenceCount: missingEvidence.length,
    missingRemediationCount: missingRemediation.length,
    lowConfidenceCount: lowConfidence.length,
    exportReadyReports: exportReadyReports.length,
  }
}

export function truncateText(value: string | undefined | null, maxLength = 150) {
  const text = (value ?? '').trim()
  if (text.length <= maxLength) return text || '—'
  return `${text.slice(0, maxLength - 1).trim()}…`
}
