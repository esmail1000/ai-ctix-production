import type { Finding, Report } from '@/lib/mock-data'
import type { StoredFinding, StoredReport } from '@/lib/server/types'

function normalizeText(value: string | null | undefined): string {
  return String(value ?? '')
    .replace(/\s+/g, ' ')
    .trim()
}

export function toPublicReport(report: StoredReport): Report {
  return {
    id: report.id,
    slug: report.slug,
    name: report.name,
    type: report.type,
    uploadedAt: report.uploadedAt,
    owner: report.owner,
    status: report.status,
    findings: report.findings ?? 0,
    critical: report.critical ?? 0,
    high: report.high ?? 0,
    medium: report.medium ?? 0,
    low: report.low ?? 0,
    summary: normalizeText(report.summary),
  }
}
export function toPublicFinding(finding: StoredFinding): Finding {
  return {
    id: finding.id,
    slug: finding.slug,
    reportId: finding.reportId,
    title: normalizeText(finding.title) || 'Security Finding Requiring Review',
    cve: normalizeText(finding.cve) || '—',
    severity: finding.severity,
    asset: normalizeText(finding.asset) || 'investigation-scope',
    score: finding.score ?? 0,
    status: finding.status,
    detectedAt: finding.detectedAt,
    summary: normalizeText(finding.summary),
    impact: normalizeText(finding.impact),
    evidence: normalizeText(finding.evidence),
    remediation: normalizeText(finding.remediation),
    exploitationSteps: Array.isArray(finding.reported?.exploitationSteps)
      ? finding.reported.exploitationSteps.map(normalizeText).filter(Boolean)
      : undefined,
    reportCvss: finding.reportCvss ?? null,
    reportCvssVector: finding.reportCvssVector ?? null,
    intelCvss: finding.intelCvss ?? null,
    intelCvssSeverity: finding.intelCvssSeverity ?? null,
    intelCvssVector: finding.intelCvssVector ?? null,
    knownExploited: Boolean(finding.knownExploited),
    cisaKev: Boolean(finding.cisaKev),
    mispMatches: finding.mispMatches ?? 0,
    exploitAvailable: Boolean(finding.exploitAvailable),
    attackVector: finding.attackVector ?? null,
    finalRiskScore: finding.finalRiskScore ?? finding.score ?? 0,
    riskBand: finding.riskBand,
    riskFactors: Array.isArray(finding.riskFactors)
      ? finding.riskFactors.map(normalizeText).filter(Boolean)
      : undefined,
    recommendations: Array.isArray(finding.recommendations)
      ? finding.recommendations.map(normalizeText).filter(Boolean)
      : undefined,
    recommendationSources: Array.isArray(finding.recommendationSources)
      ? finding.recommendationSources.map(normalizeText).filter(Boolean)
      : undefined,
    provenance: finding.provenance
      ? {
          extractionMethod: finding.provenance.extractionMethod,
          parserConfidence: finding.provenance.parserConfidence,
        }
      : undefined,
  }
}