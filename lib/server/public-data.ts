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
    provenance: finding.provenance
      ? {
          extractionMethod: finding.provenance.extractionMethod,
          parserConfidence: finding.provenance.parserConfidence,
        }
      : undefined,
  }
}