import {
  scoreThreatAwareReportRisk,
  type ThreatAwareRiskOptions,
} from '@/lib/server/threat-aware-risk'
import type { ReportRiskResult } from '@/lib/server/risk-scoring'
import type { ReportSummaryResult } from '@/lib/server/summarization'
import type { StoredFinding, StoredReport } from '@/lib/server/types'

/**
 * Compatibility entry point used by existing routes/components.
 * Despite the historical filename, this function is intentionally deterministic:
 * it uses only extracted report evidence, persisted findings, and real threat
 * intelligence supplied by the caller. It does not fabricate CVSS, KEV, MISP,
 * or recommendation data.
 */
export async function generateReportRisk(
  report: Pick<
    StoredReport,
    'id' | 'name' | 'type' | 'uploadedAt' | 'summary' | 'content'
  >,
  findings: StoredFinding[],
  summary: ReportSummaryResult,
  options?: ThreatAwareRiskOptions
): Promise<ReportRiskResult> {
  return scoreThreatAwareReportRisk(report, findings, summary, options)
}
