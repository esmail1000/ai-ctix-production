import ReportDetailsShowcase from '@/components/ReportDetailsShowcase'
import { generateReportRisk } from '@/lib/server/ai-risk-scoring'
import { generateReportSummary } from '@/lib/server/ai-summarization'
import {
  getAnalysisFindingsByReportIdForUser,
  getAnalysisReportForUser,
  saveAnalysisRiskScoreForUser,
  saveAnalysisSummaryForUser,
} from '@/lib/server/analysis-repository'
import { getCurrentSessionFromCookies } from '@/lib/server/current-session'
import { notFound, redirect } from 'next/navigation'

export const dynamic = 'force-dynamic'

export default async function ReportDetailsPage({
  params,
}: {
  params: Promise<{ id: string }>
}) {
  const session = await getCurrentSessionFromCookies()

  if (!session) {
    redirect('/login')
  }

  const { id } = await params

  const report = await getAnalysisReportForUser(session.userId, id)

  if (!report) return notFound()

  const findings = await getAnalysisFindingsByReportIdForUser(
    session.userId,
    report.id
  )

  const summary = await generateReportSummary(report, findings)
  const risk = await generateReportRisk(report, findings, summary)

  const summaryMeta = {
    generatedAtIso: summary.generatedAtIso,
    confidence: summary.confidence,
    grounding: summary.grounding,
    totalFindings: summary.stats.totalFindings,
    openFindings: summary.stats.openCount,
    distinctAssets: summary.stats.distinctAssets,
  }

  const riskMeta = {
    generatedAtIso: risk.generatedAtIso,
    overallRiskScore: risk.overallRiskScore,
    overallRiskBand: risk.overallRiskBand,
    totalFindings: risk.stats.totalFindings,
    openFindings: risk.stats.openFindings,
    findingsWithCve: risk.stats.findingsWithCve,
    distinctAssets: risk.stats.distinctAssets,
  }

  await saveAnalysisSummaryForUser({
    userId: session.userId,
    reportId: report.id,
    summary,
    summaryMeta,
  })

  await saveAnalysisRiskScoreForUser({
    userId: session.userId,
    reportId: report.id,
    risk,
    riskMeta,
  })

  return (
    <ReportDetailsShowcase
      report={report}
      findings={findings}
      summary={summary}
      risk={risk}
    />
  )
}