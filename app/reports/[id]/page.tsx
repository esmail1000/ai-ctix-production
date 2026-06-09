import ReportDetailsShowcase from '@/components/ReportDetailsShowcase'
import { generateReportRisk } from '@/lib/server/ai-risk-scoring'
import { generateReportSummary } from '@/lib/server/ai-summarization'
import {
  getAnalysisFindingsByReportIdForUser,
  getAnalysisReportForUser,
} from '@/lib/server/analysis-repository'
import { getCurrentSessionFromCookies } from '@/lib/server/current-session'
import { getReportThreatIntel } from '@/lib/server/threat-intel/read-report-intel'
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

  if (!report) {
    notFound()
  }

  const findings = await getAnalysisFindingsByReportIdForUser(
    session.userId,
    report.id
  )

  const summary = await generateReportSummary(report, findings)
  let threatIntel: any = null

  try {
    threatIntel = await getReportThreatIntel(report.id)
  } catch {
    threatIntel = null
  }

  const risk = await generateReportRisk(report, findings, summary, { threatIntel })

  return (
    <ReportDetailsShowcase
      report={report}
      findings={findings}
      summary={summary}
      risk={risk}
    />
  )
}
