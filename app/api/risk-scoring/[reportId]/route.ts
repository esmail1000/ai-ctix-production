import { generateReportRisk } from '@/lib/server/ai-risk-scoring'
import { generateReportSummary } from '@/lib/server/ai-summarization'
import { getCurrentSessionFromCookies } from '@/lib/server/current-session'
import {
  getAnalysisFindingsByReportIdForUser,
  getAnalysisReportForUser,
  saveAnalysisRiskScoreForUser,
  saveAnalysisSummaryForUser,
} from '@/lib/server/analysis-repository'
import { NextResponse } from 'next/server'

export const dynamic = 'force-dynamic'

type RouteContext = {
  params: Promise<{
    reportId: string
  }>
}

function normalizeReportId(value: string | undefined): string {
  return String(value ?? '').trim()
}

export async function GET(_request: Request, context: RouteContext) {
  try {
    const session = await getCurrentSessionFromCookies()

    if (!session) {
      return NextResponse.json(
        { error: 'Authentication required.' },
        { status: 401 }
      )
    }

    const { reportId } = await context.params
    const normalizedReportId = normalizeReportId(reportId)

    if (!normalizedReportId) {
      return NextResponse.json(
        { error: 'Missing reportId parameter.' },
        { status: 400 }
      )
    }

    const report = await getAnalysisReportForUser(
      session.userId,
      normalizedReportId
    )

    if (!report) {
      return NextResponse.json(
        { error: `Report "${normalizedReportId}" was not found.` },
        { status: 404 }
      )
    }

    const findings = await getAnalysisFindingsByReportIdForUser(
      session.userId,
      normalizedReportId
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
      reportId: normalizedReportId,
      summary,
      summaryMeta,
    })

    await saveAnalysisRiskScoreForUser({
      userId: session.userId,
      reportId: normalizedReportId,
      risk,
      riskMeta,
    })

    return NextResponse.json({
      report: {
        id: report.id,
        name: report.name,
        type: report.type,
        uploadedAt: report.uploadedAt,
        status: report.status,
        parsingStatus: report.parsingStatus,
        parserVersion: report.parserVersion ?? null,
        parsingNotes: report.parsingNotes ?? [],
      },
      summary: {
        confidence: summary.confidence,
        grounding: summary.grounding,
        executiveSummary: summary.executiveSummary,
        severityOverview: summary.severityOverview,
        topRisks: summary.topRisks,
        stats: summary.stats,
      },
      risk,
      riskMeta,
    })
  } catch (error) {
    return NextResponse.json(
      {
        error:
          error instanceof Error
            ? error.message
            : 'Failed to generate risk scoring result.',
      },
      { status: 500 }
    )
  }
}