import { generateReportSummary } from '@/lib/server/ai-summarization'
import { getCurrentSessionFromCookies } from '@/lib/server/current-session'
import {
  getAnalysisFindingsByReportIdForUser,
  getAnalysisReportForUser,
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

    const summaryMeta = {
      generatedAtIso: summary.generatedAtIso,
      confidence: summary.confidence,
      grounding: summary.grounding,
      totalFindings: summary.stats.totalFindings,
      openFindings: summary.stats.openCount,
      distinctAssets: summary.stats.distinctAssets,
    }

    await saveAnalysisSummaryForUser({
      userId: session.userId,
      reportId: normalizedReportId,
      summary,
      summaryMeta,
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
      summary,
      summaryMeta,
    })
  } catch (error) {
    return NextResponse.json(
      {
        error:
          error instanceof Error
            ? error.message
            : 'Failed to generate report summary.',
      },
      { status: 500 }
    )
  }
}