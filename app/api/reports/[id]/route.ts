import { getCurrentSessionFromCookies } from '@/lib/server/current-session'
import {
  deleteAnalysisReportForUser,
  getAnalysisReportForUser,
} from '@/lib/server/analysis-repository'
import { toPublicReport } from '@/lib/server/public-data'
import { deleteKnowledgeGraphReportForUser } from '@/lib/server/knowledge-graph/query-graph'
import { NextResponse } from 'next/server'

export const dynamic = 'force-dynamic'

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const session = await getCurrentSessionFromCookies()

  if (!session) {
    return NextResponse.json(
      { error: 'Authentication required.' },
      { status: 401 }
    )
  }

  const { id } = await params
  const report = await getAnalysisReportForUser(session.userId, id)

  if (!report) {
    return NextResponse.json({ error: 'Report not found.' }, { status: 404 })
  }

  return NextResponse.json({ report: toPublicReport(report) })
}

export async function DELETE(
  _request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const session = await getCurrentSessionFromCookies()

  if (!session) {
    return NextResponse.json(
      { error: 'Authentication required.' },
      { status: 401 }
    )
  }

  const { id } = await params
  const reportId = String(id ?? '').trim()

  if (!reportId) {
    return NextResponse.json({ error: 'Missing report ID.' }, { status: 400 })
  }

  const deletedReport = await deleteAnalysisReportForUser(session.userId, reportId)

  if (!deletedReport) {
    return NextResponse.json({ error: 'Report not found.' }, { status: 404 })
  }

  // PostgreSQL is the source of truth for the reports list. Neo4j cleanup is
  // best-effort and is intentionally not awaited, so the UI never hangs while
  // graph cleanup is running or unavailable.
  void deleteKnowledgeGraphReportForUser(session.userId, reportId).catch((error) => {
    console.warn('Neo4j report cleanup skipped:', error)
  })

  return NextResponse.json({
    ok: true,
    deletedReport: {
      id: deletedReport.id,
      name: deletedReport.name,
      findingCount: deletedReport.findingCount,
    },
    warnings: [
      'Report was deleted from PostgreSQL. Neo4j cleanup was started as a best-effort background task.',
    ],
  })
}
