import { getAnalysisReportForUser } from '@/lib/server/analysis-repository'
import { getCurrentSessionFromCookies } from '@/lib/server/current-session'
import { getKnowledgeGraphForReport } from '@/lib/server/knowledge-graph/query-graph'
import { NextResponse } from 'next/server'

export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

export async function GET(
  request: Request,
  context: { params: Promise<{ reportId: string }> }
) {
  try {
    const session = await getCurrentSessionFromCookies()

    if (!session) {
      return NextResponse.json(
        { error: 'Authentication required.' },
        { status: 401 }
      )
    }

    const { reportId } = await context.params
    const normalizedReportId = String(reportId ?? '').trim()

    if (!normalizedReportId) {
      return NextResponse.json({ error: 'Missing reportId' }, { status: 400 })
    }

    const report = await getAnalysisReportForUser(
      session.userId,
      normalizedReportId
    )

    if (!report) {
      return NextResponse.json({ error: 'Report not found.' }, { status: 404 })
    }

    const url = new URL(request.url)
    const rawDepth = Number(url.searchParams.get('depth') ?? 4)

    const depth = Number.isFinite(rawDepth)
      ? Math.max(1, Math.min(Math.floor(rawDepth), 6))
      : 4

    const graph = await getKnowledgeGraphForReport(normalizedReportId, depth)

    return NextResponse.json(graph)
  } catch (error) {
    console.error('Knowledge graph API error:', error)

    return NextResponse.json(
      {
        error: 'Failed to load knowledge graph',
        details: error instanceof Error ? error.message : String(error),
      },
      { status: 500 }
    )
  }
}
