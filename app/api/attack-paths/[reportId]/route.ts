import { getAnalysisReportForUser } from '@/lib/server/analysis-repository'
import { getCurrentSessionFromCookies } from '@/lib/server/current-session'
import { getAttackPathsForReport } from '@/lib/server/knowledge-graph/attack-path'
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
    const rawLimit = Number(url.searchParams.get('limit') ?? 10)
    const limit = Number.isFinite(rawLimit)
      ? Math.max(1, Math.min(Math.floor(rawLimit), 50))
      : 10

    const paths = await getAttackPathsForReport(normalizedReportId, limit)

    return NextResponse.json({ paths })
  } catch (error) {
    console.error('Attack paths API error:', error)

    return NextResponse.json(
      {
        error: 'Failed to load attack paths',
        details: error instanceof Error ? error.message : String(error),
      },
      { status: 500 }
    )
  }
}
