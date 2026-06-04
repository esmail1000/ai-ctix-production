import { getAnalysisReportForUser } from '@/lib/server/analysis-repository'
import { getCurrentSessionFromCookies } from '@/lib/server/current-session'
import { getReportThreatIntel } from '@/lib/server/threat-intel/read-report-intel'
import { NextResponse } from 'next/server'

export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

export async function GET(
  _request: Request,
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

    const result = await getReportThreatIntel(normalizedReportId)

    return NextResponse.json(result)
  } catch (error) {
    console.error('Failed to read threat intel:', error)

    return NextResponse.json(
      {
        error: 'Failed to read threat intel',
        details: error instanceof Error ? error.message : String(error),
      },
      { status: 500 }
    )
  }
}
