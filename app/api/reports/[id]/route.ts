import { getCurrentSessionFromCookies } from '@/lib/server/current-session'
import { getAnalysisReportForUser } from '@/lib/server/analysis-repository'
import { toPublicReport } from '@/lib/server/public-data'
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