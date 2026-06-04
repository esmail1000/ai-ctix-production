import { NextResponse } from 'next/server'
import { getCurrentSessionFromCookies } from '@/lib/server/current-session'
import { listAnalysisReportsForUser } from '@/lib/server/analysis-repository'
import { toPublicReport } from '@/lib/server/public-data'

export const dynamic = 'force-dynamic'

export async function GET() {
  const session = await getCurrentSessionFromCookies()

  if (!session) {
    return NextResponse.json(
      { error: 'Authentication required.' },
      { status: 401 }
    )
  }

  const reports = await listAnalysisReportsForUser(session.userId)

  return NextResponse.json({
    reports: reports.map(toPublicReport),
  })
}