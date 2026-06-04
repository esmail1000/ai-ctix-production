import { NextResponse } from 'next/server'
import { getCurrentSessionFromCookies } from '@/lib/server/current-session'
import { listAnalysisFindingsForUser } from '@/lib/server/analysis-repository'
import { toPublicFinding } from '@/lib/server/public-data'

export const dynamic = 'force-dynamic'

export async function GET() {
  const session = await getCurrentSessionFromCookies()

  if (!session) {
    return NextResponse.json(
      { error: 'Authentication required.' },
      { status: 401 }
    )
  }

  const findings = await listAnalysisFindingsForUser(session.userId)

  return NextResponse.json({
    findings: findings.map(toPublicFinding),
  })
}