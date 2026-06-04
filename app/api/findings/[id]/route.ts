import { getCurrentSessionFromCookies } from '@/lib/server/current-session'
import { getAnalysisFindingForUser } from '@/lib/server/analysis-repository'
import { toPublicFinding } from '@/lib/server/public-data'
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
  const finding = await getAnalysisFindingForUser(session.userId, id)

  if (!finding) {
    return NextResponse.json({ error: 'Finding not found.' }, { status: 404 })
  }

  return NextResponse.json({ finding: toPublicFinding(finding) })
}