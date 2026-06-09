// app/api/llm-threat-analysis/[reportId]/route.ts

import { getAnalysisReportForUser } from '@/lib/server/analysis-repository'
import { getCurrentSessionFromCookies } from '@/lib/server/current-session'
import { generateThreatScenarios } from '@/lib/server/llm-analysis/threat-scenarios'
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

    const result = await generateThreatScenarios(
      session.userId,
      normalizedReportId
    )

    return NextResponse.json(result)
  } catch (error) {
    console.error('LLM threat analysis failed:', error)

    return NextResponse.json(
      {
        error: 'LLM threat analysis failed',
        details: error instanceof Error ? error.message : String(error),
      },
      { status: 500 }
    )
  }
}
