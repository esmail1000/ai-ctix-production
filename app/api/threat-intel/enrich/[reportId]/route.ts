import { getAnalysisReportForUser } from '@/lib/server/analysis-repository'
import { getCurrentSessionFromCookies } from '@/lib/server/current-session'
import { enrichReportThreatIntel } from '@/lib/server/threat-intel/enrich-report'
import { NextResponse } from 'next/server'

export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

function extractCvesFromOwnedReport(value: unknown) {
  const text =
    JSON.stringify(value ?? '', (_key, item) =>
      typeof item === 'bigint' ? item.toString() : item
    ) ?? ''
  const matches = text.match(/CVE-\d{4}-\d{4,}/gi) ?? []
  return Array.from(new Set(matches.map((item) => item.toUpperCase()))).sort()
}

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

    const result = await enrichReportThreatIntel(normalizedReportId, {
      userId: session.userId,
      fallbackCves: extractCvesFromOwnedReport(report),
    })

    return NextResponse.json(result)
  } catch (error) {
    console.error('Threat intel enrichment failed:', error)

    return NextResponse.json(
      {
        error: 'Threat intel enrichment failed',
        details: error instanceof Error ? error.message : String(error),
      },
      { status: 500 }
    )
  }
}

export async function POST(
  request: Request,
  context: { params: Promise<{ reportId: string }> }
) {
  return GET(request, context)
}
