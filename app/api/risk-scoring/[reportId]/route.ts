import { generateReportRisk } from '@/lib/server/ai-risk-scoring'
import { generateReportSummary } from '@/lib/server/ai-summarization'
import {
  getAnalysisFindingsByReportIdForUser,
  getAnalysisReportForUser,
  getLatestAnalysisRiskScoreForUser,
  getLatestAnalysisSummaryForUser,
  saveAnalysisRiskScoreForUser,
  saveAnalysisSummaryForUser,
} from '@/lib/server/analysis-repository'
import { getCurrentSessionFromCookies } from '@/lib/server/current-session'
import type { ReportRiskResult } from '@/lib/server/risk-scoring'
import type { ReportSummaryResult } from '@/lib/server/summarization'
import type { StoredReport } from '@/lib/server/types'
import { getReportThreatIntel } from '@/lib/server/threat-intel/read-report-intel'
import { NextResponse } from 'next/server'

export const dynamic = 'force-dynamic'

type RouteContext = {
  params: Promise<{
    reportId: string
  }>
}

type PublicRiskStatus = 'cached' | 'generated' | 'missing'

type LoadedScope = {
  userId: string
  reportId: string
  report: StoredReport
}

function normalizeReportId(value: string | undefined): string {
  return String(value ?? '').trim()
}

function reportPayload(report: StoredReport) {
  return {
    id: report.id,
    name: report.name,
    type: report.type,
    uploadedAt: report.uploadedAt,
    status: report.status,
    parsingStatus: report.parsingStatus,
    parserVersion: report.parserVersion ?? null,
    parsingNotes: report.parsingNotes ?? [],
  }
}

function publicSummary(summary: ReportSummaryResult) {
  return {
    confidence: summary.confidence,
    grounding: summary.grounding,
    executiveSummary: summary.executiveSummary,
    severityOverview: summary.severityOverview,
    topRisks: summary.topRisks,
    stats: summary.stats,
  }
}

function buildSummaryMeta(summary: ReportSummaryResult) {
  return {
    generatedAtIso: summary.generatedAtIso,
    confidence: summary.confidence,
    grounding: summary.grounding,
    totalFindings: summary.stats.totalFindings,
    openFindings: summary.stats.openCount,
    distinctAssets: summary.stats.distinctAssets,
  }
}

function buildRiskMeta(risk: ReportRiskResult) {
  return {
    generatedAtIso: risk.generatedAtIso,
    overallRiskScore: risk.overallRiskScore,
    overallRiskBand: risk.overallRiskBand,
    totalFindings: risk.stats.totalFindings,
    openFindings: risk.stats.openFindings,
    findingsWithCve: risk.stats.findingsWithCve,
    distinctAssets: risk.stats.distinctAssets,
    knownExploitedFindings: risk.stats.knownExploitedFindings ?? 0,
    riskModelVersion: risk.allFindings[0]?.riskModelVersion ?? null,
  }
}

async function loadScope(context: RouteContext): Promise<
  | { ok: true; scope: LoadedScope }
  | { ok: false; response: NextResponse }
> {
  const session = await getCurrentSessionFromCookies()

  if (!session) {
    return {
      ok: false,
      response: NextResponse.json(
        { error: 'Authentication required.' },
        { status: 401 }
      ),
    }
  }

  const { reportId } = await context.params
  const normalizedReportId = normalizeReportId(reportId)

  if (!normalizedReportId) {
    return {
      ok: false,
      response: NextResponse.json(
        { error: 'Missing reportId parameter.' },
        { status: 400 }
      ),
    }
  }

  const report = await getAnalysisReportForUser(
    session.userId,
    normalizedReportId
  )

  if (!report) {
    return {
      ok: false,
      response: NextResponse.json(
        { error: `Report "${normalizedReportId}" was not found.` },
        { status: 404 }
      ),
    }
  }

  return {
    ok: true,
    scope: {
      userId: session.userId,
      reportId: normalizedReportId,
      report,
    },
  }
}

function riskResponse(input: {
  status: PublicRiskStatus
  report: StoredReport
  summary: ReportSummaryResult | null
  risk: ReportRiskResult | null
  message?: string
}) {
  return NextResponse.json({
    status: input.status,
    canGenerate: true,
    message: input.message ?? null,
    report: reportPayload(input.report),
    summary: input.summary ? publicSummary(input.summary) : null,
    risk: input.risk,
    riskMeta: input.risk ? buildRiskMeta(input.risk) : null,
  })
}

export async function GET(_request: Request, context: RouteContext) {
  try {
    const loaded = await loadScope(context)
    if (!loaded.ok) return loaded.response

    const { userId, reportId, report } = loaded.scope

    const [latestSummary, latestRisk] = await Promise.all([
      getLatestAnalysisSummaryForUser(userId, reportId),
      getLatestAnalysisRiskScoreForUser(userId, reportId),
    ])

    if (!latestSummary || !latestRisk) {
      return riskResponse({
        status: 'missing',
        report,
        summary: latestSummary?.summary ?? null,
        risk: latestRisk?.risk ?? null,
        message:
          'No saved risk score exists for this report yet. Use POST/regenerate to calculate and save one.',
      })
    }

    return riskResponse({
      status: 'cached',
      report,
      summary: latestSummary.summary,
      risk: latestRisk.risk,
    })
  } catch (error) {
    return NextResponse.json(
      {
        error:
          error instanceof Error
            ? error.message
            : 'Failed to load saved risk scoring result.',
      },
      { status: 500 }
    )
  }
}

export async function POST(_request: Request, context: RouteContext) {
  try {
    const loaded = await loadScope(context)
    if (!loaded.ok) return loaded.response

    const { userId, reportId, report } = loaded.scope

    const findings = await getAnalysisFindingsByReportIdForUser(userId, reportId)
    const summary = await generateReportSummary(report, findings)

    let threatIntel: any = null
    try {
      threatIntel = await getReportThreatIntel(reportId)
    } catch (intelError) {
      threatIntel = {
        reportId,
        cveCount: 0,
        cves: [],
        error:
          intelError instanceof Error
            ? intelError.message
            : 'Threat intelligence was unavailable during risk scoring.',
      }
    }

    const risk = await generateReportRisk(report, findings, summary, {
      threatIntel,
    })

    await saveAnalysisSummaryForUser({
      userId,
      reportId,
      summary,
      summaryMeta: buildSummaryMeta(summary),
    })

    await saveAnalysisRiskScoreForUser({
      userId,
      reportId,
      risk,
      riskMeta: buildRiskMeta(risk),
    })

    return riskResponse({
      status: 'generated',
      report,
      summary,
      risk,
    })
  } catch (error) {
    return NextResponse.json(
      {
        error:
          error instanceof Error
            ? error.message
            : 'Failed to generate risk scoring result.',
      },
      { status: 500 }
    )
  }
}
