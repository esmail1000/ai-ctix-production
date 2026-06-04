import { NextResponse } from 'next/server'
import { getCurrentSessionFromCookies } from '@/lib/server/current-session'
import {
  listAnalysisFindingsForUser,
  listAnalysisReportsForUser,
} from '@/lib/server/analysis-repository'
import { prisma } from '@/lib/server/prisma'

export const dynamic = 'force-dynamic'

function safeJsonParse<T>(value: string | null | undefined, fallback: T): T {
  try {
    if (!value) return fallback
    return JSON.parse(value) as T
  } catch {
    return fallback
  }
}

export async function GET() {
  const session = await getCurrentSessionFromCookies()

  if (!session) {
    return NextResponse.json(
      { error: 'Authentication required.' },
      { status: 401 }
    )
  }

  const [reports, findings, runs, summaries, riskScores] = await Promise.all([
    listAnalysisReportsForUser(session.userId),
    listAnalysisFindingsForUser(session.userId),

    prisma.analysisRun.findMany({
      where: { userId: session.userId },
      orderBy: { createdAt: 'desc' },
    }),

    prisma.analysisSummary.findMany({
      where: { userId: session.userId },
      orderBy: { generatedAt: 'desc' },
    }),

    prisma.analysisRiskScore.findMany({
      where: { userId: session.userId },
      orderBy: { generatedAt: 'desc' },
    }),
  ])

  return NextResponse.json({
    version: 1,
    initializedAtIso: new Date().toISOString(),
    user: {
      id: session.userId,
      username: session.username,
    },
    reports,
    findings,
    runs: runs.map((item) => ({
      reportId: item.reportId,
      run: safeJsonParse(item.runJson, {}),
      createdAtIso: item.createdAt.toISOString(),
    })),
    summaries: summaries.map((item) => ({
      id: item.id,
      reportId: item.reportId,
      summary: safeJsonParse(item.summaryJson, {}),
      summaryMeta: safeJsonParse(item.summaryMetaJson, {}),
      generatedAtIso: item.generatedAt.toISOString(),
      updatedAtIso: item.updatedAt.toISOString(),
    })),
    riskScores: riskScores.map((item) => ({
      id: item.id,
      reportId: item.reportId,
      overallRiskScore: item.overallRiskScore,
      overallRiskBand: item.overallRiskBand,
      risk: safeJsonParse(item.riskJson, {}),
      riskMeta: safeJsonParse(item.riskMetaJson, {}),
      generatedAtIso: item.generatedAt.toISOString(),
      updatedAtIso: item.updatedAt.toISOString(),
    })),
  })
}