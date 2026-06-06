import { buildAnalysisReport } from '@/lib/server/analysis-build'
import { createAnalysisRecord } from '@/lib/server/analysis-repository'
import { prisma } from '@/lib/server/prisma'
import type { StoredReport } from '@/lib/server/types'

function extractReportNumber(reportId: string): number {
  const match = /^R-(\d+)$/.exec(reportId)
  return match ? Number(match[1]) || 0 : 0
}

async function getNextAnalysisReportId(): Promise<string> {
  const reports = await prisma.analysisReport.findMany({
    select: { id: true },
  })

  const nextNumber =
    reports.reduce(
      (max, report) => Math.max(max, extractReportNumber(report.id)),
      0
    ) + 1

  return `R-${String(nextNumber).padStart(3, '0')}`
}

export async function ingestAnalysisReport(params: {
  userId: string
  name: string
  type: StoredReport['type']
  content: string
  sourceFileName?: string
}) {
  const reportId = await getNextAnalysisReportId()

  const result = await buildAnalysisReport({
    reportId,
    name: params.name,
    type: params.type,
    content: params.content,
    sourceFileName: params.sourceFileName,
  })

  await createAnalysisRecord({
    userId: params.userId,
    report: result.report,
    findings: result.findings,
    run: result.run,
  })

  return result
}
