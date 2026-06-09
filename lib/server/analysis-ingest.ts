import { buildAnalysisReport } from '@/lib/server/analysis-build'
import { createAnalysisRecord } from '@/lib/server/analysis-repository'
import type { StoredReport } from '@/lib/server/types'
import { randomBytes } from 'crypto'

function createAnalysisReportId(): string {
  const timestamp = Date.now().toString(36).toUpperCase()
  const nonce = randomBytes(3).toString('hex').toUpperCase()

  return `R-${timestamp}-${nonce}`
}

export async function ingestAnalysisReport(params: {
  userId: string
  name: string
  type: StoredReport['type']
  content: string
  sourceFileName?: string
}) {
  const reportId = createAnalysisReportId()

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
