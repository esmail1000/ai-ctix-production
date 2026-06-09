import { type Severity } from '@/lib/mock-data'
import { analyzeContent } from '@/lib/server/analysis-engine'
import { createAnalysisRecord } from '@/lib/server/analysis-repository'
import { mapNlpResultToFindings } from '@/lib/server/nlp/nlp-adapter'
import { runNlpEngine } from '@/lib/server/nlp/nlp-client'
import { prisma } from '@/lib/server/prisma'
import type { StoredFinding, StoredReport } from '@/lib/server/types'

function nowIso() {
  return new Date().toISOString()
}

function countFindingsBySeverity(
  findings: StoredFinding[],
  severity: Severity
): number {
  return findings.filter((finding) => finding.severity === severity).length
}

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

function refreshReportCounts<T extends Pick<StoredReport, 'findings' | 'critical' | 'high' | 'medium' | 'low' | 'status'>>(
  report: T,
  findings: StoredFinding[]
): T {
  return {
    ...report,
    findings: findings.length,
    critical: countFindingsBySeverity(findings, 'Critical'),
    high: countFindingsBySeverity(findings, 'High'),
    medium: countFindingsBySeverity(findings, 'Medium'),
    low: countFindingsBySeverity(findings, 'Low'),
    status: findings.length > 0 ? 'Ready' : 'Pending',
  }
}

function isNlpResultUsable(params: {
  nlpFindings: StoredFinding[]
  nlpError?: string
}): boolean {
  return !params.nlpError && params.nlpFindings.length > 0
}

export async function ingestAnalysisReport(params: {
  userId: string
  name: string
  type: StoredReport['type']
  content: string
  sourceFileName?: string
}) {
  const reportId = await getNextAnalysisReportId()
  const uploadedAt = nowIso()

  let { pipeline, report, findings } = analyzeContent({
    reportId,
    reportName: params.name,
    uploadedAt,
    input: params.content,
    sourceType: params.type,
  })

  const heuristicFindings = findings

  if (process.env.ENABLE_NLP === 'true') {
    const nlpResult = await runNlpEngine(params.content, {
      mode: 'auto',
      timeoutMs: 30_000,
    })

    const nlpFindings = mapNlpResultToFindings({
      result: nlpResult,
      reportId,
      reportName: params.name,
      uploadedAt,
      input: params.content,
      startingIndex: 0,
    })

    const nlpError = nlpResult.meta?.error
    const useNlpOnly = isNlpResultUsable({ nlpFindings, nlpError })

    if (useNlpOnly) {
      findings = nlpFindings
      report = refreshReportCounts(report, findings)
      report = {
        ...report,
        parsingNotes: [
          ...(report.parsingNotes ?? []),
          `NLP hybrid extraction produced ${nlpFindings.length} finding(s). Heuristic fallback output was suppressed to avoid duplicate findings.`,
          ...(nlpResult.meta?.warnings ?? []).map(
            (warning) => `NLP warning: ${warning}`
          ),
        ],
      }
    } else {
      findings = heuristicFindings
      report = refreshReportCounts(report, findings)
      report = {
        ...report,
        parsingNotes: [
          ...(report.parsingNotes ?? []),
          nlpError
            ? `NLP hybrid extraction failed: ${nlpError}. Used heuristic fallback findings.`
            : 'NLP hybrid extraction returned no usable findings. Used heuristic fallback findings.',
          ...(nlpResult.meta?.warnings ?? []).map(
            (warning) => `NLP warning: ${warning}`
          ),
        ],
      }
    }
  } else {
    report = refreshReportCounts(report, findings)
    report = {
      ...report,
      parsingNotes: [
        ...(report.parsingNotes ?? []),
        'NLP hybrid extraction skipped. Set ENABLE_NLP=true to enable model-based extraction.',
      ],
    }
  }

  const timestamp = nowIso()

  const normalizedFindings: StoredFinding[] = findings.map((finding) => ({
    ...finding,
    reportId,
    reportName: params.name,
    detectedAt: finding.detectedAt || uploadedAt,
  }))

  const storedReport: StoredReport = {
    ...report,
    content: params.content,
    sourceFileName: params.sourceFileName,
    createdAtIso: timestamp,
    updatedAtIso: timestamp,
    parserVersion: report.parserVersion ?? 1,
    parsingNotes: report.parsingNotes ?? [],
  }

  await createAnalysisRecord({
    userId: params.userId,
    report: storedReport,
    findings: normalizedFindings,
    run: pipeline,
  })

  return {
    report: storedReport,
    findings: normalizedFindings,
    run: pipeline,
  }
}
