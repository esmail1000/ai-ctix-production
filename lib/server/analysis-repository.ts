import { prisma } from '@/lib/server/prisma'
import type { PipelineRun } from '@/lib/pipeline'
import type { StoredFinding, StoredReport } from '@/lib/server/types'

function safeJsonStringify(value: unknown, fallback: string) {
  try {
    return JSON.stringify(value ?? JSON.parse(fallback))
  } catch {
    return fallback
  }
}

function safeJsonParse<T>(value: string | null | undefined, fallback: T): T {
  try {
    if (!value) return fallback
    return JSON.parse(value) as T
  } catch {
    return fallback
  }
}

function toStoredReport(row: any): StoredReport {
  return {
    id: row.id,
    slug: row.slug || row.id,
    name: row.name,
    type: row.type,
    uploadedAt: row.uploadedAt,
    owner: row.owner,
    status: row.status,
    findings: row.findingCount,
    critical: row.critical,
    high: row.high,
    medium: row.medium,
    low: row.low,
    summary: row.summary || '',
    content: row.content || '',
    sourceFileName: row.sourceFileName || undefined,
    createdAtIso: row.createdAt.toISOString(),
    updatedAtIso: row.updatedAt.toISOString(),
    parsingStatus: row.parsingStatus,
    analysisVersion: row.analysisVersion,
    parserVersion: row.parserVersion ?? undefined,
    parsingNotes: safeJsonParse<string[]>(row.parsingNotesJson, []),
  }
}

function toStoredFinding(row: any): StoredFinding {
  return {
    id: row.id,
    slug: row.slug || row.id,
    reportId: row.reportId,
    reportName: row.reportName,
    title: row.title,
    cve: row.cve || '',
    severity: row.severity,
    asset: row.asset,
    score: row.score,
    status: row.status,
    detectedAt: row.detectedAt,
    summary: row.summary || '',
    impact: row.impact || '',
    evidence: row.evidence || '',
    remediation: row.remediation || '',
    history: safeJsonParse(row.historyJson, []),
    evidenceSentenceIndex: row.evidenceSentenceIndex ?? undefined,
    reported: safeJsonParse(row.reportedJson, undefined),
    normalization: safeJsonParse(row.normalizationJson, undefined),
    provenance: safeJsonParse(row.provenanceJson, undefined),
  }
}

export async function listAnalysisReportsForUser(userId: string): Promise<StoredReport[]> {
  const rows = await prisma.analysisReport.findMany({
    where: { userId },
    orderBy: { createdAt: 'desc' },
  })

  return rows.map(toStoredReport)
}

export async function listAnalysisFindingsForUser(userId: string): Promise<StoredFinding[]> {
  const rows = await prisma.analysisFinding.findMany({
    where: { userId },
    orderBy: { createdAt: 'desc' },
  })

  return rows.map(toStoredFinding)
}

export async function getAnalysisReportForUser(
  userId: string,
  reportId: string
): Promise<StoredReport | undefined> {
  const row = await prisma.analysisReport.findFirst({
    where: { id: reportId, userId },
  })

  return row ? toStoredReport(row) : undefined
}

export async function getAnalysisFindingForUser(
  userId: string,
  findingId: string
): Promise<StoredFinding | undefined> {
  const row = await prisma.analysisFinding.findFirst({
    where: { id: findingId, userId },
  })

  return row ? toStoredFinding(row) : undefined
}

export async function getAnalysisFindingsByReportIdForUser(
  userId: string,
  reportId: string
): Promise<StoredFinding[]> {
  const rows = await prisma.analysisFinding.findMany({
    where: { userId, reportId },
    orderBy: { createdAt: 'asc' },
  })

  return rows.map(toStoredFinding)
}

export async function getAnalysisReportNameForUser(
  userId: string,
  reportId: string
): Promise<string> {
  const row = await prisma.analysisReport.findFirst({
    where: { id: reportId, userId },
    select: { name: true },
  })

  return row?.name || 'Unknown Report'
}

export async function getRelatedAnalysisFindingsForUser(
  userId: string,
  findingId: string,
  limit = 3
): Promise<StoredFinding[]> {
  const current = await prisma.analysisFinding.findFirst({
    where: { id: findingId, userId },
  })

  if (!current) return []

  const rows = await prisma.analysisFinding.findMany({
    where: {
      userId,
      id: { not: findingId },
      OR: [
        { reportId: current.reportId },
        { asset: current.asset },
        { severity: current.severity },
      ],
    },
    take: limit,
    orderBy: { score: 'desc' },
  })

  return rows.map(toStoredFinding)
}

export async function createAnalysisRecord(input: {
  userId: string
  report: StoredReport
  findings: StoredFinding[]
  run: PipelineRun
}) {
  await prisma.$transaction(async (tx) => {
    await tx.analysisReport.create({
      data: {
        id: input.report.id,
        userId: input.userId,
        slug: input.report.slug,
        name: input.report.name,
        type: input.report.type,
        uploadedAt: input.report.uploadedAt,
        owner: input.report.owner,
        status: input.report.status,
        findingCount: input.report.findings ?? input.findings.length,
        critical: input.report.critical ?? 0,
        high: input.report.high ?? 0,
        medium: input.report.medium ?? 0,
        low: input.report.low ?? 0,
        summary: input.report.summary ?? '',
        content: input.report.content ?? '',
        sourceFileName: input.report.sourceFileName,
        parsingStatus: input.report.parsingStatus,
        analysisVersion: input.report.analysisVersion,
        parserVersion: input.report.parserVersion,
        parsingNotesJson: safeJsonStringify(input.report.parsingNotes ?? [], '[]'),
        createdAt: new Date(input.report.createdAtIso),
        updatedAt: new Date(input.report.updatedAtIso),
      },
    })

    for (const finding of input.findings) {
      await tx.analysisFinding.create({
        data: {
          id: finding.id,
          userId: input.userId,
          reportId: finding.reportId,
          reportName: finding.reportName,
          slug: finding.slug,
          title: finding.title,
          cve: finding.cve || '',
          severity: finding.severity,
          asset: finding.asset,
          score: finding.score ?? 0,
          status: finding.status,
          detectedAt: finding.detectedAt,
          summary: finding.summary ?? '',
          impact: finding.impact ?? '',
          evidence: finding.evidence ?? '',
          remediation: finding.remediation ?? '',
          evidenceSentenceIndex: finding.evidenceSentenceIndex,
          historyJson: safeJsonStringify(finding.history ?? [], '[]'),
          reportedJson: safeJsonStringify(finding.reported ?? {}, '{}'),
          normalizationJson: safeJsonStringify(finding.normalization ?? {}, '{}'),
          provenanceJson: safeJsonStringify(finding.provenance ?? {}, '{}'),
        },
      })
    }

    await tx.analysisRun.create({
      data: {
        userId: input.userId,
        reportId: input.report.id,
        runJson: safeJsonStringify(input.run, '{}'),
      },
    })
  })
}export async function saveAnalysisSummaryForUser(input: {
  userId: string
  reportId: string
  summary: unknown
  summaryMeta: unknown
}) {
  const existing = await prisma.analysisSummary.findFirst({
    where: {
      userId: input.userId,
      reportId: input.reportId,
    },
    orderBy: {
      generatedAt: 'desc',
    },
  })

  const data = {
    summaryJson: safeJsonStringify(input.summary, '{}'),
    summaryMetaJson: safeJsonStringify(input.summaryMeta, '{}'),
    generatedAt: new Date(),
  }

  if (existing) {
    return prisma.analysisSummary.update({
      where: { id: existing.id },
      data,
    })
  }

  return prisma.analysisSummary.create({
    data: {
      userId: input.userId,
      reportId: input.reportId,
      ...data,
    },
  })
}

export async function saveAnalysisRiskScoreForUser(input: {
  userId: string
  reportId: string
  risk: any
  riskMeta: unknown
}) {
  const existing = await prisma.analysisRiskScore.findFirst({
    where: {
      userId: input.userId,
      reportId: input.reportId,
    },
    orderBy: {
      generatedAt: 'desc',
    },
  })

  const data = {
    overallRiskScore:
      typeof input.risk?.overallRiskScore === 'number'
        ? input.risk.overallRiskScore
        : null,
    overallRiskBand:
      typeof input.risk?.overallRiskBand === 'string'
        ? input.risk.overallRiskBand
        : null,
    riskJson: safeJsonStringify(input.risk, '{}'),
    riskMetaJson: safeJsonStringify(input.riskMeta, '{}'),
    generatedAt: new Date(),
  }

  if (existing) {
    return prisma.analysisRiskScore.update({
      where: { id: existing.id },
      data,
    })
  }

  return prisma.analysisRiskScore.create({
    data: {
      userId: input.userId,
      reportId: input.reportId,
      ...data,
    },
  })
}