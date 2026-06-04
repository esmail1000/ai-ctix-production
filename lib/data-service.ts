import type { Finding, Report } from './mock-data'
import { getCurrentSessionFromCookies } from '@/lib/server/current-session'
import {
  getAnalysisFindingForUser,
  getAnalysisFindingsByReportIdForUser,
  getAnalysisReportForUser,
  getAnalysisReportNameForUser,
  getRelatedAnalysisFindingsForUser,
  listAnalysisFindingsForUser,
  listAnalysisReportsForUser,
} from '@/lib/server/analysis-repository'
import { toPublicFinding, toPublicReport } from '@/lib/server/public-data'
import type { StoredFinding, StoredReport } from '@/lib/server/types'

export type DashboardMetrics = {
  reportsProcessed: number
  totalFindings: number
  criticalFindings: number
  avgRiskScore: number
}

async function getCurrentUserId(): Promise<string | null> {
  const session = await getCurrentSessionFromCookies()
  return session?.userId ?? null
}

async function getStoredReportsForCurrentUser(): Promise<StoredReport[]> {
  const userId = await getCurrentUserId()
  if (!userId) return []

  return listAnalysisReportsForUser(userId)
}

async function getStoredFindingsForCurrentUser(): Promise<StoredFinding[]> {
  const userId = await getCurrentUserId()
  if (!userId) return []

  return listAnalysisFindingsForUser(userId)
}

export async function getReports(): Promise<Report[]> {
  const reports = await getStoredReportsForCurrentUser()
  return reports.map(toPublicReport)
}

export async function getReportById(id: string): Promise<Report | undefined> {
  const userId = await getCurrentUserId()
  if (!userId) return undefined

  const report = await getAnalysisReportForUser(userId, id)
  return report ? toPublicReport(report) : undefined
}

export async function getFindings(): Promise<Finding[]> {
  const findings = await getStoredFindingsForCurrentUser()
  return findings.map(toPublicFinding)
}

export async function getFindingById(id: string): Promise<Finding | undefined> {
  const userId = await getCurrentUserId()
  if (!userId) return undefined

  const finding = await getAnalysisFindingForUser(userId, id)
  return finding ? toPublicFinding(finding) : undefined
}

export async function getFindingsByReportId(reportId: string): Promise<Finding[]> {
  const userId = await getCurrentUserId()
  if (!userId) return []

  const findings = await getAnalysisFindingsByReportIdForUser(userId, reportId)
  return findings.map(toPublicFinding)
}

export async function getRelatedFindings(
  findingId: string,
  limit = 3
): Promise<Finding[]> {
  const userId = await getCurrentUserId()
  if (!userId) return []

  const findings = await getRelatedAnalysisFindingsForUser(userId, findingId, limit)
  return findings.map(toPublicFinding)
}

export async function getReportName(reportId: string): Promise<string> {
  const userId = await getCurrentUserId()
  if (!userId) return 'Unknown Report'

  return getAnalysisReportNameForUser(userId, reportId)
}

export async function getSeverityBreakdown() {
  const findings = await getFindings()

  const base: Record<Finding['severity'], number> = {
    Critical: 0,
    High: 0,
    Medium: 0,
    Low: 0,
  }

  for (const finding of findings) {
    base[finding.severity] += 1
  }

  return Object.entries(base).map(([name, count]) => ({
    name: name as Finding['severity'],
    count,
  }))
}

export async function getTopAffectedAssets(limit = 5) {
  const counters = new Map<string, { name: string; count: number }>()

  for (const finding of await getFindings()) {
    const name = String(finding.asset || '').trim() || 'investigation-scope'
    const key = name.toLowerCase()

    const current = counters.get(key) ?? {
      name,
      count: 0,
    }

    current.count += 1
    counters.set(key, current)
  }

  return Array.from(counters.values())
    .sort((a, b) => b.count - a.count)
    .slice(0, limit)
    .map((item) => ({
      name: item.name,
      count: item.count,
      status: item.count >= 2 ? 'needs review' : 'monitoring',
    }))
}

export async function getDashboardMetrics(): Promise<DashboardMetrics> {
  const reports = await getReports()
  const findings = await getFindings()
  const totalFindings = findings.length

  const criticalFindings = findings.filter(
    (finding) => finding.severity === 'Critical'
  ).length

  const avgRiskScore =
    totalFindings === 0
      ? 0
      : Math.round(
          findings.reduce((sum, finding) => sum + (finding.score ?? 0), 0) /
            totalFindings
        )

  return {
    reportsProcessed: reports.length,
    totalFindings,
    criticalFindings,
    avgRiskScore,
  }
}

export async function getFindingsTrend() {
  const findings = await getFindings()
  const byDay = new Map<string, { findings: number; critical: number }>()

  for (const item of findings) {
    const day = item.detectedAt
    const entry = byDay.get(day) ?? { findings: 0, critical: 0 }

    entry.findings += 1
    if (item.severity === 'Critical') entry.critical += 1

    byDay.set(day, entry)
  }

  return Array.from(byDay.entries())
    .sort((a, b) => a[0].localeCompare(b[0]))
    .slice(-7)
    .map(([day, values]) => ({
      day: day.slice(5),
      ...values,
    }))
}