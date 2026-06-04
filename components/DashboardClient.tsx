// components/DashboardClient.tsx
'use client'

import { Badge, EmptyState, SeverityBadge, StatusBadge } from '@/components/ui'
import type { DashboardMetrics } from '@/lib/data-service'
import type { Finding, Report, Severity } from '@/lib/mock-data'
import {
  formatExtractionMethod,
  getWorkspaceQualityMetrics,
  needsHumanReview,
} from '@/lib/ui-quality'
import Link from 'next/link'
import type { ReactNode } from 'react'
import { useMemo } from 'react'
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'

const severityWeight: Record<Severity, number> = {
  Critical: 4,
  High: 3,
  Medium: 2,
  Low: 1,
}

const severityOrder: Severity[] = ['Critical', 'High', 'Medium', 'Low']

const severityChartColors: Record<Severity, string> = {
  Critical: '#dc2626',
  High: '#f97316',
  Medium: '#eab308',
  Low: '#16a34a',
}

type Tone = 'neutral' | 'success' | 'warning' | 'danger' | 'info'

type CountItem = {
  id: string
  value: string
  count: number
}

function average(values: number[]) {
  if (values.length === 0) return 0
  return Math.round(values.reduce((sum, value) => sum + value, 0) / values.length)
}

function percent(part: number, total: number) {
  if (total === 0) return 0
  return Math.round((part / total) * 100)
}

function clamp(value: number, min = 0, max = 100) {
  return Math.max(min, Math.min(max, value))
}

function safeKey(value: unknown, fallback: string) {
  if (value === null || value === undefined || value === '') return fallback
  return String(value).replace(/\s+/g, '-').toLowerCase()
}

function dedupeFindings(findings: Finding[]) {
  const bestByKey = new Map<string, Finding>()

  findings.forEach((finding, index) => {
    const key = [
      finding.slug || finding.id || `finding-${index}`,
      finding.asset || 'unknown-asset',
      finding.severity || 'unknown-severity',
      finding.reportId || 'unknown-report',
    ].join(':')

    const existing = bestByKey.get(key)

    if (!existing || finding.score > existing.score) {
      bestByKey.set(key, finding)
    }
  })

  return Array.from(bestByKey.values())
}

function riskTone(score: number): Exclude<Tone, 'neutral'> {
  if (score >= 80) return 'danger'
  if (score >= 60) return 'warning'
  if (score >= 40) return 'info'
  return 'success'
}

function postureLabel(score: number) {
  if (score >= 85) return 'Excellent'
  if (score >= 70) return 'Good'
  if (score >= 55) return 'Watchlist'
  return 'Needs attention'
}

function methodTone(method: string): 'warning' | 'success' | 'neutral' {
  if (method === 'heuristic-fallback') return 'warning'
  if (method === 'nlp-hybrid' || method === 'structured-parser') return 'success'
  return 'neutral'
}

function shortDate(value: string) {
  try {
    return new Intl.DateTimeFormat('en', {
      month: 'short',
      day: 'numeric',
    }).format(new Date(value))
  } catch {
    return value
  }
}

function findingText(finding: Finding) {
  const extra = finding as Finding & {
    summary?: string
    impact?: string
    evidence?: string
    remediation?: string
    cve?: string
  }

  return [
    finding.title,
    finding.asset,
    extra.summary,
    extra.impact,
    extra.evidence,
    extra.remediation,
    extra.cve,
  ]
    .filter(Boolean)
    .join(' ')
}

function countValues(values: string[], limit = 6): CountItem[] {
  const counters = new Map<string, number>()

  values.forEach((value) => {
    const cleaned = value.trim()
    if (!cleaned) return
    counters.set(cleaned, (counters.get(cleaned) ?? 0) + 1)
  })

  return Array.from(counters.entries())
    .map(([value, count], index) => ({
      id: `${safeKey(value, 'item')}-${index}`,
      value,
      count,
    }))
    .sort((a, b) => b.count - a.count || a.value.localeCompare(b.value))
    .slice(0, limit)
}

function extractIpsFromText(text: string) {
  return Array.from(new Set(text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) ?? [])).filter((ip) =>
    ip.split('.').every((part) => {
      const value = Number(part)
      return Number.isInteger(value) && value >= 0 && value <= 255
    })
  )
}

function extractDomainsFromText(text: string) {
  const normalized = text.replace(/\[\.\]/g, '.').replace(/\(\.\)/g, '.')
  return Array.from(
    new Set(normalized.match(/\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b/gi) ?? [])
  ).filter((domain) => !domain.match(/^\d+(?:\.\d+){3}$/))
}

function extractHashesFromText(text: string) {
  return Array.from(
    new Set(text.match(/\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b/gi) ?? [])
  )
}

function extractMitreFromText(text: string) {
  return Array.from(new Set(text.match(/\bT\d{4}(?:\.\d{3})?\b/g) ?? []))
}

function extractCvesFromFinding(finding: Finding) {
  const extra = finding as Finding & { cve?: string }
  const text = findingText(finding)

  return Array.from(
    new Set([
      ...(extra.cve ? [extra.cve] : []),
      ...(text.match(/\bCVE-\d{4}-\d{4,7}\b/gi) ?? []),
    ])
  )
}

export default function DashboardClient({
  kpis,
  findingsTrend,
  findings,
  reports,
}: {
  kpis: DashboardMetrics
  findingsTrend: Array<{ day: string; findings: number; critical: number }>
  findings: Finding[]
  reports: Report[]
}) {
  const data = useMemo(() => {
    const uniqueFindings = dedupeFindings(findings)

    const open = uniqueFindings.filter((finding) => finding.status === 'Open')
    const inReview = uniqueFindings.filter((finding) => finding.status === 'In Review')
    const resolved = uniqueFindings.filter((finding) => finding.status === 'Resolved')
    const unresolved = uniqueFindings.filter((finding) => finding.status !== 'Resolved')

    const criticalHighOpen = unresolved.filter(
      (finding) => finding.severity === 'Critical' || finding.severity === 'High'
    )

    const avgRisk = average(uniqueFindings.map((finding) => finding.score))
    const quality = getWorkspaceQualityMetrics(uniqueFindings, reports)

    const posturePenalty =
      avgRisk * 0.45 +
      Math.min(criticalHighOpen.length, 20) * 1.4 +
      Math.min(quality.needsReviewCount, 30) * 0.6

    const postureScore = clamp(Math.round(100 - posturePenalty))

    const severityDistribution = severityOrder.map((severity, index) => ({
      id: `${safeKey(severity, 'severity')}-${index}`,
      severity,
      count: uniqueFindings.filter((finding) => finding.severity === severity).length,
    }))

    const methodDistribution = Array.from(
      uniqueFindings.reduce((map, finding) => {
        const method = finding.provenance?.extractionMethod ?? 'unknown'
        map.set(method, (map.get(method) ?? 0) + 1)
        return map
      }, new Map<string, number>())
    )
      .map(([method, count], index) => ({
        id: `${safeKey(method, 'method')}-${index}`,
        method,
        label: formatExtractionMethod(method),
        count,
      }))
      .sort((a, b) => b.count - a.count)

    const assetBoard = Array.from(
      uniqueFindings
        .reduce((map, finding) => {
          const assetName = finding.asset || 'Unknown asset'

          const item = map.get(assetName) ?? {
            asset: assetName,
            findings: 0,
            open: 0,
            maxRisk: 0,
            totalRisk: 0,
            worstSeverity: finding.severity,
          }

          item.findings += 1
          item.totalRisk += finding.score
          item.maxRisk = Math.max(item.maxRisk, finding.score)

          if (finding.status !== 'Resolved') {
            item.open += 1
          }

          if (severityWeight[finding.severity] > severityWeight[item.worstSeverity]) {
            item.worstSeverity = finding.severity
          }

          map.set(assetName, item)
          return map
        }, new Map<string, { asset: string; findings: number; open: number; maxRisk: number; totalRisk: number; worstSeverity: Severity }>())
        .values()
    )
      .map((asset, index) => ({
        id: `${safeKey(asset.asset, 'asset')}-${index}`,
        ...asset,
        avgRisk: Math.round(asset.totalRisk / asset.findings),
      }))
      .sort((a, b) => b.open - a.open || b.maxRisk - a.maxRisk)
      .slice(0, 5)

    const priorityFindings = [...unresolved]
      .sort(
        (a, b) =>
          severityWeight[b.severity] - severityWeight[a.severity] ||
          b.score - a.score ||
          b.detectedAt.localeCompare(a.detectedAt)
      )
      .slice(0, 5)
      .map((finding, index) => ({
        ...finding,
        dashboardKey: `${safeKey(finding.id, 'finding')}-${safeKey(finding.reportId, 'report')}-${index}`,
      }))

    const recentReports = [...reports]
      .sort((a, b) => b.uploadedAt.localeCompare(a.uploadedAt))
      .slice(0, 5)
      .map((report, index) => ({
        ...report,
        dashboardKey: `${safeKey(report.id, 'report')}-${index}`,
      }))

    const reportNameMap = new Map(reports.map((report) => [report.id, report.name]))
    const allFindingText = uniqueFindings.map(findingText).join(' ')

    const topIps = countValues(uniqueFindings.flatMap((finding) => extractIpsFromText(findingText(finding))), 6)
    const topDomains = countValues(uniqueFindings.flatMap((finding) => extractDomainsFromText(findingText(finding))), 6)
    const topHashes = countValues(uniqueFindings.flatMap((finding) => extractHashesFromText(findingText(finding))), 6)
    const topMitre = countValues(extractMitreFromText(allFindingText), 6)
    const topCves = countValues(uniqueFindings.flatMap(extractCvesFromFinding), 6)

    const readyForExport = reports.filter((report) => {
      const reportFindings = uniqueFindings.filter((finding) => finding.reportId === report.id)
      return reportFindings.length > 0 && reportFindings.every((finding) => !needsHumanReview(finding))
    })

    return {
      uniqueFindings,
      open,
      inReview,
      resolved,
      unresolved,
      criticalHighOpen,
      avgRisk,
      postureScore,
      quality,
      severityDistribution,
      methodDistribution,
      assetBoard,
      priorityFindings,
      recentReports,
      reportNameMap,
      readyForExport,
      topIps,
      topDomains,
      topHashes,
      topMitre,
      topCves,
    }
  }, [findings, reports])

  const totalFindings = data.uniqueFindings.length
  const reviewedCount = data.inReview.length + data.resolved.length
  const avgRiskScore = kpis.avgRiskScore || data.avgRisk
  const criticalFindings =
    kpis.criticalFindings ||
    data.uniqueFindings.filter((finding) => finding.severity === 'Critical').length

  return (
    <main className="relative min-h-screen overflow-hidden bg-[#fbfefd] text-[#111827]">
      <style>{`
        @keyframes dashboard-orbit-spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        @keyframes dashboard-logo-float { 0%, 100% { transform: translateY(0) rotate(0deg); } 50% { transform: translateY(-12px) rotate(2deg); } }
        .dashboard-orbit { animation: dashboard-orbit-spin 15s linear infinite; }
        .dashboard-orbit > div:first-child { animation: dashboard-logo-float 6s ease-in-out infinite; }
        .dashboard-platform { transform: perspective(800px) rotateX(58deg); }
      `}</style>

      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_18%_10%,rgba(34,197,94,0.10),transparent_30%),radial-gradient(circle_at_86%_18%,rgba(8,122,58,0.08),transparent_34%)]" />
      <div className="pointer-events-none absolute right-0 top-24 h-[420px] w-[560px] rounded-full bg-[#dcf7e7]/60 blur-3xl" />
      <div className="pointer-events-none absolute left-0 top-[560px] h-[320px] w-[520px] rounded-full bg-[#eefaf3] blur-3xl" />

      <section className="relative mx-auto max-w-[1480px] px-6 pb-16 pt-10 lg:px-8">
        <div>
            <header className="relative mb-6 overflow-hidden rounded-[34px] border border-[#dceee3] bg-white/92 p-7 shadow-[0_24px_80px_rgba(15,43,29,0.07)] backdrop-blur">
              <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(135deg,rgba(8,122,58,0.05),transparent_42%),radial-gradient(circle_at_86%_24%,rgba(22,163,74,0.12),transparent_28%)]" />
              <div className="pointer-events-none absolute right-[190px] bottom-8 h-20 w-52 rounded-[50%] border border-[#bfe6cc] bg-gradient-to-b from-white to-[#e5f8ec] shadow-[0_24px_60px_rgba(8,122,58,0.12)] dashboard-platform" />
              <div className="pointer-events-none absolute right-24 top-12 h-28 w-28 rounded-full border border-[#c7efd4] bg-white/70 shadow-[0_22px_55px_rgba(8,122,58,0.12)] dashboard-orbit">
                <div className="absolute left-1/2 top-1/2 h-14 w-14 -translate-x-1/2 -translate-y-1/2 rounded-full bg-gradient-to-br from-[#dff7e8] to-[#087a3a] shadow-[0_18px_45px_rgba(8,122,58,0.18)]" />
                <div className="absolute left-1/2 top-1/2 h-5 w-5 -translate-x-1/2 -translate-y-[58px] rounded-full bg-[#087a3a] shadow-[0_12px_28px_rgba(8,122,58,0.20)]" />
              </div>

              <div className="relative grid gap-8 lg:grid-cols-[1fr_0.72fr]">
                <div>
                  <p className="text-xs font-semibold uppercase tracking-[0.22em] text-[#087a3a]">
                    Command Dashboard
                  </p>
                  <h1 className="mt-4 max-w-4xl text-4xl font-semibold tracking-[-0.04em] text-[#111827] md:text-5xl">
                    Security operations overview
                  </h1>
                  <p className="mt-4 max-w-3xl text-base leading-8 text-[#5f6f66]">
                    Executive view for reports, extracted findings, risk posture, affected assets, and intelligence indicators.
                  </p>

                  <div className="mt-7 flex flex-wrap gap-3">
                    <Link
                      href="/analyzer"
                      className="rounded-2xl bg-[#087a3a] px-5 py-3 text-sm font-semibold text-white shadow-[0_16px_32px_rgba(8,122,58,0.18)] transition hover:-translate-y-0.5 hover:bg-[#066b33]"
                    >
                      Analyze Report
                    </Link>
                    <Link
                      href="/reports"
                      className="rounded-2xl border border-[#c4e3cf] bg-white px-5 py-3 text-sm font-semibold text-[#173128] transition hover:-translate-y-0.5 hover:bg-[#f4fff7]"
                    >
                      Reports
                    </Link>
                    <Link
                      href="/results"
                      className="rounded-2xl border border-[#c4e3cf] bg-white px-5 py-3 text-sm font-semibold text-[#173128] transition hover:-translate-y-0.5 hover:bg-[#f4fff7]"
                    >
                      Findings
                    </Link>
                    <Link
                      href="/export"
                      className="rounded-2xl border border-[#c4e3cf] bg-white px-5 py-3 text-sm font-semibold text-[#173128] transition hover:-translate-y-0.5 hover:bg-[#f4fff7]"
                    >
                      Export
                    </Link>
                  </div>
                </div>

                <div className="rounded-[28px] border border-[#dceee3] bg-white/78 p-5 shadow-[0_20px_60px_rgba(15,43,29,0.07)] backdrop-blur">
                  <p className="text-xs font-semibold uppercase tracking-[0.18em] text-[#087a3a]">
                    Live workspace
                  </p>

                  <div className="mt-5 grid gap-3 sm:grid-cols-2">
                    <MiniMetric label="Reports" value={String(kpis.reportsProcessed || reports.length)} />
                    <MiniMetric label="Findings" value={String(kpis.totalFindings || totalFindings)} />
                    <MiniMetric label="Open" value={String(data.open.length)} />
                    <MiniMetric label="Posture" value={`${data.postureScore}%`} />
                  </div>
                </div>
              </div>
            </header>

            <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
              <KpiCard
                label="Reports analyzed"
                value={kpis.reportsProcessed || reports.length}
                note={`${data.recentReports.length} recent reports`}
                trend="+18%"
                sparkline={[10, 18, 16, 24, 20, 29, 33]}
              />

              <KpiCard
                label="Findings extracted"
                value={kpis.totalFindings || totalFindings}
                note={`${data.open.length} open findings`}
                trend="+24%"
                sparkline={[14, 20, 23, 21, 30, 28, 35]}
              />

              <KpiCard
                label="Critical findings"
                value={criticalFindings}
                note={`${data.criticalHighOpen.length} critical/high active`}
                trend="-10%"
                sparkline={[28, 24, 22, 20, 19, 17, 16]}
                danger
              />

              <KpiCard
                label="Average risk"
                value={avgRiskScore}
                suffix="/100"
                note={avgRiskScore >= 70 ? 'High risk' : avgRiskScore >= 45 ? 'Medium risk' : 'Low risk'}
                trend="+6 pts"
                sparkline={[35, 42, 39, 48, 45, 55, avgRiskScore || 50]}
              />

              <PostureCard score={data.postureScore} />
            </section>

            <section className="mt-5 grid gap-5 xl:grid-cols-[1.35fr_0.95fr_0.8fr]">
              <Panel
                title="Risk overview"
                description="Risk score and finding volume across the latest analyzed timeline."
                action={
                  <Link href="/risk-scoring" className="text-sm font-semibold text-[#087a3a] hover:underline">
                    View full risk analysis
                  </Link>
                }
              >
                <div className="grid min-h-[300px] gap-5 lg:grid-cols-[1.25fr_0.75fr]">
                  <div className="h-[260px]">
                    <ResponsiveContainer width="100%" height="100%">
                      <LineChart data={findingsTrend} margin={{ top: 10, right: 12, left: -18, bottom: 0 }}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#e0eee5" />
                        <XAxis dataKey="day" stroke="#748579" fontSize={12} tickLine={false} axisLine={false} />
                        <YAxis stroke="#748579" fontSize={12} tickLine={false} axisLine={false} />
                        <Tooltip contentStyle={{ borderRadius: 16, borderColor: '#cae7d4' }} />
                        <Line type="monotone" dataKey="findings" stroke="#087a3a" strokeWidth={3} dot={{ r: 3 }} />
                        <Line type="monotone" dataKey="critical" stroke="#dc2626" strokeWidth={2} dot={{ r: 3 }} />
                      </LineChart>
                    </ResponsiveContainer>
                  </div>

                  <div className="rounded-[24px] border border-[#e1eee6] bg-[#fbfffd] p-4">
                    <div className="h-[180px]">
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                          <Pie
                            data={data.severityDistribution}
                            dataKey="count"
                            nameKey="severity"
                            innerRadius={54}
                            outerRadius={78}
                            paddingAngle={2}
                          >
                            {data.severityDistribution.map((entry) => (
                              <Cell key={entry.id} fill={severityChartColors[entry.severity]} />
                            ))}
                          </Pie>
                          <Tooltip contentStyle={{ borderRadius: 16, borderColor: '#cae7d4' }} />
                        </PieChart>
                      </ResponsiveContainer>
                    </div>

                    <div className="-mt-24 flex h-24 items-center justify-center text-center">
                      <div>
                        <p className="text-2xl font-semibold text-[#111827]">{totalFindings}</p>
                        <p className="text-xs font-semibold uppercase tracking-[0.12em] text-[#748579]">
                          Total findings
                        </p>
                      </div>
                    </div>

                    <div className="mt-4 grid gap-2">
                      {data.severityDistribution.map((item) => (
                        <div key={item.id} className="flex items-center justify-between text-xs">
                          <span className="flex items-center gap-2 font-medium text-[#5f6f66]">
                            <span
                              className="h-2.5 w-2.5 rounded-full"
                              style={{ backgroundColor: severityChartColors[item.severity] }}
                            />
                            {item.severity}
                          </span>
                          <span className="font-semibold text-[#111827]">
                            {item.count} ({percent(item.count, totalFindings)}%)
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </Panel>

              <Panel
                title="Findings by severity"
                description="Current distribution across severity levels."
              >
                <div className="h-[300px]">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={data.severityDistribution} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#e0eee5" />
                      <XAxis dataKey="severity" stroke="#748579" fontSize={12} tickLine={false} axisLine={false} />
                      <YAxis allowDecimals={false} stroke="#748579" fontSize={12} tickLine={false} axisLine={false} />
                      <Tooltip contentStyle={{ borderRadius: 16, borderColor: '#cae7d4' }} />
                      <Bar dataKey="count" radius={[12, 12, 0, 0]}>
                        {data.severityDistribution.map((entry) => (
                          <Cell key={entry.id} fill={severityChartColors[entry.severity]} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </Panel>

              <Panel
                title="Recent reports"
                action={
                  <Link href="/reports" className="text-sm font-semibold text-[#087a3a] hover:underline">
                    View all
                  </Link>
                }
              >
                {data.recentReports.length === 0 ? (
                  <EmptyState
                    title="No reports"
                    message="Upload a pentest or CTI report to begin analysis."
                    action={{ href: '/analyzer', label: 'Analyze report' }}
                  />
                ) : (
                  <div className="space-y-3">
                    {data.recentReports.map((report) => (
                      <Link
                        key={report.dashboardKey}
                        href={`/reports/${report.id}`}
                        className="flex items-center justify-between gap-3 rounded-2xl border border-[#e1eee6] bg-[#fbfffd] p-3 transition hover:-translate-y-0.5 hover:border-[#b6dec5] hover:bg-white hover:shadow-[0_14px_34px_rgba(15,43,29,0.07)]"
                      >
                        <span className="min-w-0">
                          <span className="block truncate text-sm font-semibold text-[#111827]">
                            {report.name}
                          </span>
                          <span className="mt-1 block text-xs text-[#748579]">
                            {shortDate(report.uploadedAt)} - {report.findings} findings
                          </span>
                        </span>

                        <StatusBadge status={report.status} />
                      </Link>
                    ))}
                  </div>
                )}
              </Panel>
            </section>

            <section className="mt-5 grid gap-5 xl:grid-cols-[1.25fr_0.75fr_0.9fr]">
              <Panel
                title="Top / priority findings"
                action={
                  <Link href="/results" className="text-sm font-semibold text-[#087a3a] hover:underline">
                    View all findings
                  </Link>
                }
              >
                {data.priorityFindings.length === 0 ? (
                  <EmptyState
                    title="No active findings"
                    message="All extracted findings are resolved or no findings have been loaded yet."
                  />
                ) : (
                  <div className="overflow-hidden rounded-[22px] border border-[#e1eee6]">
                    <table className="min-w-full divide-y divide-[#e7f2eb] text-left text-sm">
                      <thead className="bg-[#fbfffd] text-xs uppercase tracking-[0.12em] text-[#748579]">
                        <tr>
                          <th className="px-4 py-3 font-semibold">Finding</th>
                          <th className="px-4 py-3 font-semibold">Severity</th>
                          <th className="px-4 py-3 font-semibold">Asset</th>
                          <th className="px-4 py-3 font-semibold">Risk</th>
                          <th className="px-4 py-3 font-semibold">Status</th>
                        </tr>
                      </thead>

                      <tbody className="divide-y divide-[#eef6f1] bg-white">
                        {data.priorityFindings.map((finding) => (
                          <tr key={finding.dashboardKey} className="align-top transition hover:bg-[#fbfffd]">
                            <td className="px-4 py-3">
                              <Link
                                href={`/results/${finding.id}`}
                                className="font-semibold text-[#111827] hover:text-[#087a3a]"
                              >
                                {finding.title}
                              </Link>
                              <p className="mt-1 text-xs text-[#748579]">
                                {data.reportNameMap.get(finding.reportId) ?? 'Unknown report'}
                              </p>
                            </td>

                            <td className="px-4 py-3">
                              <SeverityBadge severity={finding.severity} />
                            </td>

                            <td className="max-w-[160px] truncate px-4 py-3 text-[#5f6f66]">
                              {finding.asset}
                            </td>

                            <td className="px-4 py-3 font-semibold text-[#111827]">
                              {finding.score}
                            </td>

                            <td className="px-4 py-3">
                              <StatusBadge status={finding.status} />
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </Panel>

              <Panel
                title="IOC / threat intelligence"
                action={
                  <Link href="/results" className="text-sm font-semibold text-[#087a3a] hover:underline">
                    View all IOCs
                  </Link>
                }
              >
                <div className="space-y-3">
                  <ThreatIntelRow label="IP addresses" value={data.topIps.length} trend="+12%" />
                  <ThreatIntelRow label="Domains" value={data.topDomains.length} trend="+18%" />
                  <ThreatIntelRow label="CVEs" value={data.topCves.length} trend="+8%" />
                  <ThreatIntelRow label="MITRE techniques" value={data.topMitre.length} trend="+6%" />
                  <ThreatIntelRow label="Hashes" value={data.topHashes.length} trend="+4%" />
                </div>
              </Panel>

              <Panel
                title="Attack graph preview"
                action={
                  <Link href="/graph" className="text-sm font-semibold text-[#087a3a] hover:underline">
                    View full graph
                  </Link>
                }
              >
                <AttackGraphPreview />
              </Panel>
            </section>

            <section className="mt-5 grid gap-5 xl:grid-cols-3">
              <Panel title="Asset exposure" description="Assets with the highest unresolved risk concentration.">
                {data.assetBoard.length === 0 ? (
                  <EmptyState
                    title="No assets detected"
                    message="Analyze a report to populate affected assets and exposure levels."
                  />
                ) : (
                  <div className="space-y-3">
                    {data.assetBoard.map((asset) => (
                      <div
                        key={asset.id}
                        className="rounded-2xl border border-[#e1eee6] bg-[#fbfffd] p-4 transition hover:-translate-y-0.5 hover:bg-white hover:shadow-[0_14px_34px_rgba(15,43,29,0.06)]"
                      >
                        <div className="flex items-start justify-between gap-4">
                          <div className="min-w-0">
                            <p className="truncate font-semibold text-[#111827]">{asset.asset}</p>
                            <p className="mt-1 text-sm text-[#748579]">
                              {asset.findings} findings - {asset.open} active - {asset.avgRisk}/100 avg risk
                            </p>
                          </div>

                          <SeverityBadge severity={asset.worstSeverity} />
                        </div>

                        <ProgressBar value={asset.maxRisk} className="mt-4" />
                      </div>
                    ))}
                  </div>
                )}
              </Panel>

              <Panel title="Extraction quality" description="Trust indicators derived from parser metadata.">
                <div className="grid gap-3">
                  <QualityRow
                    label="Needs analyst review"
                    value={data.quality.needsReviewCount}
                    total={totalFindings}
                    tone="warning"
                  />

                  <QualityRow
                    label="Low confidence"
                    value={data.quality.lowConfidenceCount}
                    total={totalFindings}
                    tone="warning"
                  />

                  <QualityRow
                    label="Missing evidence"
                    value={data.quality.missingEvidenceCount}
                    total={totalFindings}
                    tone="danger"
                  />
                </div>
              </Panel>

              <Panel title="Extraction methods" description="Parser, model, and fallback distribution.">
                {data.methodDistribution.length === 0 ? (
                  <EmptyState
                    title="No extraction methods"
                    message="Method metrics appear after reports are analyzed."
                  />
                ) : (
                  <div className="space-y-3">
                    {data.methodDistribution.map((method) => (
                      <div
                        key={method.id}
                        className="rounded-2xl border border-[#e1eee6] bg-[#fbfffd] p-4"
                      >
                        <div className="flex items-center justify-between gap-3">
                          <Badge tone={methodTone(method.method)}>{method.label}</Badge>
                          <span className="text-sm font-semibold text-[#111827]">{method.count}</span>
                        </div>

                        <ProgressBar value={percent(method.count, totalFindings)} className="mt-3" />
                      </div>
                    ))}
                  </div>
                )}
              </Panel>
            </section>

            <section className="mt-5 overflow-hidden rounded-[32px] border border-[#dceee3] bg-white/95 shadow-[0_22px_60px_rgba(15,43,29,0.06)] backdrop-blur">
              <div className="grid items-center gap-4 p-5 lg:grid-cols-[1fr_0.7fr_0.7fr_0.55fr]">
                <div className="flex items-center gap-4">
                  <div>
                    <h2 className="text-lg font-semibold text-[#111827]">
                      Automate. Analyze. Act.
                    </h2>
                    <p className="mt-1 text-sm leading-6 text-[#5f6f66]">
                      Schedule ingestion, review high-risk findings, and export validated intelligence.
                    </p>
                  </div>
                </div>

                <MiniStatus label="Auto ingestion" value="Ready" />
                <MiniStatus label="AI analysis engine" value="Healthy" />

                <Link
                  href="/analyzer"
                  className="inline-flex justify-center rounded-2xl bg-[#087a3a] px-5 py-3 text-sm font-semibold text-white transition hover:bg-[#066b33]"
                >
                  Configure workflow
                </Link>
              </div>
            </section>
        </div>
      </section>
    </main>
  )
}

function KpiCard({
  label,
  value,
  suffix = '',
  note,
  trend,
  sparkline,
  danger = false,
}: {
  label: string
  value: number
  suffix?: string
  note: string
  trend: string
  sparkline: number[]
  danger?: boolean
}) {
  return (
    <article className="group overflow-hidden rounded-[24px] border border-[#dceee3] bg-white p-5 shadow-[0_18px_45px_rgba(15,43,29,0.04)] transition hover:-translate-y-1 hover:shadow-[0_24px_60px_rgba(15,43,29,0.08)]">
      <div className="flex items-start justify-between gap-4">
        <div className={`rounded-full px-3 py-1 text-xs font-semibold ${danger ? 'bg-red-50 text-red-600' : 'bg-[#e9f8ef] text-[#087a3a]'}`}>
          {danger ? 'Alert' : 'Metric'}
        </div>
        <MiniSparkline values={sparkline} danger={danger} />
      </div>

      <p className="mt-4 text-sm font-medium text-[#5f6f66]">{label}</p>
      <p className="mt-1 text-3xl font-semibold tracking-tight text-[#111827]">
        {value.toLocaleString()}
        {suffix}
      </p>

      <div className="mt-3 flex items-center justify-between gap-3 text-xs">
        <span className={danger ? 'font-semibold text-red-600' : 'font-semibold text-[#087a3a]'}>
          {trend}
        </span>
        <span className="text-[#748579]">{note}</span>
      </div>
    </article>
  )
}

function PostureCard({ score }: { score: number }) {
  return (
    <article className="rounded-[24px] border border-[#dceee3] bg-white p-5 shadow-[0_18px_45px_rgba(15,43,29,0.04)] transition hover:-translate-y-1 hover:shadow-[0_24px_60px_rgba(15,43,29,0.08)]">
      <p className="text-sm font-medium text-[#5f6f66]">Security posture</p>
      <div className="mt-4 flex items-center gap-4">
        <div
          className="grid h-20 w-20 place-items-center rounded-full"
          style={{
            background: `conic-gradient(#087a3a ${score * 3.6}deg, #e4f2e9 0deg)`,
          }}
        >
          <div className="grid h-14 w-14 place-items-center rounded-full bg-white">
            <span className="text-xl font-semibold text-[#111827]">{score}</span>
          </div>
        </div>
        <div>
          <p className="text-xl font-semibold text-[#087a3a]">{postureLabel(score)}</p>
          <p className="mt-1 text-sm text-[#748579]">Operational posture</p>
        </div>
      </div>
    </article>
  )
}

function Panel({
  title,
  description,
  action,
  children,
}: {
  title: string
  description?: string
  action?: ReactNode
  children: ReactNode
}) {
  return (
    <section className="rounded-[26px] border border-[#dceee3] bg-white p-5 shadow-[0_18px_45px_rgba(15,43,29,0.04)]">
      <div className="mb-5 flex items-start justify-between gap-4">
        <div>
          <h2 className="text-lg font-semibold tracking-tight text-[#111827]">{title}</h2>
          {description ? <p className="mt-1 text-sm leading-6 text-[#748579]">{description}</p> : null}
        </div>
        {action ? <div className="shrink-0">{action}</div> : null}
      </div>
      {children}
    </section>
  )
}

function ThreatIntelRow({
  label,
  value,
  trend,
}: {
  label: string
  value: number
  trend: string
}) {
  return (
    <div className="flex items-center justify-between gap-3 rounded-2xl border border-[#e1eee6] bg-[#fbfffd] p-3">
      <div className="flex items-center gap-3">
        <span className="h-2.5 w-2.5 rounded-full bg-[#087a3a]" />
        <p className="font-semibold text-[#111827]">{label}</p>
      </div>
      <div className="text-right">
        <p className="font-semibold text-[#111827]">{value}</p>
        <p className="text-xs font-semibold text-[#087a3a]">{trend}</p>
      </div>
    </div>
  )
}

function AttackGraphPreview() {
  const nodes = [
    { x: 50, y: 50, color: '#087a3a' },
    { x: 20, y: 30, color: '#dc2626' },
    { x: 28, y: 72, color: '#f97316' },
    { x: 75, y: 26, color: '#64748b' },
    { x: 82, y: 70, color: '#16a34a' },
    { x: 58, y: 82, color: '#16a34a' },
    { x: 38, y: 18, color: '#64748b' },
  ]

  return (
    <div className="rounded-[24px] border border-[#e1eee6] bg-[#fbfffd] p-4">
      <svg viewBox="0 0 100 100" className="h-[230px] w-full">
        {nodes.slice(1).map((node, index) => (
          <line
            key={`line-${index}`}
            x1="50"
            y1="50"
            x2={node.x}
            y2={node.y}
            stroke="#94a3a0"
            strokeWidth="0.7"
          />
        ))}

        {nodes.map((node, index) => (
          <g key={`node-${index}`}>
            <circle cx={node.x} cy={node.y} r={index === 0 ? 7 : 5} fill="white" stroke={node.color} strokeWidth="2" />
            <circle cx={node.x} cy={node.y} r={index === 0 ? 3 : 2.2} fill={node.color} />
          </g>
        ))}
      </svg>

      <div className="flex flex-wrap justify-center gap-4 text-xs font-semibold text-[#5f6f66]">
        <span className="flex items-center gap-2"><span className="h-2 w-2 rounded-full bg-red-600" /> High risk</span>
        <span className="flex items-center gap-2"><span className="h-2 w-2 rounded-full bg-orange-500" /> Medium risk</span>
        <span className="flex items-center gap-2"><span className="h-2 w-2 rounded-full bg-[#16a34a]" /> Low risk</span>
      </div>
    </div>
  )
}

function MiniStatus({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-2xl border border-[#e1eee6] bg-[#fbfffd] p-4">
      <p className="text-sm font-semibold text-[#111827]">{label}</p>
      <p className="mt-1 inline-flex rounded-full bg-[#e9f8ef] px-2.5 py-1 text-xs font-semibold text-[#087a3a]">
        {value}
      </p>
    </div>
  )
}

function MiniMetric({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-[18px] border border-[#dcefe2] bg-[#fbfffd] px-4 py-3">
      <p className="text-xs font-semibold uppercase tracking-[0.14em] text-[#6b8477]">{label}</p>
      <p className="mt-2 text-xl font-semibold text-[#0d2217]">{value}</p>
    </div>
  )
}

function QualityRow({
  label,
  value,
  total,
  tone,
}: {
  label: string
  value: number
  total: number
  tone: 'warning' | 'danger'
}) {
  const hasIssue = value > 0
  const badgeTone = hasIssue ? tone : 'success'

  return (
    <div className="rounded-[18px] border border-[#dcefe2] bg-[#fbfffd] p-4">
      <div className="flex items-center justify-between gap-3">
        <div>
          <p className="font-semibold text-[#0d2217]">{label}</p>
          <p className="mt-1 text-sm text-[#5a7668]">{percent(value, total)}% of findings</p>
        </div>

        <Badge tone={badgeTone}>{value}</Badge>
      </div>

      <ProgressBar value={percent(value, total)} className="mt-3" muted />
    </div>
  )
}

function ProgressBar({
  value,
  className = '',
  muted = false,
}: {
  value: number
  className?: string
  muted?: boolean
}) {
  return (
    <div className={`h-2.5 overflow-hidden rounded-full bg-[#e6f5eb] ${className}`}>
      <div
        className={`h-full rounded-full transition-all duration-700 ${
          muted ? 'bg-[#95c7a6]' : 'bg-gradient-to-r from-[#16a34a] to-[#087a3a]'
        }`}
        style={{ width: `${clamp(value)}%` }}
      />
    </div>
  )
}

function MiniSparkline({ values, danger = false }: { values: number[]; danger?: boolean }) {
  const max = Math.max(...values, 1)
  const min = Math.min(...values)
  const points = values
    .map((value, index) => {
      const x = (index / Math.max(values.length - 1, 1)) * 78
      const y = 26 - ((value - min) / Math.max(max - min, 1)) * 18
      return `${x},${y}`
    })
    .join(' ')

  return (
    <svg viewBox="0 0 80 28" className="h-8 w-20">
      <polyline
        fill="none"
        stroke={danger ? '#dc2626' : '#087a3a'}
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
        points={points}
      />
    </svg>
  )
}
