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
  Critical: '#facc15',
  High: '#dc2626',
  Medium: '#2563eb',
  Low: '#16a34a',
}

type Tone = 'neutral' | 'success' | 'warning' | 'danger' | 'info'

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
  if (score >= 85) return 'Strong'
  if (score >= 70) return 'Managed'
  if (score >= 55) return 'Watchlist'
  return 'Critical attention'
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

    const postureScore = clamp(
      Math.round(100 - avgRisk * 0.42 - criticalHighOpen.length * 5 - quality.needsReviewCount * 1.8)
    )

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
      .slice(0, 4)
      .map((report, index) => ({
        ...report,
        dashboardKey: `${safeKey(report.id, 'report')}-${index}`,
      }))

    const reportNameMap = new Map(reports.map((report) => [report.id, report.name]))

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
    }
  }, [findings, reports])

  const totalFindings = data.uniqueFindings.length
  const reviewedCount = data.inReview.length + data.resolved.length

  return (
    <main className="min-h-screen bg-transparent">
      <section className="mx-auto max-w-7xl px-6 pb-16 pt-10 lg:px-8">
        <section className="mb-8 overflow-hidden rounded-[34px] border border-[#dcefe2] bg-white shadow-[0_24px_70px_rgba(15,43,29,0.08)]">
          <div className="grid gap-0 lg:grid-cols-[1.25fr_0.75fr]">
            <div className="bg-[radial-gradient(circle_at_top_left,_rgba(34,197,94,0.18),_transparent_42%),linear-gradient(180deg,_#ffffff_0%,_#f6fff9_100%)] px-6 py-8 sm:px-8 lg:px-10">
              <p className="page-kicker">Executive Dashboard</p>

              <h1 className="page-heading">
                Security operations <span className="accent">command center</span>
              </h1>

              <p className="mt-4 max-w-3xl text-base leading-7 text-[#5a7668]">
                A simplified analyst workspace for monitoring extracted findings, report quality,
                risk posture, and remediation priorities without extra menus or visual clutter.
              </p>

              <div className="mt-7 flex flex-wrap gap-3">
                <Link
                  href="/analyzer"
                  className="rounded-2xl bg-gradient-to-r from-[#16a34a] to-[#15803d] px-5 py-3 text-sm font-semibold text-white shadow-[0_14px_28px_rgba(21,128,61,0.18)] transition hover:from-[#15803d] hover:to-[#166534]"
                >
                  Analyze report
                </Link>

                <Link
                  href="/results"
                  className="rounded-2xl border border-[#cbe8d6] bg-white px-5 py-3 text-sm font-semibold text-[#14532d] transition hover:bg-[#edfdf3]"
                >
                  Review findings
                </Link>

                <Link
                  href="/export"
                  className="rounded-2xl border border-[#cbe8d6] bg-white px-5 py-3 text-sm font-semibold text-[#14532d] transition hover:bg-[#edfdf3]"
                >
                  Export report
                </Link>
              </div>
            </div>

            <aside className="border-t border-[#e2f3e8] bg-[#f1fbf5] px-6 py-8 sm:px-8 lg:border-l lg:border-t-0">
              <div className="rounded-[28px] border border-[#cbe8d6] bg-white p-5 shadow-sm">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <p className="text-sm font-semibold uppercase tracking-[0.16em] text-[#15803d]">
                      Security Posture
                    </p>

                    <h2 className="mt-2 text-4xl font-semibold tracking-tight text-[#0d2217]">
                      {data.postureScore}/100
                    </h2>

                    <p className="mt-2 text-sm text-[#5a7668]">
                      {postureLabel(data.postureScore)} · {data.criticalHighOpen.length} critical/high open
                    </p>
                  </div>

                  <Badge tone={data.postureScore >= 70 ? 'success' : data.postureScore >= 55 ? 'warning' : 'danger'}>
                    {postureLabel(data.postureScore)}
                  </Badge>
                </div>

                <ProgressBar value={data.postureScore} className="mt-5" />

                <div className="mt-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-1 xl:grid-cols-2">
                  <MiniMetric label="Avg risk" value={`${data.avgRisk}/100`} />
                  <MiniMetric label="Review debt" value={String(data.quality.needsReviewCount)} />
                  <MiniMetric label="Reviewed" value={`${percent(reviewedCount, totalFindings)}%`} />
                  <MiniMetric label="Export ready" value={String(data.readyForExport.length)} />
                </div>
              </div>
            </aside>
          </div>
        </section>

        <section className="mb-8 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          <MetricCard
            label="Reports analyzed"
            value={String(kpis.reportsProcessed || reports.length)}
            note={`${data.recentReports.length} recent sources shown`}
          />

          <MetricCard
            label="Findings extracted"
            value={String(kpis.totalFindings || totalFindings)}
            note={`${data.open.length} open · ${data.inReview.length} in review`}
          />

          <MetricCard
            label="Critical findings"
            value={String(
              kpis.criticalFindings ||
                data.uniqueFindings.filter((finding) => finding.severity === 'Critical').length
            )}
            note={`${data.criticalHighOpen.length} critical/high still active`}
            tone="danger"
          />

          <MetricCard
            label="Average risk score"
            value={`${kpis.avgRiskScore || data.avgRisk}/100`}
            note={`${data.quality.averageConfidence || 0}% average extraction confidence`}
            tone={riskTone(kpis.avgRiskScore || data.avgRisk)}
          />
        </section>

        <section className="mb-8 grid gap-6 xl:grid-cols-[1.35fr_0.65fr]">
          <Panel
            title="Risk trend"
            description="Finding volume and critical exposure over the latest analyzed timeline."
            action={
              <Link href="/risk-scoring" className="text-sm font-semibold text-[#0f7a43] hover:underline">
                Open risk scoring
              </Link>
            }
          >
            <div className="h-[290px]">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={findingsTrend} margin={{ top: 8, right: 16, left: -12, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#dcefe2" />
                  <XAxis dataKey="day" stroke="#648072" fontSize={12} tickLine={false} axisLine={false} />
                  <YAxis stroke="#648072" fontSize={12} tickLine={false} axisLine={false} />
                  <Tooltip contentStyle={{ borderRadius: 16, borderColor: '#cfe5d7' }} />
                  <Line type="monotone" dataKey="findings" stroke="#15803d" strokeWidth={3} dot={false} />
                  <Line type="monotone" dataKey="critical" stroke="#dc2626" strokeWidth={3} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </Panel>

          <Panel title="Severity distribution" description="Current extracted findings by severity level.">
            <div className="h-[290px]">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={data.severityDistribution} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#dcefe2" />
                  <XAxis dataKey="severity" stroke="#648072" fontSize={12} tickLine={false} axisLine={false} />
                  <YAxis allowDecimals={false} stroke="#648072" fontSize={12} tickLine={false} axisLine={false} />
                  <Tooltip contentStyle={{ borderRadius: 16, borderColor: '#cfe5d7' }} />
                  <Bar dataKey="count" radius={[10, 10, 0, 0]}>
                    {data.severityDistribution.map((entry) => (
                      <Cell key={entry.id} fill={severityChartColors[entry.severity]} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </Panel>
        </section>

        <section className="mb-8 grid gap-6 xl:grid-cols-[1.15fr_0.85fr]">
          <Panel
            title="Priority queue"
            description="Highest-impact unresolved findings that should be reviewed first."
            action={
              <Link href="/results" className="text-sm font-semibold text-[#0f7a43] hover:underline">
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
              <div className="overflow-hidden rounded-[24px] border border-[#dcefe2]">
                <table className="min-w-full divide-y divide-[#e2f3e8] text-left text-sm">
                  <thead className="bg-[#f7fff9] text-xs uppercase tracking-[0.14em] text-[#5a7668]">
                    <tr>
                      <th className="px-4 py-3 font-semibold">Finding</th>
                      <th className="px-4 py-3 font-semibold">Severity</th>
                      <th className="px-4 py-3 font-semibold">Risk</th>
                      <th className="px-4 py-3 font-semibold">Status</th>
                    </tr>
                  </thead>

                  <tbody className="divide-y divide-[#edf7f0] bg-white">
                    {data.priorityFindings.map((finding) => (
                      <tr key={finding.dashboardKey} className="align-top transition hover:bg-[#f8fffb]">
                        <td className="px-4 py-4">
                          <Link
                            href={`/results/${finding.id}`}
                            className="font-semibold text-[#0d2217] hover:text-[#0f7a43]"
                          >
                            {finding.title}
                          </Link>

                          <p className="mt-1 text-xs text-[#5a7668]">
                            {finding.asset} · {data.reportNameMap.get(finding.reportId) ?? 'Unknown report'}
                          </p>
                        </td>

                        <td className="px-4 py-4">
                          <SeverityBadge severity={finding.severity} />
                        </td>

                        <td className="px-4 py-4 font-semibold text-[#0d2217]">{finding.score}/100</td>

                        <td className="px-4 py-4">
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
            title="Asset exposure"
            description="Assets with the highest unresolved risk concentration."
            action={
              <Link href="/graph" className="text-sm font-semibold text-[#0f7a43] hover:underline">
                Open graph
              </Link>
            }
          >
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
                    className="rounded-[22px] border border-[#dcefe2] bg-[#fbfffd] p-4"
                  >
                    <div className="flex items-start justify-between gap-4">
                      <div className="min-w-0">
                        <p className="truncate font-semibold text-[#0d2217]">{asset.asset}</p>
                        <p className="mt-1 text-sm text-[#5a7668]">
                          {asset.findings} findings · {asset.open} active · {asset.avgRisk}/100 avg risk
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
        </section>

        <section className="grid gap-6 xl:grid-cols-3">
          <Panel title="Extraction quality" description="Trust indicators derived from existing parser metadata.">
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

              <QualityRow
                label="Missing remediation"
                value={data.quality.missingRemediationCount}
                total={totalFindings}
                tone="danger"
              />
            </div>
          </Panel>

          <Panel title="Extraction methods" description="Distribution of parser, model, and fallback output.">
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
                    className="rounded-[18px] border border-[#dcefe2] bg-[#fbfffd] p-4"
                  >
                    <div className="flex items-center justify-between gap-3">
                      <Badge tone={methodTone(method.method)}>{method.label}</Badge>
                      <span className="text-sm font-semibold text-[#0d2217]">{method.count}</span>
                    </div>

                    <ProgressBar value={percent(method.count, totalFindings)} className="mt-3" />
                  </div>
                ))}
              </div>
            )}
          </Panel>

          <Panel
            title="Recent reports"
            description="Latest intelligence sources in the workspace."
            action={
              <Link href="/reports" className="text-sm font-semibold text-[#0f7a43] hover:underline">
                View reports
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
                    className="block rounded-[20px] border border-[#dcefe2] bg-[#fbfffd] p-4 transition hover:border-[#b7dec4] hover:bg-[#f5fff8]"
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <p className="truncate font-semibold text-[#0d2217]">{report.name}</p>
                        <p className="mt-1 text-sm text-[#5a7668]">
                          {shortDate(report.uploadedAt)} · {report.findings} findings · {report.owner}
                        </p>
                      </div>

                      <StatusBadge status={report.status} />
                    </div>
                  </Link>
                ))}
              </div>
            )}
          </Panel>
        </section>
      </section>
    </main>
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
    <section className="rounded-[30px] border border-[#dcefe2] bg-white p-6 shadow-[0_18px_45px_rgba(15,43,29,0.05)]">
      <div className="mb-5 flex items-start justify-between gap-4">
        <div>
          <h2 className="text-xl font-semibold tracking-tight text-[#0d2217]">{title}</h2>
          {description ? <p className="mt-1 text-sm leading-6 text-[#5a7668]">{description}</p> : null}
        </div>

        {action ? <div className="shrink-0">{action}</div> : null}
      </div>

      {children}
    </section>
  )
}

function MetricCard({
  label,
  value,
  note,
  tone = 'neutral',
}: {
  label: string
  value: string
  note: string
  tone?: Tone
}) {
  const toneClass =
    tone === 'danger'
      ? 'text-red-600'
      : tone === 'warning'
        ? 'text-orange-600'
        : tone === 'success'
          ? 'text-[#0f7a43]'
          : tone === 'info'
            ? 'text-sky-700'
            : 'text-[#14532d]'

  return (
    <article className="rounded-[28px] border border-[#dcefe2] bg-white p-5 shadow-sm transition hover:-translate-y-0.5 hover:shadow-[0_18px_42px_rgba(15,43,29,0.06)]">
      <p className="text-sm text-[#6b8477]">{label}</p>
      <p className={`mt-2 text-3xl font-semibold tracking-tight ${toneClass}`}>{value}</p>
      <p className="mt-2 text-sm leading-6 text-[#5a7668]">{note}</p>
    </article>
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
        className={`h-full rounded-full ${
          muted ? 'bg-[#95c7a6]' : 'bg-gradient-to-r from-[#16a34a] to-[#15803d]'
        }`}
        style={{ width: `${clamp(value)}%` }}
      />
    </div>
  )
}