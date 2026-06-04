// app/results/page.tsx
import { getFindings, getReports } from '@/lib/data-service'
import type { Finding, Severity } from '@/lib/mock-data'
import Link from 'next/link'

export const dynamic = 'force-dynamic'

const severityOrder: Severity[] = ['Critical', 'High', 'Medium', 'Low']

const severityColors: Record<Severity, string> = {
  Critical: '#dc2626',
  High: '#f97316',
  Medium: '#eab308',
  Low: '#16a34a',
}

const severityBadgeClass: Record<Severity, string> = {
  Critical: 'border-red-200 bg-red-50 text-red-600',
  High: 'border-orange-200 bg-orange-50 text-orange-600',
  Medium: 'border-yellow-200 bg-yellow-50 text-yellow-700',
  Low: 'border-green-200 bg-green-50 text-green-700',
}

const statusBadgeClass: Record<string, string> = {
  Open: 'border-[#bce7cb] bg-[#effaf3] text-[#087a3a]',
  'In Review': 'border-[#cfd8ff] bg-[#f1f4ff] text-[#3b5bdb]',
  Resolved: 'border-[#dceee3] bg-[#fbfffd] text-[#44554b]',
}

function safeText(value: unknown, fallback = 'Unknown') {
  const text = String(value ?? '').trim()
  return text.length > 0 ? text : fallback
}

function percent(part: number, total: number) {
  if (total === 0) return 0
  return Math.round((part / total) * 100)
}

function average(values: number[]) {
  if (values.length === 0) return 0
  return Math.round(values.reduce((sum, value) => sum + value, 0) / values.length)
}

function shortDate(value: string) {
  try {
    return new Intl.DateTimeFormat('en', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      timeZone: 'Africa/Cairo',
    }).format(new Date(value))
  } catch {
    return value
  }
}

function shortTime(value: string) {
  try {
    return new Intl.DateTimeFormat('en', {
      hour: '2-digit',
      minute: '2-digit',
      hour12: true,
      timeZone: 'Africa/Cairo',
    }).format(new Date(value))
  } catch {
    return ''
  }
}

function countBySeverity(findings: Finding[], severity: Severity) {
  return findings.filter((finding) => finding.severity === severity).length
}

function countByStatus(findings: Finding[], status: Finding['status']) {
  return findings.filter((finding) => finding.status === status).length
}

function normalizeConfidence(value: unknown) {
  const numeric = Number(value ?? 0)

  if (!Number.isFinite(numeric) || numeric <= 0) return 0

  // Backend data may store confidence either as 0.92 or 92.
  // Normalize both formats to a clean 0-100 percentage.
  const percentage = numeric <= 1 ? numeric * 100 : numeric

  return Math.max(0, Math.min(100, Math.round(percentage)))
}

function confidenceOf(finding: Finding) {
  return normalizeConfidence(finding.provenance?.parserConfidence)
}

function needsReview(finding: Finding) {
  return (
    finding.status !== 'Resolved' &&
    (confidenceOf(finding) < 70 ||
      !safeText(finding.evidence, '').trim() ||
      !safeText(finding.remediation, '').trim())
  )
}

function severityBreakdown(findings: Finding[]) {
  return severityOrder.map((severity) => ({
    severity,
    count: countBySeverity(findings, severity),
  }))
}

function topAssets(findings: Finding[]) {
  const counters = new Map<string, number>()

  findings.forEach((finding) => {
    const asset = safeText(finding.asset, 'investigation-scope')
    counters.set(asset, (counters.get(asset) ?? 0) + 1)
  })

  return Array.from(counters.entries())
    .map(([asset, count]) => ({ asset, count }))
    .sort((a, b) => b.count - a.count || a.asset.localeCompare(b.asset))
    .slice(0, 5)
}

function riskTone(score: number) {
  if (score >= 80) return 'text-red-600'
  if (score >= 65) return 'text-orange-500'
  if (score >= 40) return 'text-yellow-600'
  return 'text-[#087a3a]'
}

function riskLabel(score: number) {
  if (score >= 80) return 'High risk'
  if (score >= 65) return 'Elevated'
  if (score >= 40) return 'Moderate'
  return 'Controlled'
}

function getParamValue(
  params: Record<string, string | string[] | undefined>,
  key: string,
  fallback = ''
) {
  const value = params[key]
  return Array.isArray(value) ? value[0] ?? fallback : value ?? fallback
}

function filterFindings(
  findings: Finding[],
  filters: {
    q: string
    severity: string
    status: string
    reportId: string
    asset: string
    confidence: string
    risk: string
    review: string
  }
) {
  const query = filters.q.trim().toLowerCase()

  return findings.filter((finding) => {
    const confidence = confidenceOf(finding)
    const reviewNeeded = needsReview(finding)
    const score = finding.score ?? 0

    const matchesQuery =
      query.length === 0 ||
      [
        finding.title,
        finding.summary,
        finding.evidence,
        finding.remediation,
        finding.asset,
        finding.cve,
        finding.reportId,
        finding.severity,
        finding.status,
      ]
        .filter(Boolean)
        .some((value) => String(value).toLowerCase().includes(query))

    const matchesSeverity =
      filters.severity === '' || finding.severity === filters.severity

    const matchesStatus =
      filters.status === '' || finding.status === filters.status

    const matchesReport =
      filters.reportId === '' || finding.reportId === filters.reportId

    const matchesAsset =
      filters.asset === '' || finding.asset === filters.asset

    const matchesConfidence =
      filters.confidence === '' ||
      (filters.confidence === 'high' && confidence >= 80) ||
      (filters.confidence === 'medium' && confidence >= 50 && confidence < 80) ||
      (filters.confidence === 'low' && confidence < 50)

    const matchesRisk =
      filters.risk === '' ||
      (filters.risk === 'high' && score >= 80) ||
      (filters.risk === 'medium' && score >= 50 && score < 80) ||
      (filters.risk === 'low' && score < 50)

    const matchesReview =
      filters.review === '' ||
      (filters.review === 'needs-review' && reviewNeeded) ||
      (filters.review === 'ready' && !reviewNeeded)

    return (
      matchesQuery &&
      matchesSeverity &&
      matchesStatus &&
      matchesReport &&
      matchesAsset &&
      matchesConfidence &&
      matchesRisk &&
      matchesReview
    )
  })
}

export default async function ResultsPage({
  searchParams,
}: {
  searchParams?: Promise<Record<string, string | string[] | undefined>>
}) {
  const [allFindings, reports] = await Promise.all([getFindings(), getReports()])
  const params = (await searchParams) ?? {}

  const filters = {
    q: getParamValue(params, 'q'),
    severity: getParamValue(params, 'severity'),
    status: getParamValue(params, 'status'),
    reportId: getParamValue(params, 'reportId'),
    asset: getParamValue(params, 'asset'),
    confidence: getParamValue(params, 'confidence'),
    risk: getParamValue(params, 'risk'),
    review: getParamValue(params, 'review'),
  }

  const findings = filterFindings(allFindings, filters)
  const reportNameById = new Map(reports.map((report) => [report.id, report.name]))
  const assetOptions = Array.from(
    new Set(allFindings.map((finding) => finding.asset).filter(Boolean))
  ).sort()

  const totalFindings = findings.length
  const criticalCount = countBySeverity(findings, 'Critical')
  const highCount = countBySeverity(findings, 'High')
  const avgRisk = average(findings.map((finding) => finding.score ?? 0))
  const avgConfidence = average(findings.map(confidenceOf))
  const reviewQueue = findings.filter(needsReview).length
  const openCount = countByStatus(findings, 'Open')
  const inReviewCount = countByStatus(findings, 'In Review')
  const resolvedCount = countByStatus(findings, 'Resolved')
  const exportReady = findings.filter((finding) => !needsReview(finding)).length
  const exportPercent = percent(exportReady, totalFindings)

  const sortedFindings = [...findings].sort(
    (a, b) =>
      severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity) ||
      (b.score ?? 0) - (a.score ?? 0) ||
      safeText(b.detectedAt, '').localeCompare(safeText(a.detectedAt, ''))
  )

  const breakdown = severityBreakdown(findings)
  const assets = topAssets(findings)

  return (
    <main className="relative min-h-screen overflow-hidden bg-[#fbfefd] text-[#111827]">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_18%_10%,rgba(34,197,94,0.12),transparent_28%),radial-gradient(circle_at_86%_20%,rgba(8,122,58,0.10),transparent_34%)]" />
      <div className="pointer-events-none absolute right-0 top-20 h-[520px] w-[620px] rounded-full bg-[#dcf7e7]/70 blur-3xl" />
      <div className="pointer-events-none absolute left-0 top-[520px] h-[360px] w-[520px] rounded-full bg-[#eefaf3] blur-3xl" />

      <section className="relative mx-auto max-w-[1520px] px-6 pb-16 pt-10 lg:px-8">
        <header className="relative overflow-hidden rounded-[34px] border border-[#dceee3] bg-white/92 px-7 py-9 shadow-[0_24px_80px_rgba(15,43,29,0.07)] backdrop-blur">
          <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(135deg,rgba(8,122,58,0.05),transparent_42%),radial-gradient(circle_at_86%_24%,rgba(22,163,74,0.14),transparent_28%)]" />
          <div className="pointer-events-none absolute right-20 top-8 h-24 w-24 rounded-full bg-gradient-to-br from-[#dff7e8] to-[#7ddf9b] shadow-[0_22px_55px_rgba(8,122,58,0.18)] finding-float" />
          <div className="pointer-events-none absolute right-[360px] top-20 h-12 w-12 rounded-full bg-[#c8f2d7] shadow-[0_18px_45px_rgba(8,122,58,0.12)] finding-float-slow" />
          <div className="pointer-events-none absolute right-0 top-0 h-full w-1/2 opacity-25">
            <div className="absolute inset-0 bg-[linear-gradient(135deg,rgba(8,122,58,0.10)_25%,transparent_25%,transparent_50%,rgba(8,122,58,0.10)_50%,rgba(8,122,58,0.10)_75%,transparent_75%,transparent)] bg-[length:24px_24px]" />
          </div>

          <div className="relative grid gap-8 lg:grid-cols-[0.9fr_1.1fr]">
            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.22em] text-[#087a3a]">
                Findings intelligence board
              </p>
              <h1 className="mt-4 max-w-3xl text-5xl font-semibold tracking-[-0.055em] text-[#111827] md:text-6xl">
                Review <span className="text-[#087a3a]">extracted</span> findings
              </h1>
              <p className="mt-4 max-w-2xl text-base leading-7 text-[#5f6f66]">
                A focused review workspace for security findings, risk indicators, confidence,
                evidence, remediation, and export readiness.
              </p>

              <div className="mt-7 flex flex-wrap gap-3">
                <Link
                  href="/dashboard"
                  className="rounded-2xl bg-[#087a3a] px-5 py-3 text-sm font-semibold text-white shadow-[0_18px_35px_rgba(8,122,58,0.22)] transition duration-300 hover:-translate-y-1 hover:bg-[#066b33]"
                >
                  Dashboard
                </Link>
                <Link
                  href="/analyzer"
                  className="rounded-2xl border border-[#b8dec7] bg-white px-5 py-3 text-sm font-semibold text-[#087a3a] shadow-sm transition duration-300 hover:-translate-y-1 hover:bg-[#f4fff7]"
                >
                  Analyze new report
                </Link>
              </div>
            </div>

            <div className="relative min-h-[260px]">
              <div className="absolute left-[12%] top-[10%] h-24 w-40 rounded-[50%] border border-[#bfe6cc] bg-gradient-to-b from-white to-[#e5f8ec] shadow-[0_24px_60px_rgba(8,122,58,0.14)] finding-platform" />
              <div className="absolute right-[10%] top-[14%] h-32 w-32 rounded-full bg-gradient-to-br from-[#dcf7e8] via-[#b9edc8] to-[#16a34a] shadow-[0_24px_65px_rgba(8,122,58,0.18)] finding-float" />
              <div className="absolute right-[30%] bottom-[8%] h-16 w-16 rounded-2xl border border-white/70 bg-gradient-to-br from-[#effaf3] to-[#aeeabd] shadow-[0_22px_55px_rgba(8,122,58,0.13)] finding-cube" />

              <div className="absolute left-[11%] bottom-[8%] w-[280px] rounded-[26px] border border-[#d2eadb] bg-white/88 p-4 shadow-[0_24px_70px_rgba(15,43,29,0.12)] backdrop-blur finding-panel">
                <p className="text-xs font-semibold uppercase tracking-[0.14em] text-[#748579]">
                  Review pulse
                </p>
                <p className="mt-2 text-3xl font-semibold text-[#111827]">{totalFindings}</p>
                <p className="mt-1 text-sm text-[#5f6f66]">findings currently indexed</p>
                <div className="mt-4 h-2 overflow-hidden rounded-full bg-[#e6f5eb]">
                  <div className="h-full rounded-full bg-[#087a3a]" style={{ width: `${exportPercent}%` }} />
                </div>
              </div>

              <div className="absolute right-[5%] bottom-[15%] w-[270px] rounded-[26px] border border-[#d2eadb] bg-white/88 p-4 shadow-[0_24px_70px_rgba(15,43,29,0.12)] backdrop-blur finding-panel-delay">
                <p className="text-xs font-semibold uppercase tracking-[0.14em] text-[#748579]">
                  Current risk
                </p>
                <div className="mt-3 flex items-end gap-3">
                  <p className={`text-4xl font-semibold ${riskTone(avgRisk)}`}>{avgRisk}</p>
                  <p className="pb-2 text-sm text-[#5f6f66]">{riskLabel(avgRisk)}</p>
                </div>
                <div className="mt-4 flex gap-1">
                  {[criticalCount, highCount, countBySeverity(findings, 'Medium'), countBySeverity(findings, 'Low')].map((count, index) => (
                    <span
                      key={index}
                      className="w-full rounded-full"
                      style={{
                        height: `${Math.max(18, Math.min(88, count * 4))}px`,
                        backgroundColor: severityColors[severityOrder[index]],
                        opacity: 0.26 + index * 0.12,
                      }}
                    />
                  ))}
                </div>
              </div>
            </div>
          </div>
        </header>

        <form
          action="/results"
          className="relative z-10 -mt-7 mx-auto max-w-[1320px] rounded-[26px] border border-[#dceee3] bg-white/95 p-4 shadow-[0_22px_60px_rgba(15,43,29,0.08)] backdrop-blur"
        >
          <div className="grid gap-3 lg:grid-cols-[1.4fr_0.72fr_0.72fr_0.72fr]">
            <input
              name="q"
              defaultValue={filters.q}
              placeholder="Search findings by title, CVE, asset, or evidence..."
              className="rounded-2xl border border-[#dceee3] bg-[#fbfffd] px-4 py-3 text-sm text-[#44554b] outline-none transition focus:border-[#087a3a] focus:bg-white"
            />

            <select
              name="severity"
              defaultValue={filters.severity}
              className="rounded-2xl border border-[#dceee3] bg-[#fbfffd] px-4 py-3 text-sm font-semibold text-[#44554b] outline-none transition focus:border-[#087a3a] focus:bg-white"
            >
              <option value="">All severities</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>

            <select
              name="status"
              defaultValue={filters.status}
              className="rounded-2xl border border-[#dceee3] bg-[#fbfffd] px-4 py-3 text-sm font-semibold text-[#44554b] outline-none transition focus:border-[#087a3a] focus:bg-white"
            >
              <option value="">All statuses</option>
              <option value="Open">Open</option>
              <option value="In Review">In Review</option>
              <option value="Resolved">Resolved</option>
            </select>

            <select
              name="reportId"
              defaultValue={filters.reportId}
              className="rounded-2xl border border-[#dceee3] bg-[#fbfffd] px-4 py-3 text-sm font-semibold text-[#44554b] outline-none transition focus:border-[#087a3a] focus:bg-white"
            >
              <option value="">All reports</option>
              {reports.map((report) => (
                <option key={report.id} value={report.id}>
                  {report.id} - {report.name}
                </option>
              ))}
            </select>
          </div>

          <div className="mt-3 grid gap-3 lg:grid-cols-[0.75fr_0.75fr_0.75fr_0.75fr_0.6fr_0.6fr]">
            <select
              name="asset"
              defaultValue={filters.asset}
              className="rounded-2xl border border-[#dceee3] bg-[#fbfffd] px-4 py-3 text-sm font-semibold text-[#44554b] outline-none transition focus:border-[#087a3a] focus:bg-white"
            >
              <option value="">All assets</option>
              {assetOptions.map((asset) => (
                <option key={asset} value={asset}>
                  {asset}
                </option>
              ))}
            </select>

            <select
              name="confidence"
              defaultValue={filters.confidence}
              className="rounded-2xl border border-[#dceee3] bg-[#fbfffd] px-4 py-3 text-sm font-semibold text-[#44554b] outline-none transition focus:border-[#087a3a] focus:bg-white"
            >
              <option value="">All confidence</option>
              <option value="high">High confidence</option>
              <option value="medium">Medium confidence</option>
              <option value="low">Low confidence</option>
            </select>

            <select
              name="risk"
              defaultValue={filters.risk}
              className="rounded-2xl border border-[#dceee3] bg-[#fbfffd] px-4 py-3 text-sm font-semibold text-[#44554b] outline-none transition focus:border-[#087a3a] focus:bg-white"
            >
              <option value="">All risk scores</option>
              <option value="high">High risk</option>
              <option value="medium">Medium risk</option>
              <option value="low">Low risk</option>
            </select>

            <select
              name="review"
              defaultValue={filters.review}
              className="rounded-2xl border border-[#dceee3] bg-[#fbfffd] px-4 py-3 text-sm font-semibold text-[#44554b] outline-none transition focus:border-[#087a3a] focus:bg-white"
            >
              <option value="">All review states</option>
              <option value="needs-review">Needs review</option>
              <option value="ready">Ready</option>
            </select>

            <button
              type="submit"
              className="rounded-2xl bg-[#087a3a] px-4 py-3 text-sm font-semibold text-white shadow-[0_16px_32px_rgba(8,122,58,0.18)] transition hover:-translate-y-0.5 hover:bg-[#066b33]"
            >
              Apply filters
            </button>

            <Link
              href="/results"
              className="rounded-2xl border border-[#dceee3] bg-white px-4 py-3 text-center text-sm font-semibold text-[#44554b] transition hover:bg-[#f4fff7]"
            >
              Reset
            </Link>
          </div>
        </form>

        <section className="mt-6 grid gap-4 md:grid-cols-2 xl:grid-cols-6">
          <StatCard label="Total findings" value={totalFindings} note="+18% vs last 7 days" />
          <StatCard label="Critical" value={criticalCount} note={`${percent(criticalCount, totalFindings)}% of total`} danger />
          <StatCard label="High" value={highCount} note={`${percent(highCount, totalFindings)}% of total`} warning />
          <StatCard label="Avg risk score" value={avgRisk} note={riskLabel(avgRisk)} warning={avgRisk >= 65} />
          <StatCard label="Avg confidence" value={avgConfidence} note="Across all findings" />
          <StatCard label="Needs review" value={reviewQueue} note="Pending analyst review" />
        </section>

        <section className="mt-6 grid gap-6 xl:grid-cols-[1fr_360px]">
          <div className="rounded-[32px] border border-[#dceee3] bg-white/95 p-6 shadow-[0_22px_60px_rgba(15,43,29,0.06)] backdrop-blur">
            <div className="mb-5 flex flex-wrap items-center justify-between gap-4">
              <div>
                <h2 className="text-xl font-semibold text-[#111827]">Findings ({totalFindings})</h2>
                <p className="mt-1 text-sm text-[#748579]">Prioritized review cards with evidence and remediation context.</p>
              </div>

              <div className="rounded-2xl border border-[#dceee3] bg-[#fbfffd] px-4 py-2 text-sm font-semibold text-[#44554b]">
                Sort by latest
              </div>
            </div>

            {sortedFindings.length === 0 ? (
              <div className="rounded-[26px] border border-[#dceee3] bg-[#fbfffd] p-8">
                <p className="text-xl font-semibold text-[#111827]">No matching findings</p>
                <p className="mt-2 text-sm text-[#5f6f66]">Try changing the filters or analyze a new report.</p>
                <Link
                  href="/analyzer"
                  className="mt-5 inline-flex rounded-2xl bg-[#087a3a] px-5 py-3 text-sm font-semibold text-white"
                >
                  Analyze report
                </Link>
              </div>
            ) : (
              <div className="space-y-4">
                {sortedFindings.map((finding) => (
                  <FindingCard
                    key={finding.id}
                    finding={finding}
                    reportName={reportNameById.get(finding.reportId) ?? finding.reportId}
                  />
                ))}
              </div>
            )}
          </div>

          <aside className="space-y-5">
            <Panel title="Severity breakdown">
              <div className="flex items-center gap-6">
                <div
                  className="grid h-32 w-32 shrink-0 place-items-center rounded-full"
                  style={{
                    background: `conic-gradient(
                      ${severityColors.Critical} 0 ${percent(criticalCount, totalFindings) * 3.6}deg,
                      ${severityColors.High} ${percent(criticalCount, totalFindings) * 3.6}deg ${(percent(criticalCount, totalFindings) + percent(highCount, totalFindings)) * 3.6}deg,
                      ${severityColors.Medium} ${(percent(criticalCount, totalFindings) + percent(highCount, totalFindings)) * 3.6}deg ${(percent(criticalCount, totalFindings) + percent(highCount, totalFindings) + percent(countBySeverity(findings, 'Medium'), totalFindings)) * 3.6}deg,
                      ${severityColors.Low} 0
                    )`,
                  }}
                >
                  <div className="grid h-20 w-20 place-items-center rounded-full bg-white text-center">
                    <div>
                      <p className="text-2xl font-semibold text-[#111827]">{totalFindings}</p>
                      <p className="text-xs text-[#748579]">Total</p>
                    </div>
                  </div>
                </div>

                <div className="grid flex-1 gap-2">
                  {breakdown.map((item) => (
                    <div key={item.severity} className="flex items-center justify-between gap-3 text-sm">
                      <span className="flex items-center gap-2 font-semibold text-[#44554b]">
                        <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: severityColors[item.severity] }} />
                        {item.severity}
                      </span>
                      <span className="font-semibold text-[#111827]">
                        {item.count} ({percent(item.count, totalFindings)}%)
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </Panel>

            <Panel title="Top affected assets">
              <div className="space-y-3">
                {assets.length === 0 ? (
                  <p className="text-sm text-[#748579]">No assets detected yet.</p>
                ) : (
                  assets.map((asset) => (
                    <div key={asset.asset}>
                      <div className="mb-1 flex items-center justify-between text-sm">
                        <span className="font-semibold text-[#44554b]">{asset.asset}</span>
                        <span className="text-[#748579]">{asset.count} ({percent(asset.count, totalFindings)}%)</span>
                      </div>
                      <div className="h-2 overflow-hidden rounded-full bg-[#e6f5eb]">
                        <div
                          className="h-full rounded-full bg-[#087a3a]"
                          style={{ width: `${percent(asset.count, totalFindings)}%` }}
                        />
                      </div>
                    </div>
                  ))
                )}
              </div>
            </Panel>

            <Panel title="Review queue">
              <QueueLine label="Unassigned findings" value={reviewQueue} />
              <QueueLine label="Open findings" value={openCount} />
              <QueueLine label="In review" value={inReviewCount} />
              <QueueLine label="Resolved" value={resolvedCount} />
            </Panel>

            <Panel title="Export readiness">
              <p className="text-sm text-[#748579]">Ready to export</p>
              <div className="mt-3 h-3 overflow-hidden rounded-full bg-[#e6f5eb]">
                <div className="h-full rounded-full bg-[#087a3a]" style={{ width: `${exportPercent}%` }} />
              </div>
              <p className="mt-3 text-2xl font-semibold text-[#111827]">{exportPercent}%</p>
              <Link
                href="/export"
                className="mt-4 inline-flex rounded-2xl bg-[#087a3a] px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-[#066b33]"
              >
                Export findings
              </Link>
            </Panel>
          </aside>
        </section>
      </section>

      <style>{`
        @keyframes finding-float {
          0%, 100% { transform: translateY(0) rotate(0deg); }
          50% { transform: translateY(-12px) rotate(2deg); }
        }

        @keyframes finding-cube {
          0%, 100% { transform: translateY(0) rotate(0deg); }
          50% { transform: translateY(-16px) rotate(12deg); }
        }

        @keyframes finding-panel {
          0%, 100% { transform: translateY(0); }
          50% { transform: translateY(-9px); }
        }

        .finding-float { animation: finding-float 6.2s ease-in-out infinite; }
        .finding-float-slow { animation: finding-float 8s ease-in-out infinite; animation-delay: -1s; }
        .finding-cube { animation: finding-cube 7s ease-in-out infinite; }
        .finding-panel { animation: finding-panel 6.5s ease-in-out infinite; }
        .finding-panel-delay { animation: finding-panel 7.4s ease-in-out infinite; animation-delay: -1.4s; }
        .finding-platform { transform: perspective(800px) rotateX(58deg); }
      `}</style>
    </main>
  )
}

function StatCard({
  label,
  value,
  note,
  danger = false,
  warning = false,
}: {
  label: string
  value: number
  note: string
  danger?: boolean
  warning?: boolean
}) {
  return (
    <article className="group relative overflow-hidden rounded-[26px] border border-[#dceee3] bg-white p-5 shadow-[0_22px_60px_rgba(15,43,29,0.05)] transition duration-300 hover:-translate-y-1 hover:shadow-[0_30px_80px_rgba(15,43,29,0.09)]">
      <div className="pointer-events-none absolute right-4 top-4 h-20 w-20 rounded-full bg-[#e8f8ee] opacity-80 blur-2xl transition duration-500 group-hover:scale-150" />
      <p className="relative text-xs font-semibold uppercase tracking-[0.16em] text-[#44554b]">{label}</p>
      <p className={`relative mt-4 text-4xl font-semibold tracking-tight ${danger ? 'text-red-600' : warning ? 'text-orange-500' : 'text-[#111827]'}`}>
        {value.toLocaleString()}
      </p>
      <p className="relative mt-3 text-sm font-medium text-[#087a3a]">{note}</p>
      <div className="relative mt-4 h-1.5 overflow-hidden rounded-full bg-[#e6f5eb]">
        <div
          className={`h-full rounded-full ${danger ? 'bg-red-500' : warning ? 'bg-orange-500' : 'bg-[#16a34a]'}`}
          style={{ width: `${Math.min(100, Math.max(24, value))}%` }}
        />
      </div>
    </article>
  )
}

function FindingCard({
  finding,
  reportName,
}: {
  finding: Finding
  reportName: string
}) {
  const confidence = confidenceOf(finding)

  return (
    <article className="group relative overflow-hidden rounded-[28px] border border-[#dceee3] bg-white shadow-[0_20px_55px_rgba(15,43,29,0.05)] transition duration-300 hover:-translate-y-1 hover:border-[#b6dec5] hover:shadow-[0_32px_82px_rgba(15,43,29,0.10)]">
      <div
        className="absolute left-0 top-0 h-full w-1.5"
        style={{ backgroundColor: severityColors[finding.severity] }}
      />
      <div className="grid gap-0 lg:grid-cols-[1fr_280px_150px]">
        <div className="p-6 pl-7">
          <div className="flex flex-wrap gap-2">
            <span className={`rounded-full border px-3 py-1 text-xs font-semibold ${severityBadgeClass[finding.severity]}`}>
              {finding.severity}
            </span>
            <span className={`rounded-full border px-3 py-1 text-xs font-semibold ${statusBadgeClass[finding.status] ?? statusBadgeClass.Open}`}>
              {finding.status}
            </span>
            <span className="rounded-full border border-red-100 bg-red-50 px-3 py-1 text-xs font-semibold text-red-600">
              Score {finding.score}
            </span>
          </div>

          <h2 className="mt-4 text-xl font-semibold tracking-tight text-[#111827]">
            {finding.title}
          </h2>

          <p className="mt-3 max-w-3xl text-sm leading-7 text-[#5f6f66]">
            {safeText(finding.summary, 'No summary available for this finding.')}
          </p>

          <div className="mt-5 flex flex-wrap gap-2">
            <span className="rounded-full border border-[#cfe8d8] bg-[#effaf3] px-3 py-1.5 text-xs font-semibold text-[#087a3a]">
              Asset: {safeText(finding.asset, 'investigation-scope')}
            </span>
            <span className="rounded-full border border-[#cfe8d8] bg-[#effaf3] px-3 py-1.5 text-xs font-semibold text-[#087a3a]">
              Report: {safeText(finding.reportId)}
            </span>
            {finding.cve && finding.cve !== '—' && finding.cve !== 'ΓÇö' && finding.cve !== '╬ô├ç├╢' ? (
              <span className="rounded-full border border-[#dceee3] bg-[#fbfffd] px-3 py-1.5 text-xs font-semibold text-[#44554b]">
                {finding.cve}
              </span>
            ) : null}
          </div>

          <div className="mt-5 grid gap-3 md:grid-cols-2">
            <MiniTextBlock title="Evidence" value={safeText(finding.evidence, 'Evidence needs analyst review.')} />
            <MiniTextBlock title="Remediation" value={safeText(finding.remediation, 'Remediation needs analyst review.')} />
          </div>
        </div>

        <div className="border-y border-[#e8f4ec] bg-[#fbfffd] p-6 lg:border-x lg:border-y-0">
          <MetaLine label="CVE" value={safeText(finding.cve, 'N/A')} />
          <MetaLine label="Confidence" value={`${confidence}%`} />
          <MetaLine label="Detected" value={`${shortDate(finding.detectedAt)} ${shortTime(finding.detectedAt)}`} />
          <MetaLine label="Source" value={finding.provenance?.extractionMethod ?? 'NLP hybrid'} />
          <MetaLine label="Reviewer" value={needsReview(finding) ? 'Pending' : 'Ready'} />
        </div>

        <div className="flex flex-col justify-center gap-3 p-6">
          <Link
            href={`/results/${finding.id}`}
            className="rounded-2xl border border-[#b8dec7] bg-white px-4 py-3 text-center text-sm font-semibold text-[#087a3a] transition hover:bg-[#f4fff7]"
          >
            View details
          </Link>
          <Link
            href={`/graph?reportId=${encodeURIComponent(finding.reportId)}`}
            className="rounded-2xl border border-[#dceee3] bg-[#fbfffd] px-4 py-3 text-center text-sm font-semibold text-[#44554b] transition hover:bg-white"
          >
            View graph
          </Link>
          <Link
            href={`/export?reportId=${encodeURIComponent(finding.reportId)}`}
            className="rounded-2xl bg-[#087a3a] px-4 py-3 text-center text-sm font-semibold text-white transition hover:bg-[#066b33]"
          >
            Export
          </Link>
        </div>
      </div>
    </article>
  )
}

function MiniTextBlock({ title, value }: { title: string; value: string }) {
  return (
    <div className="rounded-2xl border border-[#e1eee6] bg-[#fbfffd] p-4">
      <p className="text-xs font-semibold uppercase tracking-[0.14em] text-[#748579]">{title}</p>
      <p className="mt-2 line-clamp-3 text-sm leading-6 text-[#5f6f66]">{value}</p>
    </div>
  )
}

function MetaLine({ label, value }: { label: string; value: string }) {
  return (
    <div className="border-b border-[#e8f4ec] py-3 last:border-b-0">
      <p className="text-xs font-semibold uppercase tracking-[0.14em] text-[#748579]">{label}</p>
      <p className="mt-1 break-words text-sm font-semibold text-[#111827]">{value}</p>
    </div>
  )
}

function Panel({
  title,
  children,
}: {
  title: string
  children: React.ReactNode
}) {
  return (
    <section className="rounded-[28px] border border-[#dceee3] bg-white/95 p-6 shadow-[0_22px_60px_rgba(15,43,29,0.06)] backdrop-blur">
      <h2 className="mb-5 text-xl font-semibold text-[#111827]">{title}</h2>
      {children}
    </section>
  )
}

function QueueLine({ label, value }: { label: string; value: number }) {
  return (
    <div className="mb-3 flex items-center justify-between gap-4 last:mb-0">
      <span className="text-sm font-medium text-[#5f6f66]">{label}</span>
      <span className="rounded-full bg-[#effaf3] px-3 py-1 text-sm font-semibold text-[#087a3a]">{value}</span>
    </div>
  )
}
