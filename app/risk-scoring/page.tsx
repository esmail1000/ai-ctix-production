// app/risk-scoring/page.tsx
'use client'

import Link from 'next/link'
import { useEffect, useMemo, useState, type ReactNode } from 'react'

type Report = {
  id: string
  slug: string
  name: string
  type: 'PDF' | 'DOCX' | 'TXT'
  uploadedAt: string
  owner: string
  status: 'Ready' | 'Reviewed' | 'Pending'
  findings: number
  critical: number
  high: number
  medium: number
  low: number
  summary: string
}

type Severity = 'Critical' | 'High' | 'Medium' | 'Low'
type RiskBand = 'Low' | 'Medium' | 'High' | 'Critical'

type RiskFactorBreakdown = {
  severity: number
  status: number
  cvePresence: number
  exploitability: number
  exposure: number
  assetCriticality: number
  confidence: number
  mitigationPenalty: number
}

type FindingRiskResult = {
  findingId: string
  reportId: string
  title: string
  asset: string
  severity: Severity
  originalScore: number
  riskScore: number
  riskBand: RiskBand
  rationale: string[]
  factors: RiskFactorBreakdown
}

type RiskApiResponse = {
  report: {
    id: string
    name: string
    type: 'PDF' | 'DOCX' | 'TXT'
    uploadedAt: string
    status: 'Ready' | 'Reviewed' | 'Pending'
    parsingStatus: 'seeded' | 'parsed' | 'failed'
    parserVersion: number | null
    parsingNotes: string[]
  }
  summary: {
    confidence: number
    grounding: {
      findingsWithSummary: number
      findingsWithImpact: number
      findingsWithEvidence: number
      findingsWithRemediation: number
      fullyGroundedFindings: number
      partiallyGroundedFindings: number
      averageFieldCoverage: number
    }
    executiveSummary: string
    severityOverview: Record<Severity, number>
    topRisks: Array<{
      id: string
      title: string
      severity: Severity
      score: number
      asset: string
      reason: string
    }>
    stats: {
      totalFindings: number
      criticalCount: number
      highCount: number
      mediumCount: number
      lowCount: number
      openCount: number
      resolvedCount: number
      distinctAssets: number
    }
  }
  risk: {
    reportId: string
    reportName: string
    generatedAtIso: string
    overallRiskScore: number
    overallRiskBand: RiskBand
    rationale: string[]
    stats: {
      totalFindings: number
      criticalFindings: number
      highFindings: number
      mediumFindings: number
      lowFindings: number
      openFindings: number
      findingsWithCve: number
      distinctAssets: number
    }
    topRiskFindings: FindingRiskResult[]
    allFindings: FindingRiskResult[]
  }
  riskMeta: {
    generatedAtIso: string
    overallRiskScore: number
    overallRiskBand: RiskBand
    totalFindings: number
    openFindings: number
    findingsWithCve: number
    distinctAssets: number
  }
}

const APP_TIME_ZONE = 'Africa/Cairo'

function getReportIdFromUrl() {
  if (typeof window === 'undefined') return ''
  return new URLSearchParams(window.location.search).get('reportId')?.trim() ?? ''
}

function riskBandClass(band: RiskBand) {
  switch (band) {
    case 'Critical':
      return 'border-red-200 bg-red-50 text-red-700'
    case 'High':
      return 'border-orange-200 bg-orange-50 text-orange-700'
    case 'Medium':
      return 'border-yellow-200 bg-yellow-50 text-yellow-700'
    case 'Low':
      return 'border-emerald-200 bg-emerald-50 text-emerald-700'
    default:
      return 'border-slate-200 bg-slate-50 text-slate-700'
  }
}

function severityClass(severity: Severity) {
  switch (severity) {
    case 'Critical':
      return 'border-red-200 bg-red-50 text-red-700'
    case 'High':
      return 'border-orange-200 bg-orange-50 text-orange-700'
    case 'Medium':
      return 'border-yellow-200 bg-yellow-50 text-yellow-700'
    case 'Low':
      return 'border-emerald-200 bg-emerald-50 text-emerald-700'
    default:
      return 'border-slate-200 bg-slate-50 text-slate-700'
  }
}

function scoreTone(score: number) {
  if (score >= 85) return 'text-red-700'
  if (score >= 65) return 'text-orange-700'
  if (score >= 40) return 'text-yellow-700'
  return 'text-emerald-700'
}

function ringColor(score: number) {
  if (score >= 85) return '#dc2626'
  if (score >= 65) return '#f97316'
  if (score >= 40) return '#eab308'
  return '#087a3a'
}

function percent(part: number, total: number) {
  if (total === 0) return 0
  return Math.round((part / total) * 100)
}

function clamp(value: number, min = 0, max = 100) {
  return Math.max(min, Math.min(max, value))
}

function shortDateTime(value: string) {
  try {
    return new Intl.DateTimeFormat('en', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      hour12: true,
      timeZone: APP_TIME_ZONE,
    }).format(new Date(value))
  } catch {
    return value
  }
}

function topAssets(riskData: RiskApiResponse) {
  const assets = new Map<string, { count: number; maxScore: number; band: RiskBand }>()

  for (const finding of riskData.risk.allFindings) {
    const current = assets.get(finding.asset) ?? {
      count: 0,
      maxScore: 0,
      band: 'Low' as RiskBand,
    }

    const nextScore = Math.max(current.maxScore, finding.riskScore)
    assets.set(finding.asset, {
      count: current.count + 1,
      maxScore: nextScore,
      band: finding.riskScore >= current.maxScore ? finding.riskBand : current.band,
    })
  }

  return Array.from(assets.entries())
    .map(([asset, value]) => ({ asset, ...value }))
    .sort((a, b) => b.maxScore - a.maxScore || b.count - a.count)
    .slice(0, 5)
}

function ActionLink(props: {
  href: string
  children: ReactNode
  primary?: boolean
}) {
  return (
    <Link
      href={props.href}
      className={
        props.primary
          ? 'inline-flex items-center justify-center rounded-2xl bg-[#087a3a] px-5 py-3 text-sm font-semibold text-white shadow-[0_16px_32px_rgba(8,122,58,0.18)] transition hover:-translate-y-0.5 hover:bg-[#066b33]'
          : 'inline-flex items-center justify-center rounded-2xl border border-[#c4e3cf] bg-white px-5 py-3 text-sm font-semibold text-[#173128] transition hover:-translate-y-0.5 hover:bg-[#f4fff7]'
      }
    >
      {props.children}
    </Link>
  )
}

export default function RiskScoringPage() {
  const [reports, setReports] = useState<Report[]>([])
  const [selectedReportId, setSelectedReportId] = useState('')
  const [riskData, setRiskData] = useState<RiskApiResponse | null>(null)
  const [isLoadingReports, setIsLoadingReports] = useState(true)
  const [isLoadingRisk, setIsLoadingRisk] = useState(false)
  const [reportsError, setReportsError] = useState('')
  const [riskError, setRiskError] = useState('')
  const [lastGeneratedAt, setLastGeneratedAt] = useState('')

  useEffect(() => {
    let isMounted = true

    async function loadReports() {
      try {
        setIsLoadingReports(true)
        setReportsError('')

        const response = await fetch('/api/reports', { cache: 'no-store' })
        const data = await response.json()

        if (!response.ok) {
          throw new Error(data.error ?? 'Failed to load reports.')
        }

        const nextReports: Report[] = data.reports ?? []
        if (!isMounted) return

        setReports(nextReports)

        if (nextReports.length > 0) {
          const requestedReportId = getReportIdFromUrl()
          const requestedReportExists = nextReports.some(
            (report) => report.id === requestedReportId
          )

          setSelectedReportId((current) => {
            if (current) return current
            if (requestedReportId && requestedReportExists) return requestedReportId
            return nextReports[0].id
          })
        }
      } catch (error) {
        if (!isMounted) return
        setReportsError(error instanceof Error ? error.message : 'Failed to load reports.')
      } finally {
        if (!isMounted) return
        setIsLoadingReports(false)
      }
    }

    loadReports()

    return () => {
      isMounted = false
    }
  }, [])

  useEffect(() => {
    if (!selectedReportId) return
    void handleGenerate(selectedReportId)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedReportId])

  async function handleGenerate(reportId?: string) {
    const targetReportId = reportId ?? selectedReportId
    if (!targetReportId) return

    try {
      setIsLoadingRisk(true)
      setRiskError('')
      setLastGeneratedAt('')

      const response = await fetch(`/api/risk-scoring/${targetReportId}`, {
        cache: 'no-store',
      })
      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.error ?? 'Failed to load risk scoring.')
      }

      setRiskData(data)
      setLastGeneratedAt(new Date().toISOString())
    } catch (error) {
      setRiskData(null)
      setRiskError(error instanceof Error ? error.message : 'Failed to load risk scoring.')
    } finally {
      setIsLoadingRisk(false)
    }
  }

  const selectedReport = useMemo(
    () => reports.find((item) => item.id === selectedReportId) ?? null,
    [reports, selectedReportId]
  )

  const selectedReportParam = selectedReportId
    ? encodeURIComponent(selectedReportId)
    : ''

  const assetExposure = riskData ? topAssets(riskData) : []

  return (
    <main className="relative min-h-screen overflow-hidden bg-[#fbfefd] text-[#111827]">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_18%_10%,rgba(34,197,94,0.10),transparent_30%),radial-gradient(circle_at_86%_18%,rgba(8,122,58,0.08),transparent_34%)]" />
      <div className="pointer-events-none absolute right-0 top-24 h-[420px] w-[560px] rounded-full bg-[#dcf7e7]/60 blur-3xl" />
      <div className="pointer-events-none absolute left-0 top-[540px] h-[320px] w-[520px] rounded-full bg-[#eefaf3] blur-3xl" />

      <section className="relative mx-auto max-w-[1480px] px-6 pb-16 pt-10 lg:px-8">
        <header className="relative overflow-hidden rounded-[34px] border border-[#dceee3] bg-white/92 p-7 shadow-[0_24px_80px_rgba(15,43,29,0.07)] backdrop-blur">
          <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(135deg,rgba(8,122,58,0.05),transparent_42%),radial-gradient(circle_at_86%_24%,rgba(22,163,74,0.12),transparent_28%)]" />
          <div className="pointer-events-none absolute right-[180px] bottom-8 h-20 w-52 rounded-[50%] border border-[#bfe6cc] bg-gradient-to-b from-white to-[#e5f8ec] shadow-[0_24px_60px_rgba(8,122,58,0.12)] risk-platform" />
          <div className="pointer-events-none absolute right-20 top-12 h-24 w-24 rounded-full bg-gradient-to-br from-[#dff7e8] to-[#7ddf9b] shadow-[0_22px_55px_rgba(8,122,58,0.14)] risk-float" />

          <div className="relative grid gap-8 lg:grid-cols-[1fr_0.78fr]">
            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.22em] text-[#087a3a]">
                Risk Command View
              </p>
              <h1 className="mt-4 max-w-4xl text-4xl font-semibold tracking-[-0.04em] text-[#111827] md:text-5xl">
                Report Risk Scoring
              </h1>
              <p className="mt-4 max-w-3xl text-base leading-8 text-[#5f6f66]">
                Overall risk scoring, top-risk findings, factor breakdown, severity
                coverage, and report-level risk rationale from the backend API.
              </p>

              <div className="mt-7 flex flex-wrap gap-3">
                <ActionLink href="/dashboard">Back to Dashboard</ActionLink>
                <ActionLink href="/reports">All Reports</ActionLink>
                {selectedReportParam ? (
                  <>
                    <ActionLink href={`/reports/${selectedReportParam}`}>
                      Open Report
                    </ActionLink>
                    <ActionLink href={`/summarization?reportId=${selectedReportParam}`}>
                      Summary
                    </ActionLink>
                    <ActionLink href={`/results?reportId=${selectedReportParam}`}>
                      Findings
                    </ActionLink>
                    <ActionLink href={`/graph?reportId=${selectedReportParam}`}>
                      Attack Graph
                    </ActionLink>
                  </>
                ) : null}
              </div>
            </div>

            <div className="rounded-[28px] border border-[#dceee3] bg-white/78 p-5 shadow-[0_20px_60px_rgba(15,43,29,0.07)] backdrop-blur">
              <div className="grid gap-3">
                <select
                  value={selectedReportId}
                  onChange={(event) => setSelectedReportId(event.target.value)}
                  disabled={isLoadingReports || reports.length === 0}
                  className="h-12 rounded-2xl border border-[#c4e3cf] bg-[#f6fff9] px-4 text-sm font-semibold text-[#173128] outline-none focus:border-[#087a3a] disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {reports.length === 0 ? (
                    <option value="">No reports available</option>
                  ) : (
                    reports.map((report) => (
                      <option key={report.id} value={report.id}>
                        {report.name} - {report.id}
                      </option>
                    ))
                  )}
                </select>

                <div className="grid gap-3 sm:grid-cols-2">
                  <button
                    onClick={() => handleGenerate()}
                    disabled={!selectedReportId || isLoadingReports || isLoadingRisk}
                    className="h-12 rounded-2xl bg-[#087a3a] px-5 text-sm font-semibold text-white transition hover:bg-[#066b33] disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    {isLoadingRisk
                      ? 'Scoring risk...'
                      : riskData
                        ? 'Regenerate Risk'
                        : 'Generate Risk'}
                  </button>

                  <Link
                    href={selectedReportParam ? `/reports/${selectedReportParam}` : '/reports'}
                    className="inline-flex h-12 items-center justify-center rounded-2xl border border-[#c4e3cf] bg-white px-5 text-sm font-semibold text-[#173128] transition hover:bg-[#edfdf3]"
                  >
                    Open Report
                  </Link>
                </div>
              </div>
            </div>
          </div>
        </header>

        {reportsError ? <ErrorBox message={reportsError} /> : null}
        {riskError ? <ErrorBox message={riskError} /> : null}

        {isLoadingRisk ? (
          <section className="mt-5 rounded-[28px] border border-[#dceee3] bg-white/95 p-6 shadow-[0_22px_60px_rgba(15,43,29,0.05)]">
            <p className="text-sm font-semibold uppercase tracking-[0.18em] text-[#087a3a]">
              Calculating risk score
            </p>
            <p className="mt-2 text-sm leading-6 text-[#5a7668]">
              The system is refreshing report-level risk, scoring factors, and top risk findings.
            </p>
            <div className="mt-4 h-2 overflow-hidden rounded-full bg-[#e6f5eb]">
              <div className="h-full w-2/3 animate-pulse rounded-full bg-[#087a3a]" />
            </div>
          </section>
        ) : null}

        {lastGeneratedAt && riskData ? (
          <section className="mt-5 rounded-2xl border border-[#c4e3cf] bg-[#f6fff9] px-5 py-3 text-sm font-semibold text-[#087a3a]">
            Risk score refreshed at {shortDateTime(lastGeneratedAt)}
          </section>
        ) : null}

        {selectedReport ? (
          <section className="mt-5 rounded-[28px] border border-[#dceee3] bg-white/95 p-5 shadow-[0_22px_60px_rgba(15,43,29,0.05)]">
            <div className="flex flex-wrap items-center gap-3">
              <Pill>{selectedReport.id}</Pill>
              <Pill>{selectedReport.type}</Pill>
              <Pill>{selectedReport.status}</Pill>
              <Pill>Uploaded {shortDateTime(selectedReport.uploadedAt)}</Pill>
            </div>
            <h2 className="mt-4 text-2xl font-semibold text-[#0d2217]">
              {selectedReport.name}
            </h2>
            <p className="mt-2 max-w-5xl text-sm leading-7 text-[#5a7668]">
              {selectedReport.summary}
            </p>
          </section>
        ) : null}

        {riskData ? (
          <>
            <section className="mt-5 grid gap-4 md:grid-cols-2 xl:grid-cols-5">
              <MetricCard
                label="Overall risk"
                value={`${riskData.riskMeta.overallRiskScore}/100`}
                helper={riskData.riskMeta.overallRiskBand}
                valueClass={scoreTone(riskData.riskMeta.overallRiskScore)}
              />
              <MetricCard
                label="Summary confidence"
                value={`${riskData.summary.confidence}%`}
                helper="Grounded summarization"
              />
              <MetricCard
                label="Coverage"
                value={`${riskData.summary.grounding.averageFieldCoverage}%`}
                helper="Average field grounding"
              />
              <MetricCard
                label="Open findings"
                value={String(riskData.riskMeta.openFindings)}
                helper={`${riskData.riskMeta.totalFindings} total findings`}
              />
              <MetricCard
                label="Findings with CVE"
                value={String(riskData.riskMeta.findingsWithCve)}
                helper={`${riskData.riskMeta.distinctAssets} distinct assets`}
              />
            </section>

            <section className="mt-6 grid gap-6 xl:grid-cols-[1fr_430px]">
              <div className="space-y-6">
                <section className="rounded-[32px] border border-[#dceee3] bg-white/95 p-6 shadow-[0_22px_60px_rgba(15,43,29,0.06)] backdrop-blur">
                  <div className="flex flex-wrap items-center justify-between gap-4">
                    <div>
                      <p className="text-sm font-semibold uppercase tracking-[0.18em] text-[#087a3a]">
                        Risk summary
                      </p>
                      <h2 className="mt-2 text-2xl font-semibold text-[#0d2217]">
                        Overall report risk
                      </h2>
                    </div>

                    <span
                      className={`inline-flex rounded-full border px-3 py-1 text-xs font-semibold ${riskBandClass(
                        riskData.risk.overallRiskBand
                      )}`}
                    >
                      {riskData.risk.overallRiskBand}
                    </span>
                  </div>

                  <div className="mt-6 grid gap-6 lg:grid-cols-[220px_1fr]">
                    <div className="flex justify-center">
                      <div
                        className="grid h-40 w-40 place-items-center rounded-full"
                        style={{
                          background: `conic-gradient(${ringColor(
                            riskData.risk.overallRiskScore
                          )} ${riskData.risk.overallRiskScore * 3.6}deg, #e6f5eb 0deg)`,
                        }}
                      >
                        <div className="grid h-28 w-28 place-items-center rounded-full bg-white text-center shadow-inner">
                          <div>
                            <p
                              className={`text-4xl font-semibold ${scoreTone(
                                riskData.risk.overallRiskScore
                              )}`}
                            >
                              {riskData.risk.overallRiskScore}
                            </p>
                            <p className="text-xs text-[#748579]">Risk score</p>
                          </div>
                        </div>
                      </div>
                    </div>

                    <div className="space-y-3">
                      {riskData.risk.rationale.length === 0 ? (
                        <p className="rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] p-4 text-sm text-[#5a7668]">
                          No risk rationale was generated.
                        </p>
                      ) : (
                        riskData.risk.rationale.map((item, index) => (
                          <p
                            key={`${item}-${index}`}
                            className="rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] p-4 text-sm leading-7 text-[#173128]"
                          >
                            {item}
                          </p>
                        ))
                      )}
                    </div>
                  </div>
                </section>

                <section className="rounded-[32px] border border-[#dceee3] bg-white/95 p-6 shadow-[0_22px_60px_rgba(15,43,29,0.06)] backdrop-blur">
                  <div className="flex flex-wrap items-center justify-between gap-4">
                    <div>
                      <p className="text-sm font-semibold uppercase tracking-[0.18em] text-[#087a3a]">
                        Top risk findings
                      </p>
                      <h2 className="mt-2 text-2xl font-semibold text-[#0d2217]">
                        Highest-priority scoring results
                      </h2>
                    </div>

                    <Link
                      href={selectedReportParam ? `/results?reportId=${selectedReportParam}` : '/results'}
                      className="rounded-2xl border border-[#c4e3cf] bg-white px-4 py-2 text-sm font-semibold text-[#173128] transition hover:bg-[#edfdf3]"
                    >
                      Open findings board
                    </Link>
                  </div>

                  <div className="mt-5 grid gap-4">
                    {riskData.risk.topRiskFindings.length === 0 ? (
                      <p className="rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] p-4 text-sm text-[#5a7668]">
                        No risk findings available.
                      </p>
                    ) : (
                      riskData.risk.topRiskFindings.slice(0, 6).map((item) => (
                        <article
                          key={item.findingId}
                          className="rounded-[24px] border border-[#e4f2e9] bg-[#f8fffa] p-5"
                        >
                          <div className="flex flex-wrap items-center gap-3">
                            <span
                              className={`inline-flex rounded-full border px-3 py-1 text-xs font-semibold ${severityClass(
                                item.severity
                              )}`}
                            >
                              {item.severity}
                            </span>

                            <span
                              className={`inline-flex rounded-full border px-3 py-1 text-xs font-semibold ${riskBandClass(
                                item.riskBand
                              )}`}
                            >
                              {item.riskBand}
                            </span>

                            <span className={`text-sm font-semibold ${scoreTone(item.riskScore)}`}>
                              Risk {item.riskScore}
                            </span>

                            <span className="rounded-full border border-[#dcefe2] bg-white px-3 py-1 text-xs font-semibold text-[#173128]">
                              Original {item.originalScore}
                            </span>
                          </div>

                          <h3 className="mt-4 text-lg font-semibold text-[#0d2217]">
                            {item.title}
                          </h3>
                          <p className="mt-1 text-sm text-[#5a7668]">{item.asset}</p>

                          <div className="mt-4 grid gap-4 xl:grid-cols-[1fr_0.8fr]">
                            <div>
                              <p className="text-xs font-semibold uppercase tracking-wide text-[#5a7668]">
                                Rationale
                              </p>
                              <div className="mt-2 space-y-2">
                                {item.rationale.slice(0, 4).map((reason, index) => (
                                  <p
                                    key={`${reason}-${index}`}
                                    className="text-sm leading-7 text-[#173128]"
                                  >
                                    {reason}
                                  </p>
                                ))}
                              </div>
                            </div>

                            <FactorGrid factors={item.factors} />
                          </div>

                          <div className="mt-4 flex flex-wrap gap-3">
                            <ActionLink href={`/results/${item.findingId}`}>
                              Open Finding
                            </ActionLink>
                            <ActionLink href={`/reports/${item.reportId}`}>
                              Parent Report
                            </ActionLink>
                          </div>
                        </article>
                      ))
                    )}
                  </div>
                </section>

                <section className="rounded-[32px] border border-[#dceee3] bg-white/95 p-6 shadow-[0_22px_60px_rgba(15,43,29,0.06)] backdrop-blur">
                  <p className="text-sm font-semibold uppercase tracking-[0.18em] text-[#087a3a]">
                    Executive context
                  </p>
                  <h2 className="mt-2 text-2xl font-semibold text-[#0d2217]">
                    Summary used for scoring
                  </h2>
                  <p className="mt-4 rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] p-5 text-base leading-8 text-[#173128]">
                    {riskData.summary.executiveSummary}
                  </p>
                </section>
              </div>

              <aside className="space-y-5">
                <Panel title="Coverage and severity">
                  <div className="grid gap-3">
                    <GroundingRow
                      label="With summary"
                      value={riskData.summary.grounding.findingsWithSummary}
                      total={riskData.summary.stats.totalFindings}
                    />
                    <GroundingRow
                      label="With impact"
                      value={riskData.summary.grounding.findingsWithImpact}
                      total={riskData.summary.stats.totalFindings}
                    />
                    <GroundingRow
                      label="With evidence"
                      value={riskData.summary.grounding.findingsWithEvidence}
                      total={riskData.summary.stats.totalFindings}
                    />
                    <GroundingRow
                      label="With remediation"
                      value={riskData.summary.grounding.findingsWithRemediation}
                      total={riskData.summary.stats.totalFindings}
                    />
                  </div>

                  <div className="mt-5 space-y-3">
                    {(['Critical', 'High', 'Medium', 'Low'] as Severity[]).map((severity) => (
                      <div
                        key={severity}
                        className="flex items-center justify-between rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] px-4 py-3"
                      >
                        <span
                          className={`inline-flex rounded-full border px-3 py-1 text-xs font-semibold ${severityClass(
                            severity
                          )}`}
                        >
                          {severity}
                        </span>
                        <span className="text-lg font-semibold text-[#173128]">
                          {riskData.summary.severityOverview[severity]}
                        </span>
                      </div>
                    ))}
                  </div>
                </Panel>

                <Panel title="Risk statistics">
                  <div className="grid grid-cols-2 gap-3">
                    <QualityBox label="Total findings" value={String(riskData.risk.stats.totalFindings)} helper="Report scope" />
                    <QualityBox label="Open findings" value={String(riskData.risk.stats.openFindings)} helper="Needs action" />
                    <QualityBox label="Findings with CVE" value={String(riskData.risk.stats.findingsWithCve)} helper="Mapped IDs" />
                    <QualityBox label="Distinct assets" value={String(riskData.risk.stats.distinctAssets)} helper="Affected scope" />
                  </div>
                </Panel>

                <Panel title="Asset exposure">
                  <div className="space-y-3">
                    {assetExposure.length === 0 ? (
                      <p className="text-sm text-[#5a7668]">No affected assets were identified.</p>
                    ) : (
                      assetExposure.map((asset) => (
                        <div
                          key={asset.asset}
                          className="rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] p-4"
                        >
                          <div className="flex items-start justify-between gap-3">
                            <div className="min-w-0">
                              <p className="truncate font-semibold text-[#0f2b1d]">
                                {asset.asset}
                              </p>
                              <p className="mt-1 text-sm text-[#5a7668]">
                                {asset.count} linked finding{asset.count > 1 ? 's' : ''}
                              </p>
                            </div>
                            <span
                              className={`shrink-0 rounded-full border px-3 py-1 text-xs font-semibold ${riskBandClass(
                                asset.band
                              )}`}
                            >
                              {asset.band}
                            </span>
                          </div>
                          <p className="mt-3 text-sm text-[#173128]">
                            Highest risk score on this asset: {asset.maxScore}
                          </p>
                        </div>
                      ))
                    )}
                  </div>
                </Panel>

                <Panel title="Parser notes">
                  <div className="grid gap-3">
                    <QualityBox
                      label="Parsing status"
                      value={riskData.report.parsingStatus}
                      helper={`Parser version ${riskData.report.parserVersion ?? '-'}`}
                    />

                    {riskData.report.parsingNotes.length === 0 ? (
                      <p className="text-sm text-[#5a7668]">No parsing notes.</p>
                    ) : (
                      riskData.report.parsingNotes.slice(0, 4).map((note, index) => (
                        <p
                          key={`${note}-${index}`}
                          className="rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] p-4 text-sm leading-6 text-[#173128]"
                        >
                          {note}
                        </p>
                      ))
                    )}
                  </div>
                </Panel>
              </aside>
            </section>
          </>
        ) : (
          !isLoadingReports &&
          !riskError &&
          reports.length > 0 && (
            <section className="mt-8 rounded-[28px] border border-dashed border-[#c4e3cf] bg-white p-10 text-center shadow-sm">
              <p className="text-lg font-semibold text-[#173128]">
                Select a report to generate risk scoring.
              </p>
              <p className="mt-2 text-sm text-[#5a7668]">
                The page will display overall risk, scoring factors, and grounded
                metadata from the summarization layer.
              </p>
            </section>
          )
        )}
      </section>

      <style>{`
        @keyframes risk-float {
          0%, 100% { transform: translateY(0) rotate(0deg); }
          50% { transform: translateY(-12px) rotate(2deg); }
        }

        .risk-float { animation: risk-float 6.2s ease-in-out infinite; }
        .risk-platform { transform: perspective(800px) rotateX(58deg); }
      `}</style>
    </main>
  )
}

function MetricCard(props: {
  label: string
  value: string
  helper?: string
  valueClass?: string
}) {
  return (
    <div className="rounded-[26px] border border-[#dceee3] bg-white p-5 shadow-[0_22px_60px_rgba(15,43,29,0.05)] transition hover:-translate-y-1 hover:shadow-[0_30px_80px_rgba(15,43,29,0.09)]">
      <p className="text-sm font-medium text-[#5a7668]">{props.label}</p>
      <p className={`mt-3 text-3xl font-semibold tracking-tight ${props.valueClass ?? 'text-[#0d2217]'}`}>
        {props.value}
      </p>
      {props.helper ? (
        <p className="mt-2 text-sm leading-6 text-[#5a7668]">{props.helper}</p>
      ) : null}
    </div>
  )
}

function Panel({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="rounded-[28px] border border-[#dceee3] bg-white/95 p-6 shadow-[0_22px_60px_rgba(15,43,29,0.06)] backdrop-blur">
      <h2 className="mb-5 text-xl font-semibold text-[#0d2217]">{title}</h2>
      {children}
    </section>
  )
}

function QualityBox({
  label,
  value,
  helper,
}: {
  label: string
  value: string
  helper: string
}) {
  return (
    <div className="rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] p-4">
      <p className="text-xs font-semibold uppercase tracking-wide text-[#5a7668]">
        {label}
      </p>
      <p className="mt-2 text-2xl font-semibold text-[#087a3a]">{value}</p>
      <p className="mt-1 text-xs text-[#5a7668]">{helper}</p>
    </div>
  )
}

function GroundingRow({
  label,
  value,
  total,
}: {
  label: string
  value: number
  total: number
}) {
  const width = percent(value, total)

  return (
    <div>
      <div className="mb-1 flex items-center justify-between text-sm">
        <span className="font-semibold text-[#44554b]">{label}</span>
        <span className="text-[#748579]">
          {value} ({width}%)
        </span>
      </div>
      <div className="h-2 overflow-hidden rounded-full bg-[#e6f5eb]">
        <div
          className="h-full rounded-full bg-[#087a3a]"
          style={{ width: `${width}%` }}
        />
      </div>
    </div>
  )
}

function FactorGrid({ factors }: { factors: RiskFactorBreakdown }) {
  const rows = [
    ['Severity', factors.severity],
    ['Status', factors.status],
    ['CVE', factors.cvePresence],
    ['Exploitability', factors.exploitability],
    ['Exposure', factors.exposure],
    ['Asset criticality', factors.assetCriticality],
    ['Confidence', factors.confidence],
    ['Mitigation penalty', factors.mitigationPenalty],
  ]

  return (
    <div>
      <p className="text-xs font-semibold uppercase tracking-wide text-[#5a7668]">
        Factors
      </p>
      <div className="mt-2 grid gap-2 sm:grid-cols-2">
        {rows.map(([label, value]) => (
          <div
            key={label}
            className="rounded-xl border border-[#e4f2e9] bg-white px-3 py-2"
          >
            <p className="text-xs text-[#5a7668]">{label}</p>
            <p className="mt-1 text-sm font-semibold text-[#173128]">{value}</p>
          </div>
        ))}
      </div>
    </div>
  )
}

function ErrorBox({ message }: { message: string }) {
  return (
    <div className="mt-5 rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">
      {message}
    </div>
  )
}

function Pill({ children }: { children: ReactNode }) {
  return (
    <span className="rounded-full border border-[#c4e3cf] bg-[#f6fff9] px-3 py-1 text-xs font-semibold text-[#173128]">
      {children}
    </span>
  )
}
