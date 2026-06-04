// app/summarization/page.tsx
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

type SummaryKeyFinding = {
  id: string
  title: string
  severity: Severity
  asset: string
  score: number
  cve: string
  status: 'Open' | 'In Review' | 'Resolved'
  summary: string
  impact: string
  remediation: string
  priority: number
}

type SummaryAffectedAsset = {
  asset: string
  findingsCount: number
  highestSeverity: Severity
  highestScore: number
}

type SummaryTopRisk = {
  id: string
  title: string
  severity: Severity
  score: number
  asset: string
  reason: string
}

type SummaryGroundingStats = {
  findingsWithSummary: number
  findingsWithImpact: number
  findingsWithEvidence: number
  findingsWithRemediation: number
  fullyGroundedFindings: number
  partiallyGroundedFindings: number
  averageFieldCoverage: number
}

type SummaryResponse = {
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
    reportId: string
    reportName: string
    generatedAtIso: string
    executiveSummary: string
    narrativeSummary: string
    keyFindings: SummaryKeyFinding[]
    affectedAssets: SummaryAffectedAsset[]
    severityOverview: Record<Severity, number>
    topRisks: SummaryTopRisk[]
    recommendations: string[]
    confidence: number
    grounding: SummaryGroundingStats
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
  summaryMeta: {
    generatedAtIso: string
    confidence: number
    grounding: SummaryGroundingStats
    totalFindings: number
    openFindings: number
    distinctAssets: number
  }
}

const APP_TIME_ZONE = 'Africa/Cairo'

function getReportIdFromUrl() {
  if (typeof window === 'undefined') return ''
  return new URLSearchParams(window.location.search).get('reportId')?.trim() ?? ''
}

function severityBadgeClass(severity: Severity) {
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

export default function SummarizationPage() {
  const [reports, setReports] = useState<Report[]>([])
  const [selectedReportId, setSelectedReportId] = useState('')
  const [summaryData, setSummaryData] = useState<SummaryResponse | null>(null)
  const [isLoadingReports, setIsLoadingReports] = useState(true)
  const [isLoadingSummary, setIsLoadingSummary] = useState(false)
  const [reportsError, setReportsError] = useState('')
  const [summaryError, setSummaryError] = useState('')
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
      setIsLoadingSummary(true)
      setSummaryError('')
      setSummaryData(null)
      setLastGeneratedAt('')

      const response = await fetch(`/api/summarization/${targetReportId}`, {
        cache: 'no-store',
      })
      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.error ?? 'Failed to generate summary.')
      }

      setSummaryData(data)
      setLastGeneratedAt(new Date().toISOString())
    } catch (error) {
      setSummaryData(null)
      setSummaryError(error instanceof Error ? error.message : 'Failed to generate summary.')
    } finally {
      setIsLoadingSummary(false)
    }
  }

  const selectedReport = useMemo(
    () => reports.find((item) => item.id === selectedReportId) ?? null,
    [reports, selectedReportId]
  )

  const selectedReportParam = selectedReportId
    ? encodeURIComponent(selectedReportId)
    : ''

  const exportReadiness = summaryData
    ? clamp(
        summaryData.summaryMeta.grounding.averageFieldCoverage -
          (summaryData.summaryMeta.openFindings > 0 ? 8 : 0)
      )
    : 0

  return (
    <main className="relative min-h-screen overflow-hidden bg-[#fbfefd] text-[#111827]">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_18%_10%,rgba(34,197,94,0.10),transparent_30%),radial-gradient(circle_at_86%_18%,rgba(8,122,58,0.08),transparent_34%)]" />
      <div className="pointer-events-none absolute right-0 top-24 h-[420px] w-[560px] rounded-full bg-[#dcf7e7]/60 blur-3xl" />
      <div className="pointer-events-none absolute left-0 top-[540px] h-[320px] w-[520px] rounded-full bg-[#eefaf3] blur-3xl" />

      <section className="relative mx-auto max-w-[1480px] px-6 pb-16 pt-10 lg:px-8">
        <header className="relative overflow-hidden rounded-[34px] border border-[#dceee3] bg-white/92 p-7 shadow-[0_24px_80px_rgba(15,43,29,0.07)] backdrop-blur">
          <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(135deg,rgba(8,122,58,0.05),transparent_42%),radial-gradient(circle_at_86%_24%,rgba(22,163,74,0.12),transparent_28%)]" />
          <div className="pointer-events-none absolute right-[180px] bottom-8 h-20 w-52 rounded-[50%] border border-[#bfe6cc] bg-gradient-to-b from-white to-[#e5f8ec] shadow-[0_24px_60px_rgba(8,122,58,0.12)] summary-platform" />
          <div className="pointer-events-none absolute right-20 top-12 h-24 w-24 rounded-full bg-gradient-to-br from-[#dff7e8] to-[#7ddf9b] shadow-[0_22px_55px_rgba(8,122,58,0.14)] summary-float" />

          <div className="relative grid gap-8 lg:grid-cols-[1fr_0.78fr]">
            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.22em] text-[#087a3a]">
                Summary Command View
              </p>
              <h1 className="mt-4 max-w-4xl text-4xl font-semibold tracking-[-0.04em] text-[#111827] md:text-5xl">
                Report Summarization
              </h1>
              <p className="mt-4 max-w-3xl text-base leading-8 text-[#5f6f66]">
                Grounded executive summary, narrative explanation, evidence coverage,
                affected assets, and recommendations for the selected report.
              </p>

              <div className="mt-7 flex flex-wrap gap-3">
                <ActionLink href="/dashboard">Back to Dashboard</ActionLink>
                <ActionLink href="/reports">All Reports</ActionLink>
                {selectedReportParam ? (
                  <>
                    <ActionLink href={`/reports/${selectedReportParam}`}>
                      Open Report
                    </ActionLink>
                    <ActionLink href={`/risk-scoring?reportId=${selectedReportParam}`}>
                      Risk Scoring
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
                    disabled={!selectedReportId || isLoadingReports || isLoadingSummary}
                    className="h-12 rounded-2xl bg-[#087a3a] px-5 text-sm font-semibold text-white transition hover:bg-[#066b33] disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    {isLoadingSummary ? 'Generating summary...' : summaryData ? 'Regenerate Summary' : 'Generate Summary'}
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
        {summaryError ? <ErrorBox message={summaryError} /> : null}

        {isLoadingSummary ? (
          <section className="mt-5 rounded-[28px] border border-[#dceee3] bg-white/95 p-6 shadow-[0_22px_60px_rgba(15,43,29,0.05)]">
            <p className="text-sm font-semibold uppercase tracking-[0.18em] text-[#087a3a]">
              Generating summary
            </p>
            <p className="mt-2 text-sm leading-6 text-[#5a7668]">
              The system is refreshing the grounded summary for the selected report.
            </p>
            <div className="mt-4 h-2 overflow-hidden rounded-full bg-[#e6f5eb]">
              <div className="h-full w-2/3 animate-pulse rounded-full bg-[#087a3a]" />
            </div>
          </section>
        ) : null}

        {lastGeneratedAt && summaryData ? (
          <section className="mt-5 rounded-2xl border border-[#c4e3cf] bg-[#f6fff9] px-5 py-3 text-sm font-semibold text-[#087a3a]">
            Summary refreshed at {shortDateTime(lastGeneratedAt)}
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

        {summaryData ? (
          <>
            <section className="mt-5 grid gap-4 md:grid-cols-2 xl:grid-cols-5">
              <MetricCard
                label="Confidence"
                value={`${summaryData.summaryMeta.confidence}%`}
                helper="Grounded confidence"
              />
              <MetricCard
                label="Coverage"
                value={`${summaryData.summaryMeta.grounding.averageFieldCoverage}%`}
                helper="Average field grounding"
              />
              <MetricCard
                label="Findings"
                value={String(summaryData.summaryMeta.totalFindings)}
                helper={`${summaryData.summaryMeta.openFindings} open`}
              />
              <MetricCard
                label="Assets"
                value={String(summaryData.summaryMeta.distinctAssets)}
                helper="Distinct affected assets"
              />
              <MetricCard
                label="Export readiness"
                value={`${exportReadiness}%`}
                helper="Summary quality score"
              />
            </section>

            <section className="mt-6 grid gap-6 xl:grid-cols-[1fr_430px]">
              <div className="space-y-6">
                <section className="rounded-[32px] border border-[#dceee3] bg-white/95 p-6 shadow-[0_22px_60px_rgba(15,43,29,0.06)] backdrop-blur">
                  <div className="flex flex-wrap items-center justify-between gap-4">
                    <div>
                      <p className="text-sm font-semibold uppercase tracking-[0.18em] text-[#087a3a]">
                        Executive summary
                      </p>
                      <h2 className="mt-2 text-2xl font-semibold text-[#0d2217]">
                        Grounded narrative
                      </h2>
                    </div>

                    <span className="rounded-full border border-[#c4e3cf] bg-[#f6fff9] px-3 py-1 text-xs font-semibold text-[#173128]">
                      Generated {shortDateTime(summaryData.summary.generatedAtIso)}
                    </span>
                  </div>

                  <div className="mt-5 grid gap-4">
                    <TextPanel label="Executive" body={summaryData.summary.executiveSummary} />
                    <TextPanel label="Narrative" body={summaryData.summary.narrativeSummary} />
                  </div>
                </section>

                <section className="rounded-[32px] border border-[#dceee3] bg-white/95 p-6 shadow-[0_22px_60px_rgba(15,43,29,0.06)] backdrop-blur">
                  <p className="text-sm font-semibold uppercase tracking-[0.18em] text-[#087a3a]">
                    Recommendations
                  </p>
                  <h2 className="mt-2 text-2xl font-semibold text-[#0d2217]">
                    Next actions
                  </h2>

                  <div className="mt-5 grid gap-3">
                    {summaryData.summary.recommendations.length === 0 ? (
                      <p className="rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] p-4 text-sm text-[#5a7668]">
                        No recommendations were generated.
                      </p>
                    ) : (
                      summaryData.summary.recommendations.slice(0, 5).map((item, index) => (
                        <div
                          key={`${item}-${index}`}
                          className="rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] p-4"
                        >
                          <p className="text-sm leading-7 text-[#173128]">
                            <span className="font-semibold text-[#15803d]">
                              {index + 1}.
                            </span>{' '}
                            {item}
                          </p>
                        </div>
                      ))
                    )}
                  </div>
                </section>

                <section className="rounded-[32px] border border-[#dceee3] bg-white/95 p-6 shadow-[0_22px_60px_rgba(15,43,29,0.06)] backdrop-blur">
                  <div className="flex flex-wrap items-center justify-between gap-4">
                    <div>
                      <p className="text-sm font-semibold uppercase tracking-[0.18em] text-[#087a3a]">
                        Key findings
                      </p>
                      <h2 className="mt-2 text-2xl font-semibold text-[#0d2217]">
                        Structured summary output
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
                    {summaryData.summary.keyFindings.length === 0 ? (
                      <p className="rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] p-4 text-sm text-[#5a7668]">
                        No key findings were generated.
                      </p>
                    ) : (
                      summaryData.summary.keyFindings.slice(0, 5).map((item) => (
                        <article
                          key={item.id}
                          className="rounded-[24px] border border-[#e4f2e9] bg-[#f8fffa] p-5"
                        >
                          <div className="flex flex-wrap items-center gap-3">
                            <span
                              className={`inline-flex rounded-full border px-3 py-1 text-xs font-semibold ${severityBadgeClass(
                                item.severity
                              )}`}
                            >
                              {item.severity}
                            </span>

                            <span className={`text-sm font-semibold ${scoreTone(item.score)}`}>
                              Score {item.score}
                            </span>

                            <span className="rounded-full border border-[#dcefe2] bg-white px-3 py-1 text-xs font-semibold text-[#173128]">
                              {item.asset}
                            </span>
                          </div>

                          <h3 className="mt-4 text-lg font-semibold text-[#0d2217]">
                            {item.title}
                          </h3>

                          <p className="mt-2 text-sm leading-7 text-[#173128]">
                            {item.summary}
                          </p>

                          <div className="mt-4 flex flex-wrap gap-3">
                            <ActionLink href={`/results/${item.id}`}>Open Finding</ActionLink>
                            <ActionLink href={`/reports/${summaryData.report.id}`}>Parent Report</ActionLink>
                          </div>
                        </article>
                      ))
                    )}
                  </div>
                </section>
              </div>

              <aside className="space-y-5">
                <Panel title="Parser and grounding">
                  <div className="grid gap-3">
                    <QualityBox label="Parsing status" value={summaryData.report.parsingStatus} helper={`Parser version ${summaryData.report.parserVersion ?? '-'}`} />
                    <QualityBox label="Average coverage" value={`${summaryData.summary.grounding.averageFieldCoverage}%`} helper="Grounding score" />
                    <QualityBox label="Fully grounded" value={String(summaryData.summary.grounding.fullyGroundedFindings)} helper="Complete finding fields" />
                    <QualityBox label="Partially grounded" value={String(summaryData.summary.grounding.partiallyGroundedFindings)} helper="Needs analyst review" />
                  </div>
                </Panel>

                <Panel title="Grounding breakdown">
                  <div className="grid gap-3">
                    <GroundingRow label="With summary" value={summaryData.summary.grounding.findingsWithSummary} total={summaryData.summary.stats.totalFindings} />
                    <GroundingRow label="With impact" value={summaryData.summary.grounding.findingsWithImpact} total={summaryData.summary.stats.totalFindings} />
                    <GroundingRow label="With evidence" value={summaryData.summary.grounding.findingsWithEvidence} total={summaryData.summary.stats.totalFindings} />
                    <GroundingRow label="With remediation" value={summaryData.summary.grounding.findingsWithRemediation} total={summaryData.summary.stats.totalFindings} />
                  </div>
                </Panel>

                <Panel title="Affected assets">
                  <div className="space-y-3">
                    {summaryData.summary.affectedAssets.length === 0 ? (
                      <p className="text-sm text-[#5a7668]">No affected assets were identified.</p>
                    ) : (
                      summaryData.summary.affectedAssets.slice(0, 5).map((asset) => (
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
                                {asset.findingsCount} linked finding
                                {asset.findingsCount > 1 ? 's' : ''}
                              </p>
                            </div>
                            <span
                              className={`shrink-0 rounded-full border px-3 py-1 text-xs font-semibold ${severityBadgeClass(
                                asset.highestSeverity
                              )}`}
                            >
                              {asset.highestSeverity}
                            </span>
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </Panel>

                <Panel title="Parsing notes">
                  {summaryData.report.parsingNotes.length === 0 ? (
                    <p className="text-sm text-[#5a7668]">No parsing notes.</p>
                  ) : (
                    <div className="space-y-3">
                      {summaryData.report.parsingNotes.slice(0, 4).map((note, index) => (
                        <p
                          key={`${note}-${index}`}
                          className="rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] p-4 text-sm leading-6 text-[#173128]"
                        >
                          {note}
                        </p>
                      ))}
                    </div>
                  )}
                </Panel>
              </aside>
            </section>
          </>
        ) : (
          !isLoadingReports &&
          !summaryError &&
          reports.length > 0 && (
            <section className="mt-8 rounded-[28px] border border-dashed border-[#c4e3cf] bg-white p-10 text-center shadow-sm">
              <p className="text-lg font-semibold text-[#173128]">
                Select a report to generate its summary.
              </p>
              <p className="mt-2 text-sm text-[#5a7668]">
                The page will display grounded summaries, confidence, recommendations,
                and key findings.
              </p>
            </section>
          )
        )}
      </section>

      <style>{`
        @keyframes summary-float {
          0%, 100% { transform: translateY(0) rotate(0deg); }
          50% { transform: translateY(-12px) rotate(2deg); }
        }

        .summary-float { animation: summary-float 6.2s ease-in-out infinite; }
        .summary-platform { transform: perspective(800px) rotateX(58deg); }
      `}</style>
    </main>
  )
}

function MetricCard(props: {
  label: string
  value: string
  helper?: string
}) {
  return (
    <div className="rounded-[26px] border border-[#dceee3] bg-white p-5 shadow-[0_22px_60px_rgba(15,43,29,0.05)] transition hover:-translate-y-1 hover:shadow-[0_30px_80px_rgba(15,43,29,0.09)]">
      <p className="text-sm font-medium text-[#5a7668]">{props.label}</p>
      <p className="mt-3 text-3xl font-semibold tracking-tight text-[#0d2217]">
        {props.value}
      </p>
      {props.helper ? (
        <p className="mt-2 text-sm leading-6 text-[#5a7668]">{props.helper}</p>
      ) : null}
    </div>
  )
}

function TextPanel({ label, body }: { label: string; body: string }) {
  return (
    <div className="rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] p-5">
      <p className="text-sm font-semibold text-[#4d6b5b]">{label}</p>
      <p className="mt-3 text-base leading-8 text-[#173128]">{body}</p>
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
