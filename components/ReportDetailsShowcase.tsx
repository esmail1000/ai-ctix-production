// components/ReportDetailsShowcase.tsx
'use client'

import {
  ConfidenceBadge,
  ReadinessBadge,
  findingStatusClass,
  reportStatusClass,
  severityClass
} from '@/components/ui'
import type { ReportRiskResult } from '@/lib/server/risk-scoring'
import type { ReportSummaryResult } from '@/lib/server/summarization'
import type { StoredFinding, StoredReport } from '@/lib/server/types'
import {
  getWorkspaceQualityMetrics
} from '@/lib/ui-quality'
import Link from 'next/link'
import { useMemo } from 'react'

type RiskBand = 'Low' | 'Medium' | 'High' | 'Critical'

function riskBandClass(band: RiskBand) {
  switch (band) {
    case 'Critical':
      return 'border-red-200 bg-red-50 text-red-700'
    case 'High':
      return 'border-orange-200 bg-orange-50 text-orange-700'
    case 'Medium':
      return 'border-amber-200 bg-amber-50 text-amber-700'
    case 'Low':
      return 'border-emerald-200 bg-emerald-50 text-emerald-700'
    default:
      return 'border-slate-200 bg-slate-50 text-slate-700'
  }
}

function scoreTone(score: number) {
  if (score >= 85) return 'text-red-700'
  if (score >= 65) return 'text-orange-700'
  if (score >= 40) return 'text-amber-700'
  return 'text-emerald-700'
}

function isNlpFinding(finding: StoredFinding) {
  return finding.provenance?.extractionMethod === 'nlp-hybrid'
}

function formatExtractionMethod(method: string | undefined) {
  switch (method) {
    case 'nlp-hybrid':
      return 'NLP Hybrid'
    case 'structured-parser':
      return 'Structured Parser'
    case 'heuristic-fallback':
      return 'Heuristic Fallback'
    case 'manual':
      return 'Manual Review'
    case 'seed':
      return 'Seed Data'
    default:
      return 'Unknown'
  }
}

function percent(part: number, total: number) {
  if (total === 0) return 0
  return Math.round((part / total) * 100)
}

function clamp(value: number, min = 0, max = 100) {
  return Math.max(min, Math.min(max, value))
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

function topAffectedAssets(summary: ReportSummaryResult) {
  return summary.affectedAssets.slice(0, 4)
}

function topFindings(
  findings: StoredFinding[],
  risk: ReportRiskResult
) {
  const riskByFindingId = new Map(
    risk.allFindings.map((item) => [item.findingId, item])
  )

  return [...findings]
    .sort((a, b) => {
      const aRisk = riskByFindingId.get(a.id)?.riskScore ?? a.score ?? 0
      const bRisk = riskByFindingId.get(b.id)?.riskScore ?? b.score ?? 0
      return bRisk - aRisk
    })
    .slice(0, 5)
}

function ActionLink(props: {
  href: string
  children: React.ReactNode
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

export default function ReportDetailsShowcase({
  report,
  findings,
  summary,
  risk,
}: {
  report: StoredReport
  findings: StoredFinding[]
  summary: ReportSummaryResult
  risk: ReportRiskResult
}) {
  const reportIdParam = encodeURIComponent(report.id)

  const openFindings = useMemo(
    () => findings.filter((item) => item.status === 'Open').length,
    [findings]
  )

  const nlpFindingsCount = useMemo(
    () => findings.filter((item) => isNlpFinding(item)).length,
    [findings]
  )

  const qualityMetrics = useMemo(
    () => getWorkspaceQualityMetrics(findings, [report]),
    [findings, report]
  )

  const readinessState =
    findings.length === 0 ||
    qualityMetrics.missingEvidenceCount + qualityMetrics.missingRemediationCount > 0
      ? 'Incomplete'
      : qualityMetrics.needsReviewCount > 0
        ? 'Needs Review'
        : 'Ready'

  const exportReadiness = clamp(
    100 -
      qualityMetrics.needsReviewCount * 14 -
      qualityMetrics.missingEvidenceCount * 16 -
      qualityMetrics.missingRemediationCount * 16
  )

  const affectedAssets = topAffectedAssets(summary)
  const previewFindings = topFindings(findings, risk)

  return (
    <main className="relative min-h-screen overflow-hidden bg-[#fbfefd] text-[#111827]">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_18%_10%,rgba(34,197,94,0.10),transparent_30%),radial-gradient(circle_at_86%_18%,rgba(8,122,58,0.08),transparent_34%)]" />
      <div className="pointer-events-none absolute right-0 top-24 h-[420px] w-[560px] rounded-full bg-[#dcf7e7]/60 blur-3xl" />
      <div className="pointer-events-none absolute left-0 top-[540px] h-[320px] w-[520px] rounded-full bg-[#eefaf3] blur-3xl" />

      <section className="relative mx-auto max-w-[1480px] px-6 pb-16 pt-10 lg:px-8">
        <Link
          href="/reports"
          className="inline-flex text-sm font-semibold text-[#087a3a] hover:underline"
        >
          Back to reports
        </Link>

        <header className="relative mt-5 overflow-hidden rounded-[34px] border border-[#dceee3] bg-white/92 p-7 shadow-[0_24px_80px_rgba(15,43,29,0.07)] backdrop-blur">
          <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(135deg,rgba(8,122,58,0.05),transparent_42%),radial-gradient(circle_at_86%_24%,rgba(22,163,74,0.12),transparent_28%)]" />
          <div className="pointer-events-none absolute right-[180px] bottom-8 h-20 w-52 rounded-[50%] border border-[#bfe6cc] bg-gradient-to-b from-white to-[#e5f8ec] shadow-[0_24px_60px_rgba(8,122,58,0.12)] report-platform" />
          <div className="pointer-events-none absolute right-20 top-12 h-24 w-24 rounded-full bg-gradient-to-br from-[#dff7e8] to-[#7ddf9b] shadow-[0_22px_55px_rgba(8,122,58,0.14)] report-float" />

          <div className="relative grid gap-8 lg:grid-cols-[1fr_0.7fr]">
            <div>
              <div className="flex flex-wrap items-center gap-3">
                <span
                  className={`rounded-full border px-3 py-1 text-xs font-semibold ${reportStatusClass(
                    report.status
                  )}`}
                >
                  {report.status}
                </span>

                <span className="rounded-full border border-[#c4e3cf] bg-[#f6fff9] px-3 py-1 text-xs font-semibold text-[#173128]">
                  Report ID: {report.id}
                </span>
              </div>

              <h1 className="mt-5 max-w-5xl text-4xl font-semibold tracking-[-0.04em] text-[#111827] md:text-5xl">
                {report.name}
              </h1>

              <p className="mt-4 max-w-4xl text-base leading-8 text-[#5f6f66]">
                Unified report analysis, grounded summary, risk scoring, and action-ready
                recommendations for this selected report.
              </p>

              <div className="mt-7 grid max-w-4xl gap-3 sm:grid-cols-2 xl:grid-cols-4">
                <HeroMeta label="Type" value={report.type} />
                <HeroMeta
                  label="Uploaded"
                  value={`${shortDate(report.uploadedAt)} ${shortTime(report.uploadedAt)}`}
                />
                <HeroMeta label="Owner" value={report.owner} />
                <HeroMeta label="Readiness" value={readinessState} />
              </div>
            </div>

            <div className="flex items-start justify-end">
              <div className="grid w-full max-w-[620px] grid-cols-2 gap-3 xl:grid-cols-3">
                <ActionLink href={`/results?reportId=${reportIdParam}`} primary>
                  View Findings
                </ActionLink>
                <ActionLink href={`/summarization?reportId=${reportIdParam}`}>
                  Open Summary
                </ActionLink>
                <ActionLink href={`/risk-scoring?reportId=${reportIdParam}`}>
                  Risk Scoring
                </ActionLink>
                <ActionLink href={`/graph?reportId=${reportIdParam}`}>
                  Attack Graph
                </ActionLink>
                <ActionLink href={`/export?reportId=${reportIdParam}`}>
                  Export PDF
                </ActionLink>
                <ActionLink href="/analyzer">
                  Analyze New Report
                </ActionLink>
              </div>
            </div>
          </div>
        </header>

        <section className="mt-5 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <MetricCard
            label="Findings"
            value={String(summary.stats.totalFindings)}
            helper={`${openFindings} open findings`}
          />
          <MetricCard
            label="Average confidence"
            value={
              qualityMetrics.confidenceSampleSize
                ? `${qualityMetrics.averageConfidence}%`
                : '—'
            }
            helper="Parser and model signal"
          />
          <MetricCard
            label="Risk score"
            value={`${risk.overallRiskScore}/100`}
            helper={risk.overallRiskBand}
            valueClass={scoreTone(risk.overallRiskScore)}
          />
          <MetricCard
            label="Export readiness"
            value={`${exportReadiness}%`}
            helper={readinessState}
          />
        </section>

        <section className="mt-6 grid gap-6 xl:grid-cols-[1fr_430px]">
          <div className="space-y-6">
            <section className="rounded-[32px] border border-[#dceee3] bg-white/95 p-6 shadow-[0_22px_60px_rgba(15,43,29,0.06)] backdrop-blur">
              <p className="text-sm font-semibold uppercase tracking-[0.18em] text-[#087a3a]">
                Executive summary
              </p>
              <p className="mt-4 text-base leading-8 text-[#173128]">
                {summary.executiveSummary}
              </p>

              <div className="mt-6 grid gap-4 md:grid-cols-4">
                <MiniMetric label="Total findings" value={String(summary.stats.totalFindings)} />
                <MiniMetric label="Open findings" value={String(summary.stats.openCount)} />
                <MiniMetric label="Distinct assets" value={String(summary.stats.distinctAssets)} />
                <MiniMetric label="Confidence" value={`${summary.confidence}%`} />
              </div>
            </section>

            <section className="rounded-[32px] border border-[#dceee3] bg-white/95 p-6 shadow-[0_22px_60px_rgba(15,43,29,0.06)] backdrop-blur">
              <div className="flex flex-wrap items-center justify-between gap-4">
                <div>
                  <p className="text-sm font-semibold uppercase tracking-[0.18em] text-[#087a3a]">
                    Top findings preview
                  </p>
                  <h2 className="mt-2 text-2xl font-semibold text-[#0d2217]">
                    Highest priority findings
                  </h2>
                </div>

                <Link
                  href={`/results?reportId=${reportIdParam}`}
                  className="rounded-2xl border border-[#c4e3cf] bg-white px-4 py-2 text-sm font-semibold text-[#173128] transition hover:bg-[#edfdf3]"
                >
                  View all findings
                </Link>
              </div>

              <div className="mt-5 overflow-hidden rounded-[24px] border border-[#dceee3]">
                <table className="min-w-full divide-y divide-[#e8f4ec] text-left text-sm">
                  <thead className="bg-[#fbfffd] text-xs uppercase tracking-[0.12em] text-[#748579]">
                    <tr>
                      <th className="px-4 py-3 font-semibold">Finding</th>
                      <th className="px-4 py-3 font-semibold">Severity</th>
                      <th className="px-4 py-3 font-semibold">Asset</th>
                      <th className="px-4 py-3 font-semibold">Confidence</th>
                      <th className="px-4 py-3 font-semibold">Status</th>
                    </tr>
                  </thead>

                  <tbody className="divide-y divide-[#eef6f1] bg-white">
                    {previewFindings.length === 0 ? (
                      <tr>
                        <td colSpan={5} className="px-4 py-6 text-[#5a7668]">
                          No findings were extracted for this report.
                        </td>
                      </tr>
                    ) : (
                      previewFindings.map((finding) => (
                        <tr key={finding.id} className="align-top transition hover:bg-[#fbfffd]">
                          <td className="px-4 py-3">
                            <Link
                              href={`/results/${finding.id}`}
                              className="font-semibold text-[#0f2b1d] hover:text-[#087a3a]"
                            >
                              {finding.title}
                            </Link>
                            <p className="mt-1 text-xs text-[#748579]">{finding.id}</p>
                          </td>
                          <td className="px-4 py-3">
                            <span
                              className={`inline-flex rounded-full border px-3 py-1 text-xs font-semibold ${severityClass(
                                finding.severity
                              )}`}
                            >
                              {finding.severity}
                            </span>
                          </td>
                          <td className="max-w-[190px] truncate px-4 py-3 text-[#5a7668]">
                            {finding.asset}
                          </td>
                          <td className="px-4 py-3">
                            <ConfidenceBadge value={finding.provenance?.parserConfidence} />
                          </td>
                          <td className="px-4 py-3">
                            <span
                              className={`inline-flex rounded-full border px-3 py-1 text-xs font-semibold ${findingStatusClass(
                                finding.status
                              )}`}
                            >
                              {finding.status}
                            </span>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </section>

            <section className="rounded-[32px] border border-[#dceee3] bg-white/95 p-6 shadow-[0_22px_60px_rgba(15,43,29,0.06)] backdrop-blur">
              <p className="text-sm font-semibold uppercase tracking-[0.18em] text-[#087a3a]">
                Key recommendations
              </p>

              <div className="mt-5 grid gap-3">
                {summary.recommendations.length === 0 ? (
                  <p className="rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] p-4 text-sm text-[#5a7668]">
                    No recommendations were generated.
                  </p>
                ) : (
                  summary.recommendations.slice(0, 4).map((item, index) => (
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
          </div>

          <aside className="space-y-5">
            <Panel title="Report quality">
              <ReadinessBadge state={readinessState} />

              <div className="mt-5 h-3 overflow-hidden rounded-full bg-[#e6f5eb]">
                <div
                  className="h-full rounded-full bg-[#087a3a]"
                  style={{ width: `${exportReadiness}%` }}
                />
              </div>

              <div className="mt-4 flex items-center justify-between text-sm">
                <span className="text-[#5a7668]">Overall export readiness</span>
                <span className="font-semibold text-[#0d2217]">{exportReadiness}%</span>
              </div>

              <div className="mt-5 grid grid-cols-3 gap-3">
                <QualityChip label="Needs review" value={String(qualityMetrics.needsReviewCount)} />
                <QualityChip label="Missing evidence" value={String(qualityMetrics.missingEvidenceCount)} />
                <QualityChip label="Missing remediation" value={String(qualityMetrics.missingRemediationCount)} />
              </div>
            </Panel>

            <Panel title="Extraction quality">
              <div className="grid grid-cols-2 gap-3">
                <QualityBox
                  label="Parser confidence"
                  value={
                    qualityMetrics.confidenceSampleSize
                      ? `${qualityMetrics.averageConfidence}%`
                      : '—'
                  }
                  helper="Average"
                />
                <QualityBox
                  label="Grounding score"
                  value={`${summary.grounding.averageFieldCoverage}%`}
                  helper="Coverage"
                />
                <QualityBox
                  label="NLP findings"
                  value={String(nlpFindingsCount)}
                  helper="Hybrid results"
                />
                <QualityBox
                  label="Fallback findings"
                  value={String(qualityMetrics.fallbackCount)}
                  helper="Needs attention"
                />
              </div>
            </Panel>

            <Panel title="Affected assets">
              <div className="space-y-3">
                {affectedAssets.length === 0 ? (
                  <p className="text-sm text-[#5a7668]">No affected assets were identified.</p>
                ) : (
                  affectedAssets.map((asset) => (
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
                          className={`shrink-0 rounded-full border px-3 py-1 text-xs font-semibold ${severityClass(
                            asset.highestSeverity
                          )}`}
                        >
                          {asset.highestSeverity}
                        </span>
                      </div>

                      <p className="mt-3 text-sm text-[#173128]">
                        Highest score on this asset: {asset.highestScore}
                      </p>
                    </div>
                  ))
                )}
              </div>
            </Panel>

            <Panel title="Extraction notes">
              {report.parsingNotes && report.parsingNotes.length > 0 ? (
                <div className="space-y-3">
                  {report.parsingNotes.slice(0, 4).map((note, index) => (
                    <p
                      key={`${note}-${index}`}
                      className="rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] p-4 text-sm leading-6 text-[#173128]"
                    >
                      {note}
                    </p>
                  ))}
                </div>
              ) : (
                <p className="text-sm text-[#5a7668]">No extraction notes were recorded.</p>
              )}
            </Panel>
          </aside>
        </section>
      </section>

      <style>{`
        @keyframes report-float {
          0%, 100% { transform: translateY(0) rotate(0deg); }
          50% { transform: translateY(-12px) rotate(2deg); }
        }

        .report-float { animation: report-float 6.2s ease-in-out infinite; }
        .report-platform { transform: perspective(800px) rotateX(58deg); }
      `}</style>
    </main>
  )
}

function HeroMeta({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-2xl border border-[#dceee3] bg-white/85 px-4 py-3 shadow-sm">
      <p className="text-xs font-semibold uppercase tracking-[0.14em] text-[#748579]">
        {label}
      </p>
      <p className="mt-2 break-words text-sm font-semibold text-[#0f2b1d]">
        {value}
      </p>
    </div>
  )
}

function MetricCard({
  label,
  value,
  helper,
  valueClass = 'text-[#0d2217]',
}: {
  label: string
  value: string
  helper?: string
  valueClass?: string
}) {
  return (
    <div className="rounded-[26px] border border-[#dceee3] bg-white p-5 shadow-[0_22px_60px_rgba(15,43,29,0.05)] transition hover:-translate-y-1 hover:shadow-[0_30px_80px_rgba(15,43,29,0.09)]">
      <p className="text-sm font-medium text-[#5a7668]">{label}</p>
      <p className={`mt-3 text-3xl font-semibold tracking-tight ${valueClass}`}>
        {value}
      </p>
      {helper ? (
        <p className="mt-2 text-sm leading-6 text-[#5a7668]">{helper}</p>
      ) : null}
    </div>
  )
}

function MiniMetric({ label, value }: { label: string; value: string }) {
  return (
    <div className="border-[#e4f2e9] md:border-r md:last:border-r-0 md:pr-4">
      <p className="text-sm text-[#5a7668]">{label}</p>
      <p className="mt-2 text-2xl font-semibold text-[#0d2217]">{value}</p>
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
      <h2 className="mb-5 text-xl font-semibold text-[#0d2217]">{title}</h2>
      {children}
    </section>
  )
}

function QualityChip({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] p-3 text-center">
      <p className="text-lg font-semibold text-[#0d2217]">{value}</p>
      <p className="mt-1 text-xs leading-4 text-[#5a7668]">{label}</p>
    </div>
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
