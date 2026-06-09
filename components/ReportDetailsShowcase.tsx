'use client'

import type { ReportRiskResult } from '@/lib/server/risk-scoring'
import type { ReportSummaryResult } from '@/lib/server/summarization'
import type { StoredFinding, StoredReport } from '@/lib/server/types'
import { getWorkspaceQualityMetrics } from '@/lib/ui-quality'
import Link from 'next/link'
import type { ReactNode } from 'react'
import { useMemo } from 'react'

type Severity = StoredFinding['severity']
type FindingStatus = StoredFinding['status']

type ReadinessState = 'Ready' | 'Needs Review' | 'Incomplete'

const severityWeight: Record<Severity, number> = {
  Critical: 4,
  High: 3,
  Medium: 2,
  Low: 1,
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

function cleanText(value: string | null | undefined, fallback = '—') {
  const text = String(value ?? '').replace(/\s+/g, ' ').trim()
  return text || fallback
}

function truncate(value: string | null | undefined, max = 170) {
  const text = cleanText(value, '')
  if (!text) return '—'
  if (text.length <= max) return text
  return `${text.slice(0, max - 1).trim()}…`
}

function severityClass(severity: Severity) {
  switch (severity) {
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

function statusClass(status: FindingStatus | StoredReport['status']) {
  switch (status) {
    case 'Ready':
    case 'Resolved':
      return 'border-emerald-200 bg-emerald-50 text-emerald-700'
    case 'Reviewed':
    case 'In Review':
      return 'border-blue-200 bg-blue-50 text-blue-700'
    case 'Open':
      return 'border-orange-200 bg-orange-50 text-orange-700'
    case 'Pending':
      return 'border-amber-200 bg-amber-50 text-amber-700'
    default:
      return 'border-slate-200 bg-slate-50 text-slate-700'
  }
}


function scoreClass(score: number) {
  if (score >= 85) return 'text-red-700'
  if (score >= 70) return 'text-orange-700'
  if (score >= 40) return 'text-amber-700'
  return 'text-emerald-700'
}

function confidenceLabel(value: number | undefined) {
  if (typeof value !== 'number') return '—'
  return `${Math.round(value)}%`
}

function confidenceClass(value: number | undefined) {
  if (typeof value !== 'number') return 'border-slate-200 bg-slate-50 text-slate-600'
  if (value >= 85) return 'border-emerald-200 bg-emerald-50 text-emerald-700'
  if (value >= 70) return 'border-blue-200 bg-blue-50 text-blue-700'
  if (value >= 50) return 'border-amber-200 bg-amber-50 text-amber-700'
  return 'border-red-200 bg-red-50 text-red-700'
}


function getReadinessState(input: {
  findingsCount: number
  needsReviewCount: number
  missingEvidenceCount: number
  missingRemediationCount: number
}): ReadinessState {
  if (
    input.findingsCount === 0 ||
    input.missingEvidenceCount > 0 ||
    input.missingRemediationCount > 0
  ) {
    return 'Incomplete'
  }

  if (input.needsReviewCount > 0) return 'Needs Review'
  return 'Ready'
}

function topFindings(findings: StoredFinding[], risk: ReportRiskResult) {
  const riskByFindingId = new Map(
    risk.allFindings.map((item) => [item.findingId, item])
  )

  return [...findings]
    .sort((a, b) => {
      const aRisk = riskByFindingId.get(a.id)?.riskScore ?? a.score ?? 0
      const bRisk = riskByFindingId.get(b.id)?.riskScore ?? b.score ?? 0
      const severityDiff = severityWeight[b.severity] - severityWeight[a.severity]
      if (severityDiff !== 0) return severityDiff
      return bRisk - aRisk
    })
    .slice(0, 6)
    .map((finding) => ({
      finding,
      risk: riskByFindingId.get(finding.id),
    }))
}

function countCves(findings: StoredFinding[]) {
  return new Set(
    findings
      .map((finding) => cleanText(finding.cve, ''))
      .filter((value) => /^CVE-\d{4}-\d{4,}$/i.test(value))
  ).size
}

function buildReportFingerprint(report: StoredReport, findings: StoredFinding[]) {
  const cveCount = countCves(findings)
  const affectedAssets = new Set(findings.map((finding) => finding.asset).filter(Boolean)).size
  const highOrCritical = findings.filter(
    (finding) => finding.severity === 'Critical' || finding.severity === 'High'
  ).length

  return [
    { label: 'AI-extracted findings', value: String(findings.length) },
    { label: 'CVEs detected', value: String(cveCount) },
    { label: 'Affected assets', value: String(affectedAssets) },
    { label: 'Critical / High', value: String(highOrCritical) },
    { label: 'Source type', value: report.type },
  ]
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

  const data = useMemo(() => {
    const openFindings = findings.filter((item) => item.status === 'Open').length
    const quality = getWorkspaceQualityMetrics(findings, [report])
    const readinessState = getReadinessState({
      findingsCount: findings.length,
      needsReviewCount: quality.needsReviewCount,
      missingEvidenceCount: quality.missingEvidenceCount,
      missingRemediationCount: quality.missingRemediationCount,
    })
    const exportReadiness = clamp(
      100 -
        quality.needsReviewCount * 12 -
        quality.lowConfidenceCount * 8 -
        quality.missingEvidenceCount * 14 -
        quality.missingRemediationCount * 14
    )

    const criticalFindings = findings.filter((item) => item.severity === 'Critical').length
    const highFindings = findings.filter((item) => item.severity === 'High').length
    const nlpFindings = findings.filter(
      (item) => item.provenance?.extractionMethod === 'nlp-hybrid'
    ).length
    const structuredFindings = findings.filter(
      (item) => item.provenance?.extractionMethod === 'structured-parser'
    ).length

    return {
      openFindings,
      quality,
      readinessState,
      exportReadiness,
      criticalFindings,
      highFindings,
      nlpFindings,
      structuredFindings,
      previewFindings: topFindings(findings, risk),
      fingerprint: buildReportFingerprint(report, findings),
      affectedAssets: summary.affectedAssets.slice(0, 5),
      topRisks: summary.topRisks.slice(0, 4),
      recommendations: summary.recommendations.slice(0, 5),
    }
  }, [findings, report, risk, summary])

  return (
    <main className="relative min-h-screen overflow-hidden bg-[#fbfefd] text-[#102016]">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_16%_8%,rgba(34,197,94,0.14),transparent_29%),radial-gradient(circle_at_84%_20%,rgba(8,122,58,0.10),transparent_32%),linear-gradient(180deg,#fbfefd_0%,#f5fbf7_100%)]" />
      <div className="pointer-events-none absolute left-[-120px] top-[360px] h-[360px] w-[560px] rounded-full bg-[#edf9f1] blur-3xl" />
      <div className="pointer-events-none absolute right-[-80px] top-24 h-[430px] w-[620px] rounded-full bg-[#dff7e8]/70 blur-3xl" />

      <section className="relative mx-auto w-full max-w-none px-7 pb-16 pt-8 2xl:px-12">
        <div className="mb-5 flex flex-wrap items-center justify-between gap-3">
          <Link
            href="/reports"
            className="rounded-2xl border border-[#cce8d6] bg-white/90 px-4 py-2 text-sm font-semibold text-[#087a3a] shadow-sm transition hover:-translate-y-0.5 hover:bg-[#f4fff7]"
          >
            Back to reports
          </Link>

          <div className="flex flex-wrap items-center gap-2 text-xs font-semibold text-[#5f7568]">
            <span className={`rounded-full border px-3 py-1 ${statusClass(report.status)}`}>
              {report.status}
            </span>
            <span className="rounded-full border border-[#cce8d6] bg-white/90 px-3 py-1">
              AI analysis ready
            </span>
            <span className="rounded-full border border-[#cce8d6] bg-white/90 px-3 py-1">
              {report.id}
            </span>
          </div>
        </div>

        <header className="relative overflow-hidden rounded-[36px] border border-[#d7ecdf] bg-white/92 p-7 shadow-[0_26px_90px_rgba(15,43,29,0.08)] backdrop-blur">
          <div className="pointer-events-none absolute inset-0 opacity-80">
            <NeuralRibbon />
          </div>
          <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(135deg,rgba(8,122,58,0.06),transparent_40%),radial-gradient(circle_at_73%_42%,rgba(34,197,94,0.13),transparent_26%)]" />

          <div className="relative grid gap-7 xl:grid-cols-[1.05fr_0.75fr_0.55fr]">
            <div className="min-w-0">
              <p className="text-xs font-semibold uppercase tracking-[0.28em] text-[#087a3a]">
                AI-powered report intelligence
              </p>
              <h1 className="mt-4 max-w-5xl text-4xl font-semibold tracking-[-0.05em] text-[#111827] md:text-5xl">
                <span className="text-[#087a3a]">AI</span> Report Intelligence View
              </h1>
              <p className="mt-3 max-w-4xl truncate text-xl font-semibold tracking-[-0.02em] text-[#102016]">
                {report.name}
              </p>
              <p className="mt-4 max-w-4xl text-base leading-8 text-[#607367]">
                The report has been interpreted as security intelligence, not plain text. The AI layer connects findings, affected assets, CVEs, evidence, risk, and recommendations into an action-ready view.
              </p>

              <div className="mt-6 grid max-w-5xl gap-3 sm:grid-cols-2 xl:grid-cols-5">
                {data.fingerprint.map((item) => (
                  <HeroFact key={item.label} label={item.label} value={item.value} />
                ))}
              </div>
            </div>

            <AiReportCore
              score={risk.overallRiskScore}
              confidence={summary.confidence}
              readiness={data.exportReadiness}
            />

            <div className="rounded-[28px] border border-[#d7ecdf] bg-white/84 p-5 shadow-[0_24px_70px_rgba(15,43,29,0.08)] backdrop-blur">
              <p className="text-xs font-semibold uppercase tracking-[0.22em] text-[#087a3a]">
                Powered by Advanced AI
              </p>
              <p className="mt-3 text-sm leading-7 text-[#607367]">
                Summary, risk reasoning, entity extraction, and prioritization are generated from report evidence and extracted finding metadata.
              </p>

              <div className="mt-5 space-y-3">
                <AiCapability label="Context reasoning" value={summary.grounding.averageFieldCoverage} />
                <AiCapability label="Extraction confidence" value={summary.confidence} />
                <AiCapability label="Export readiness" value={data.exportReadiness} />
              </div>
            </div>
          </div>
        </header>

        <section className="mt-5 grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
          <MetricCard
            label="AI risk score"
            value={`${risk.overallRiskScore}/100`}
            helper={risk.overallRiskBand}
            valueClass={scoreClass(risk.overallRiskScore)}
          />
          <MetricCard
            label="Total findings"
            value={String(summary.stats.totalFindings)}
            helper={`${data.openFindings} still open`}
          />
          <MetricCard
            label="Critical / High"
            value={`${data.criticalFindings + data.highFindings}`}
            helper={`${data.criticalFindings} critical, ${data.highFindings} high`}
          />
          <MetricCard
            label="AI confidence"
            value={`${summary.confidence}%`}
            helper={`${data.quality.confidenceSampleSize} confidence samples`}
          />
          <MetricCard
            label="Report readiness"
            value={`${data.exportReadiness}%`}
            helper={data.readinessState}
          />
        </section>

        <section className="mt-6 grid gap-6 xl:grid-cols-[1.1fr_0.9fr]">
          <Panel
            eyebrow="AI-generated executive view"
            title="Reasoned report summary"
            action={
              <Link href={`/summarization?reportId=${reportIdParam}`} className="text-sm font-semibold text-[#087a3a] hover:underline">
                Open summary
              </Link>
            }
          >
            <p className="text-base leading-8 text-[#173128]">
              {summary.executiveSummary}
            </p>

            <div className="mt-6 grid gap-3 md:grid-cols-4">
              <MiniMetric label="Open findings" value={String(summary.stats.openCount)} />
              <MiniMetric label="Distinct assets" value={String(summary.stats.distinctAssets)} />
              <MiniMetric label="Grounding" value={`${summary.grounding.averageFieldCoverage}%`} />
              <MiniMetric label="Generated" value={shortDate(summary.generatedAtIso)} />
            </div>

            <div className="mt-6 rounded-[24px] border border-[#dceee3] bg-[#fbfffd] p-4">
              <p className="text-xs font-semibold uppercase tracking-[0.18em] text-[#087a3a]">
                AI rationale
              </p>
              <div className="mt-3 grid gap-2">
                {risk.rationale.slice(0, 4).map((item, index) => (
                  <p key={`${item}-${index}`} className="text-sm leading-6 text-[#5f7568]">
                    <span className="font-semibold text-[#087a3a]">{index + 1}.</span> {item}
                  </p>
                ))}
              </div>
            </div>
          </Panel>

          <Panel eyebrow="Next actions" title="Continue the investigation">
            <div className="grid gap-3 sm:grid-cols-2">
              <ActionTile href={`/results?reportId=${reportIdParam}`} title="View findings" detail="Inspect extracted vulnerabilities" primary />
              <ActionTile href={`/risk-scoring?reportId=${reportIdParam}`} title="Risk scoring" detail="Review score factors" />
              <ActionTile href={`/graph?reportId=${reportIdParam}`} title="Knowledge graph" detail="Map entities and relationships" />
              <ActionTile href={`/attack-paths?reportId=${reportIdParam}`} title="Attack paths" detail="Predict likely paths" />
              <ActionTile href={`/recommendations?reportId=${reportIdParam}`} title="Recommendations" detail="Plan mitigations" />
              <ActionTile href={`/export?reportId=${reportIdParam}`} title="Export report" detail="Download final package" />
            </div>
          </Panel>
        </section>

        <section className="mt-6 grid gap-6 xl:grid-cols-[1.15fr_0.85fr]">
          <Panel
            eyebrow="Finding intelligence"
            title="Highest priority findings"
            action={
              <Link href={`/results?reportId=${reportIdParam}`} className="text-sm font-semibold text-[#087a3a] hover:underline">
                View all findings
              </Link>
            }
          >
            {data.previewFindings.length === 0 ? (
              <EmptyBox title="No extracted findings" text="Analyze a richer report or review the extraction notes for parsing issues." />
            ) : (
              <>
                <div className="hidden overflow-hidden rounded-[24px] border border-[#dceee3] lg:block">
                  <table className="min-w-full divide-y divide-[#e8f4ec] text-left text-sm">
                    <thead className="bg-[#fbfffd] text-xs uppercase tracking-[0.12em] text-[#748579]">
                      <tr>
                        <th className="px-4 py-3 font-semibold">Finding</th>
                        <th className="px-4 py-3 font-semibold">Severity</th>
                        <th className="px-4 py-3 font-semibold">Asset</th>
                        <th className="px-4 py-3 font-semibold">AI risk</th>
                        <th className="px-4 py-3 font-semibold">Confidence</th>
                        <th className="px-4 py-3 font-semibold">Status</th>
                      </tr>
                    </thead>

                    <tbody className="divide-y divide-[#eef6f1] bg-white">
                      {data.previewFindings.map(({ finding, risk: findingRisk }) => (
                        <FindingRow key={finding.id} finding={finding} risk={findingRisk} />
                      ))}
                    </tbody>
                  </table>
                </div>

                <div className="grid gap-3 lg:hidden">
                  {data.previewFindings.map(({ finding, risk: findingRisk }) => (
                    <FindingCard key={finding.id} finding={finding} risk={findingRisk} />
                  ))}
                </div>
              </>
            )}
          </Panel>

          <Panel eyebrow="AI reasoning console" title="Understanding state">
            <div className="relative overflow-hidden rounded-[26px] border border-[#d7ecdf] bg-[#f8fffb] p-5">
              <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(90deg,transparent,rgba(8,122,58,0.06),transparent)] ai-scan" />
              <div className="relative grid gap-4">
                <ReasoningStep
                  label="Context understanding"
                  detail="AI reads report sections, findings, evidence, and scope."
                  value={summary.grounding.averageFieldCoverage}
                  state="Ready"
                />
                <ReasoningStep
                  label="Entity recognition"
                  detail="CVEs, assets, domains, services, and finding metadata."
                  value={summary.confidence}
                  state="Ready"
                />
                <ReasoningStep
                  label="Relationship extraction"
                  detail="Connects vulnerabilities to assets, impact, and likely attack flow."
                  value={Math.max(62, risk.overallRiskScore - 4)}
                  state="Prepared"
                />
                <ReasoningStep
                  label="Risk intelligence"
                  detail="Ranks issues by severity, exposure, confidence, and exploitability."
                  value={risk.overallRiskScore}
                  state={risk.overallRiskBand}
                />
              </div>
            </div>
          </Panel>
        </section>

        <section className="mt-6 grid gap-6 xl:grid-cols-3">
          <Panel eyebrow="Remediation" title="Key recommendations">
            {data.recommendations.length === 0 ? (
              <EmptyBox title="No recommendations" text="No recommendations were generated for this report." />
            ) : (
              <div className="space-y-3">
                {data.recommendations.map((item, index) => (
                  <div key={`${item}-${index}`} className="rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] p-4">
                    <p className="text-sm leading-7 text-[#173128]">
                      <span className="font-semibold text-[#087a3a]">{index + 1}.</span> {item}
                    </p>
                  </div>
                ))}
              </div>
            )}
          </Panel>

          <Panel eyebrow="Exposure" title="Affected assets">
            {data.affectedAssets.length === 0 ? (
              <EmptyBox title="No assets detected" text="No affected assets were identified in the extracted findings." />
            ) : (
              <div className="space-y-3">
                {data.affectedAssets.map((asset) => (
                  <div key={asset.asset} className="rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] p-4">
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <p className="truncate font-semibold text-[#0f2b1d]">{asset.asset}</p>
                        <p className="mt-1 text-sm text-[#5a7668]">
                          {asset.findingsCount} linked finding{asset.findingsCount > 1 ? 's' : ''}
                        </p>
                      </div>
                      <span className={`shrink-0 rounded-full border px-3 py-1 text-xs font-semibold ${severityClass(asset.highestSeverity)}`}>
                        {asset.highestSeverity}
                      </span>
                    </div>
                    <ProgressBar value={asset.highestScore} className="mt-4" />
                  </div>
                ))}
              </div>
            )}
          </Panel>

          <Panel eyebrow="Quality" title="Export readiness">
            <div className="rounded-[24px] border border-[#e4f2e9] bg-[#f8fffa] p-5">
              <div className="flex items-center justify-between gap-4">
                <span className={`rounded-full border px-3 py-1 text-xs font-semibold ${readinessClass(data.readinessState)}`}>
                  {data.readinessState}
                </span>
                <span className="text-3xl font-semibold text-[#0d2217]">{data.exportReadiness}%</span>
              </div>
              <ProgressBar value={data.exportReadiness} className="mt-5" />
            </div>

            <div className="mt-4 grid grid-cols-3 gap-3">
              <QualityChip label="Review" value={String(data.quality.needsReviewCount)} />
              <QualityChip label="Evidence" value={String(data.quality.missingEvidenceCount)} />
              <QualityChip label="Remediation" value={String(data.quality.missingRemediationCount)} />
            </div>

            <div className="mt-4 grid grid-cols-2 gap-3">
              <QualityBox label="NLP hybrid" value={String(data.nlpFindings)} />
              <QualityBox label="Structured" value={String(data.structuredFindings)} />
              <QualityBox label="Fallback" value={String(data.quality.fallbackCount)} />
              <QualityBox label="Low confidence" value={String(data.quality.lowConfidenceCount)} />
            </div>
          </Panel>
        </section>

        <section className="mt-6 rounded-[32px] border border-[#dceee3] bg-white/95 p-6 shadow-[0_22px_60px_rgba(15,43,29,0.06)] backdrop-blur">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div>
              <p className="text-sm font-semibold uppercase tracking-[0.18em] text-[#087a3a]">
                Phase II intelligence path
              </p>
              <h2 className="mt-2 text-2xl font-semibold tracking-[-0.03em] text-[#0d2217]">
                From report analysis to predictive defense
              </h2>
            </div>
            <Link href={`/recommendations?reportId=${reportIdParam}`} className="rounded-2xl bg-[#087a3a] px-5 py-3 text-sm font-semibold text-white shadow-[0_16px_32px_rgba(8,122,58,0.18)] transition hover:-translate-y-0.5 hover:bg-[#066b33]">
              Open recommendations
            </Link>
          </div>

          <div className="mt-5 grid gap-4 md:grid-cols-5">
            <PhaseCard title="Threat enrichment" text="Map CVEs and indicators to intelligence sources." />
            <PhaseCard title="Knowledge graph" text="Connect entities into a graph-ready model." />
            <PhaseCard title="Attack paths" text="Predict likely chains from entry to impact." />
            <PhaseCard title="Defense actions" text="Convert risk into prioritized controls." />
            <PhaseCard title="Executive export" text="Package validated results for stakeholders." />
          </div>
        </section>
      </section>

      <style>{`
        @keyframes ai-ribbon-drift {
          0%, 100% { transform: translateX(-1%) translateY(0); opacity: .66; }
          50% { transform: translateX(1%) translateY(-6px); opacity: .92; }
        }

        @keyframes ai-core-float {
          0%, 100% { transform: translateY(0) rotateX(62deg) rotateZ(0deg); }
          50% { transform: translateY(-10px) rotateX(62deg) rotateZ(5deg); }
        }

        @keyframes ai-document-float {
          0%, 100% { transform: translateY(0) rotateY(-14deg); }
          50% { transform: translateY(-13px) rotateY(14deg); }
        }

        @keyframes ai-pulse {
          0%, 100% { transform: scale(1); opacity: .46; }
          50% { transform: scale(1.18); opacity: .82; }
        }

        @keyframes ai-scan {
          0% { transform: translateX(-120%); }
          100% { transform: translateX(120%); }
        }

        .ai-ribbon { animation: ai-ribbon-drift 8s ease-in-out infinite; }
        .ai-core-base { animation: ai-core-float 7s ease-in-out infinite; transform-style: preserve-3d; }
        .ai-document { animation: ai-document-float 5.8s ease-in-out infinite; transform-style: preserve-3d; }
        .ai-pulse { animation: ai-pulse 3.4s ease-in-out infinite; }
        .ai-scan { animation: ai-scan 4.8s ease-in-out infinite; }

        @media (prefers-reduced-motion: reduce) {
          .ai-ribbon,
          .ai-core-base,
          .ai-document,
          .ai-pulse,
          .ai-scan {
            animation: none !important;
          }
        }
      `}</style>
    </main>
  )
}

function NeuralRibbon() {
  return (
    <div className="ai-ribbon absolute left-0 top-0 h-full w-full overflow-hidden">
      <svg viewBox="0 0 1200 260" className="h-full w-full" preserveAspectRatio="none">
        <path d="M0 120 C150 30 280 210 430 105 S760 70 910 145 1110 100 1200 70" fill="none" stroke="rgba(8,122,58,.22)" strokeWidth="1.2" />
        <path d="M0 150 C170 90 260 130 400 155 S700 210 880 105 1080 20 1200 128" fill="none" stroke="rgba(22,163,74,.16)" strokeWidth="1" />
        <path d="M0 90 C140 140 250 40 420 86 S670 146 820 78 1020 162 1200 110" fill="none" stroke="rgba(8,122,58,.11)" strokeWidth="1" />
        {Array.from({ length: 22 }).map((_, index) => {
          const x = 42 + index * 54
          const y = 78 + ((index * 37) % 95)
          return <circle key={index} cx={x} cy={y} r="2" fill="rgba(8,122,58,.38)" />
        })}
      </svg>
    </div>
  )
}

function AiReportCore({
  score,
  confidence,
  readiness,
}: {
  score: number
  confidence: number
  readiness: number
}) {
  return (
    <div className="relative min-h-[300px] overflow-hidden rounded-[30px] border border-[#d7ecdf] bg-white/70 shadow-[0_24px_70px_rgba(15,43,29,0.08)] backdrop-blur">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_40%,rgba(22,163,74,.20),transparent_32%),linear-gradient(180deg,transparent,#f5fff8)]" />
      <div className="absolute left-1/2 top-[48%] h-28 w-56 -translate-x-1/2 rounded-[50%] border border-[#bde6ca] bg-gradient-to-b from-white to-[#e3f8eb] shadow-[0_30px_70px_rgba(8,122,58,.18)] ai-core-base" />
      <div className="absolute left-1/2 top-[35%] h-28 w-[92px] -translate-x-1/2 rounded-[26px] border border-[#bde6ca] bg-white/76 shadow-[0_24px_80px_rgba(8,122,58,.18)] ai-document">
        <div className="mx-auto mt-6 h-1.5 w-12 rounded-full bg-[#087a3a]/45" />
        <div className="mx-auto mt-3 h-1.5 w-10 rounded-full bg-[#087a3a]/30" />
        <div className="mx-auto mt-3 h-1.5 w-14 rounded-full bg-[#087a3a]/25" />
        <div className="mx-auto mt-3 h-1.5 w-9 rounded-full bg-[#087a3a]/25" />
      </div>
      <div className="absolute left-1/2 top-[34%] h-44 w-44 -translate-x-1/2 -translate-y-1/2 rounded-full border border-[#bde6ca] ai-pulse" />
      <div className="absolute left-1/2 top-[34%] h-28 w-28 -translate-x-1/2 -translate-y-1/2 rounded-full border border-[#bde6ca]/70 ai-pulse" style={{ animationDelay: '-1.4s' }} />
      <div className="absolute left-1/2 top-11 -translate-x-1/2 rounded-full bg-[#e9f8ef] px-5 py-3 text-lg font-semibold text-[#087a3a] shadow-[0_18px_42px_rgba(8,122,58,.16)]">
        AI
      </div>

      <div className="absolute bottom-4 left-4 right-4 rounded-[24px] border border-[#d7ecdf] bg-white/90 p-4 backdrop-blur">
        <div className="flex items-center justify-between gap-4 text-sm">
          <span className="font-semibold text-[#0d2217]">AI Engine Status</span>
          <span className="rounded-full bg-[#e9f8ef] px-3 py-1 text-xs font-semibold text-[#087a3a]">Active</span>
        </div>
        <div className="mt-3 grid gap-3 sm:grid-cols-3">
          <CoreMetric label="Risk" value={`${score}`} />
          <CoreMetric label="Confidence" value={`${confidence}%`} />
          <CoreMetric label="Ready" value={`${readiness}%`} />
        </div>
      </div>
    </div>
  )
}

function CoreMetric({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <p className="text-xs text-[#607367]">{label}</p>
      <p className="mt-1 text-lg font-semibold text-[#0d2217]">{value}</p>
    </div>
  )
}

function AiCapability({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-2xl border border-[#e1eee6] bg-[#fbfffd] p-3">
      <div className="flex items-center justify-between gap-3">
        <p className="text-sm font-semibold text-[#0d2217]">{label}</p>
        <p className="text-xs font-semibold text-[#087a3a]">{clamp(value)}%</p>
      </div>
      <ProgressBar value={value} className="mt-3" />
    </div>
  )
}

function HeroFact({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-2xl border border-[#dceee3] bg-white/82 px-4 py-3 shadow-sm backdrop-blur">
      <p className="text-[11px] font-semibold uppercase tracking-[0.14em] text-[#748579]">{label}</p>
      <p className="mt-2 truncate text-sm font-semibold text-[#0f2b1d]">{value}</p>
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
    <article className="group relative overflow-hidden rounded-[26px] border border-[#dceee3] bg-white p-5 shadow-[0_22px_60px_rgba(15,43,29,0.05)] transition duration-300 hover:-translate-y-1 hover:shadow-[0_30px_80px_rgba(15,43,29,0.09)]">
      <div className="pointer-events-none absolute right-4 top-4 h-20 w-20 rounded-full bg-[#e8f8ee] opacity-80 blur-2xl transition duration-500 group-hover:scale-150" />
      <p className="relative text-sm font-medium text-[#5a7668]">{label}</p>
      <p className={`relative mt-3 text-3xl font-semibold tracking-tight ${valueClass}`}>{value}</p>
      {helper ? <p className="relative mt-2 text-sm leading-6 text-[#5a7668]">{helper}</p> : null}
    </article>
  )
}

function Panel({
  eyebrow,
  title,
  action,
  children,
}: {
  eyebrow: string
  title: string
  action?: ReactNode
  children: ReactNode
}) {
  return (
    <section className="rounded-[32px] border border-[#dceee3] bg-white/95 p-6 shadow-[0_22px_60px_rgba(15,43,29,0.06)] backdrop-blur">
      <div className="mb-5 flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.18em] text-[#087a3a]">{eyebrow}</p>
          <h2 className="mt-2 text-2xl font-semibold tracking-[-0.03em] text-[#0d2217]">{title}</h2>
        </div>
        {action ? <div className="shrink-0">{action}</div> : null}
      </div>
      {children}
    </section>
  )
}

function MiniMetric({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] p-4">
      <p className="text-xs font-semibold uppercase tracking-[0.12em] text-[#5a7668]">{label}</p>
      <p className="mt-2 text-xl font-semibold text-[#0d2217]">{value}</p>
    </div>
  )
}

function ActionTile({
  href,
  title,
  detail,
  primary = false,
}: {
  href: string
  title: string
  detail: string
  primary?: boolean
}) {
  return (
    <Link
      href={href}
      className={
        primary
          ? 'group rounded-[22px] border border-[#087a3a] bg-[#087a3a] p-4 text-white shadow-[0_18px_42px_rgba(8,122,58,0.22)] transition hover:-translate-y-1 hover:bg-[#066b33]'
          : 'group rounded-[22px] border border-[#dceee3] bg-[#fbfffd] p-4 text-[#102016] transition hover:-translate-y-1 hover:border-[#b6dec5] hover:bg-white hover:shadow-[0_18px_45px_rgba(15,43,29,0.07)]'
      }
    >
      <p className="font-semibold">{title}</p>
      <p className={primary ? 'mt-1 text-sm text-white/76' : 'mt-1 text-sm text-[#5a7668]'}>{detail}</p>
      <div className={primary ? 'mt-3 h-1 rounded-full bg-white/40' : 'mt-3 h-1 rounded-full bg-[#e6f5eb]'}>
        <div className={primary ? 'h-full w-[62%] rounded-full bg-white' : 'h-full w-[62%] rounded-full bg-[#087a3a]'} />
      </div>
    </Link>
  )
}

function FindingRow({
  finding,
  risk,
}: {
  finding: StoredFinding
  risk?: ReportRiskResult['allFindings'][number]
}) {
  return (
    <tr className="align-top transition hover:bg-[#fbfffd]">
      <td className="px-4 py-3">
        <Link href={`/results/${finding.id}`} className="font-semibold text-[#0f2b1d] hover:text-[#087a3a]">
          {finding.title}
        </Link>
        <p className="mt-1 text-xs text-[#748579]">{finding.cve || finding.id}</p>
      </td>
      <td className="px-4 py-3">
        <Badge className={severityClass(finding.severity)}>{finding.severity}</Badge>
      </td>
      <td className="max-w-[190px] truncate px-4 py-3 text-[#5a7668]">{finding.asset}</td>
      <td className="px-4 py-3 font-semibold text-[#0d2217]">{risk?.riskScore ?? finding.score}</td>
      <td className="px-4 py-3">
        <Badge className={confidenceClass(finding.provenance?.parserConfidence)}>
          {confidenceLabel(finding.provenance?.parserConfidence)}
        </Badge>
      </td>
      <td className="px-4 py-3">
        <Badge className={statusClass(finding.status)}>{finding.status}</Badge>
      </td>
    </tr>
  )
}

function FindingCard({
  finding,
  risk,
}: {
  finding: StoredFinding
  risk?: ReportRiskResult['allFindings'][number]
}) {
  return (
    <Link href={`/results/${finding.id}`} className="rounded-[24px] border border-[#dceee3] bg-[#fbfffd] p-4 transition hover:-translate-y-1 hover:bg-white hover:shadow-[0_18px_45px_rgba(15,43,29,0.07)]">
      <div className="flex flex-wrap items-center gap-2">
        <Badge className={severityClass(finding.severity)}>{finding.severity}</Badge>
        <Badge className={statusClass(finding.status)}>{finding.status}</Badge>
        <Badge className={confidenceClass(finding.provenance?.parserConfidence)}>
          {confidenceLabel(finding.provenance?.parserConfidence)}
        </Badge>
      </div>
      <p className="mt-3 font-semibold text-[#0f2b1d]">{finding.title}</p>
      <p className="mt-2 text-sm text-[#5a7668]">{finding.asset}</p>
      <div className="mt-3 flex items-center justify-between text-sm">
        <span className="text-[#5a7668]">AI risk</span>
        <span className="font-semibold text-[#0d2217]">{risk?.riskScore ?? finding.score}</span>
      </div>
      <p className="mt-3 text-sm leading-6 text-[#5a7668]">{truncate(finding.summary || finding.impact, 150)}</p>
    </Link>
  )
}

function ReasoningStep({
  label,
  detail,
  value,
  state,
}: {
  label: string
  detail: string
  value: number
  state: string
}) {
  return (
    <div className="rounded-[22px] border border-[#dceee3] bg-white/88 p-4 shadow-sm">
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="font-semibold text-[#0d2217]">{label}</p>
          <p className="mt-1 text-sm leading-6 text-[#5a7668]">{detail}</p>
        </div>
        <span className="shrink-0 rounded-full border border-[#bfe6cc] bg-[#effaf3] px-3 py-1 text-xs font-semibold text-[#087a3a]">
          {state}
        </span>
      </div>
      <ProgressBar value={value} className="mt-4" />
    </div>
  )
}

function Badge({ className, children }: { className: string; children: ReactNode }) {
  return <span className={`inline-flex rounded-full border px-3 py-1 text-xs font-semibold ${className}`}>{children}</span>
}

function ProgressBar({
  value,
  className = '',
}: {
  value: number
  className?: string
}) {
  return (
    <div className={`h-2.5 overflow-hidden rounded-full bg-[#e6f5eb] ${className}`}>
      <div className="h-full rounded-full bg-gradient-to-r from-[#16a34a] to-[#087a3a] transition-all duration-700" style={{ width: `${clamp(value)}%` }} />
    </div>
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

function QualityBox({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] p-4">
      <p className="text-xs font-semibold uppercase tracking-wide text-[#5a7668]">{label}</p>
      <p className="mt-2 text-2xl font-semibold text-[#087a3a]">{value}</p>
    </div>
  )
}

function readinessClass(state: ReadinessState) {
  switch (state) {
    case 'Ready':
      return 'border-emerald-200 bg-emerald-50 text-emerald-700'
    case 'Needs Review':
      return 'border-amber-200 bg-amber-50 text-amber-700'
    case 'Incomplete':
      return 'border-orange-200 bg-orange-50 text-orange-700'
    default:
      return 'border-slate-200 bg-slate-50 text-slate-700'
  }
}

function EmptyBox({ title, text }: { title: string; text: string }) {
  return (
    <div className="rounded-[24px] border border-dashed border-[#cfe8d8] bg-[#fbfffd] p-6">
      <p className="font-semibold text-[#0d2217]">{title}</p>
      <p className="mt-2 text-sm leading-6 text-[#5a7668]">{text}</p>
    </div>
  )
}

function PhaseCard({ title, text }: { title: string; text: string }) {
  return (
    <div className="rounded-[24px] border border-[#e4f2e9] bg-[#f8fffa] p-4 transition hover:-translate-y-1 hover:bg-white hover:shadow-[0_18px_45px_rgba(15,43,29,0.07)]">
      <div className="mb-4 h-1.5 overflow-hidden rounded-full bg-[#e6f5eb]">
        <div className="h-full w-[76%] rounded-full bg-[#087a3a]" />
      </div>
      <p className="font-semibold text-[#0d2217]">{title}</p>
      <p className="mt-2 text-sm leading-6 text-[#5a7668]">{text}</p>
    </div>
  )
}
