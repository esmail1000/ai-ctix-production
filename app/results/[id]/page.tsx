// app/results/[id]/page.tsx
import {
  getFindingById,
  getRelatedFindings,
  getReportById,
  getReportName,
} from '@/lib/data-service'
import type { Finding, Severity } from '@/lib/mock-data'
import Link from 'next/link'
import { notFound } from 'next/navigation'

export const dynamic = 'force-dynamic'

type RiskBand = 'Low' | 'Medium' | 'High' | 'Critical'

const APP_TIME_ZONE = 'Africa/Cairo'

const severityOrder: Severity[] = ['Critical', 'High', 'Medium', 'Low']

const severityColors: Record<Severity, string> = {
  Critical: '#dc2626',
  High: '#f97316',
  Medium: '#eab308',
  Low: '#16a34a',
}

const severityBadgeClass: Record<Severity, string> = {
  Critical: 'border-red-200 bg-red-50 text-red-700',
  High: 'border-orange-200 bg-orange-50 text-orange-700',
  Medium: 'border-yellow-200 bg-yellow-50 text-yellow-700',
  Low: 'border-emerald-200 bg-emerald-50 text-emerald-700',
}

const statusBadgeClass: Record<string, string> = {
  Open: 'border-red-200 bg-red-50 text-red-700',
  'In Review': 'border-yellow-200 bg-yellow-50 text-yellow-700',
  Resolved: 'border-emerald-200 bg-emerald-50 text-emerald-700',
}

const riskBandClass: Record<RiskBand, string> = {
  Critical: 'border-red-200 bg-red-50 text-red-700',
  High: 'border-orange-200 bg-orange-50 text-orange-700',
  Medium: 'border-yellow-200 bg-yellow-50 text-yellow-700',
  Low: 'border-emerald-200 bg-emerald-50 text-emerald-700',
}

function safeText(value: unknown, fallback = 'Unknown') {
  const text = String(value ?? '').trim()
  if (!text || text === 'ΓÇö' || text === '╬ô├ç├╢' || text === 'Γò¼├┤Γö£├ºΓö£Γòó') return fallback
  return text
}

function clamp(value: number, min = 0, max = 100) {
  return Math.max(min, Math.min(max, value))
}

function normalizeConfidence(value: unknown) {
  const numeric = Number(value ?? 0)

  if (!Number.isFinite(numeric) || numeric <= 0) return 0

  const percentage = numeric <= 1 ? numeric * 100 : numeric

  return clamp(Math.round(percentage))
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

function scoreTone(score: number) {
  if (score >= 85) return 'text-red-700'
  if (score >= 65) return 'text-orange-700'
  if (score >= 40) return 'text-yellow-700'
  return 'text-emerald-700'
}

function scoreBand(score: number): RiskBand {
  if (score >= 85) return 'Critical'
  if (score >= 65) return 'High'
  if (score >= 40) return 'Medium'
  return 'Low'
}

function riskLabel(score: number) {
  if (score >= 85) return 'Critical exposure'
  if (score >= 65) return 'High priority'
  if (score >= 40) return 'Moderate priority'
  return 'Controlled'
}

function formatExtractionMethod(value: unknown) {
  return safeText(value, 'Hybrid')
    .split(/[_\s-]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase())
    .join(' ')
}

function reviewState(finding: Finding) {
  const confidence = normalizeConfidence(finding.provenance?.parserConfidence)
  const hasEvidence = safeText(finding.evidence, '').length > 0
  const hasRemediation = safeText(finding.remediation, '').length > 0

  if (finding.status === 'Resolved') return 'Ready'
  if (confidence < 70 || !hasEvidence || !hasRemediation) return 'Needs Review'
  return 'Ready'
}

function relatedSort(a: Finding, b: Finding) {
  return severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity) || (b.score ?? 0) - (a.score ?? 0)
}

function confidenceLabel(value: number) {
  if (value >= 80) return 'High confidence'
  if (value >= 50) return 'Medium confidence'
  return 'Low confidence'
}

export default async function FindingDetailsPage({
  params,
}: {
  params: Promise<{ id: string }>
}) {
  const { id } = await params
  const finding = await getFindingById(id)

  if (!finding) {
    notFound()
  }

  const [report, reportName, relatedFindings] = await Promise.all([
    getReportById(finding.reportId),
    getReportName(finding.reportId),
    getRelatedFindings(finding.id),
  ])

  const confidence = normalizeConfidence(finding.provenance?.parserConfidence)
  const extractionMethod = formatExtractionMethod(finding.provenance?.extractionMethod)
  const review = reviewState(finding)
  const riskScore = finding.score ?? 0
  const riskBand = scoreBand(riskScore)
  const related = relatedFindings.filter((item) => item.id !== finding.id).sort(relatedSort).slice(0, 5)
  const reportParam = encodeURIComponent(finding.reportId)
  const hasEvidence = safeText(finding.evidence, '').length > 0
  const hasRemediation = safeText(finding.remediation, '').length > 0

  return (
    <main className="relative min-h-screen overflow-hidden bg-[#fbfefd] text-[#111827]">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_18%_10%,rgba(34,197,94,0.12),transparent_30%),radial-gradient(circle_at_86%_18%,rgba(8,122,58,0.09),transparent_34%)]" />
      <div className="pointer-events-none absolute right-0 top-24 h-[440px] w-[580px] rounded-full bg-[#dcf7e7]/65 blur-3xl" />
      <div className="pointer-events-none absolute left-0 top-[590px] h-[330px] w-[540px] rounded-full bg-[#eefaf3] blur-3xl" />

      <section className="relative mx-auto max-w-[1500px] px-6 pb-16 pt-10 lg:px-8">
        <Link href={`/results?reportId=${reportParam}`} className="inline-flex text-sm font-semibold text-[#087a3a] hover:underline">
          Back to report findings
        </Link>

        <header className="relative mt-5 overflow-hidden rounded-[36px] border border-[#dceee3] bg-white/92 p-7 shadow-[0_24px_80px_rgba(15,43,29,0.07)] backdrop-blur">
          <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(135deg,rgba(8,122,58,0.05),transparent_42%),radial-gradient(circle_at_86%_24%,rgba(22,163,74,0.13),transparent_28%)]" />
          <div className="pointer-events-none absolute right-0 top-0 h-full w-1/2 opacity-20">
            <div className="absolute inset-0 bg-[linear-gradient(135deg,rgba(8,122,58,0.10)_25%,transparent_25%,transparent_50%,rgba(8,122,58,0.10)_50%,rgba(8,122,58,0.10)_75%,transparent_75%,transparent)] bg-[length:24px_24px]" />
          </div>

          <div className="relative grid gap-8 lg:grid-cols-[1fr_0.82fr]">
            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.22em] text-[#087a3a]">
                AI Finding Command View
              </p>

              <div className="mt-4 flex flex-wrap items-center gap-3">
                <Badge className={severityBadgeClass[finding.severity]}>{finding.severity}</Badge>
                <Badge className={statusBadgeClass[finding.status] ?? statusBadgeClass.Open}>{finding.status}</Badge>
                <Badge className={riskBandClass[riskBand]}>{riskBand}</Badge>
                <Badge className={review === 'Needs Review' ? 'border-yellow-200 bg-yellow-50 text-yellow-700' : 'border-emerald-200 bg-emerald-50 text-emerald-700'}>
                  {review}
                </Badge>
              </div>

              <h1 className="mt-4 max-w-4xl text-4xl font-semibold tracking-[-0.04em] text-[#111827] md:text-5xl">
                {safeText(finding.title, 'Untitled finding')}
              </h1>

              <p className="mt-4 max-w-4xl text-base leading-8 text-[#5f6f66]">
                {safeText(finding.summary, 'No summary was extracted for this finding.')}
              </p>

              <div className="mt-6 flex flex-wrap gap-3">
                <InfoPill label="Finding ID" value={finding.id} />
                <InfoPill label="Report" value={`${finding.reportId} - ${reportName}`} />
                <InfoPill label="Detected" value={shortDateTime(finding.detectedAt)} />
              </div>
            </div>

            <div className="relative min-h-[315px]">
              <div className="absolute left-[8%] top-[18%] h-24 w-44 rounded-[50%] border border-[#bfe6cc] bg-gradient-to-b from-white to-[#e5f8ec] shadow-[0_24px_60px_rgba(8,122,58,0.14)] finding-platform" />
              <div className="absolute right-[12%] top-[8%] h-36 w-36 rounded-full bg-gradient-to-br from-[#ecfff2] via-[#b9edc8] to-[#16a34a] shadow-[0_24px_65px_rgba(8,122,58,0.18)] finding-orb">
                <span className="absolute inset-4 rounded-full border border-white/70" />
                <span className="absolute left-1/2 top-1/2 h-5 w-5 -translate-x-1/2 -translate-y-1/2 rounded-full bg-white shadow-[0_0_24px_rgba(255,255,255,0.95)]" />
              </div>

              <div className="absolute left-[5%] bottom-[7%] w-[280px] rounded-[26px] border border-[#d2eadb] bg-white/88 p-4 shadow-[0_24px_70px_rgba(15,43,29,0.12)] backdrop-blur finding-panel">
                <p className="text-xs font-semibold uppercase tracking-[0.14em] text-[#748579]">AI reasoning</p>
                <p className={`mt-2 text-3xl font-semibold ${scoreTone(riskScore)}`}>{riskScore}</p>
                <p className="mt-1 text-sm text-[#5f6f66]">{riskLabel(riskScore)}</p>
                <div className="mt-4 h-2 overflow-hidden rounded-full bg-[#e6f5eb]">
                  <div className="h-full rounded-full bg-[#087a3a]" style={{ width: `${riskScore}%` }} />
                </div>
              </div>

              <div className="absolute right-[3%] bottom-[11%] w-[285px] rounded-[26px] border border-[#d2eadb] bg-white/88 p-4 shadow-[0_24px_70px_rgba(15,43,29,0.12)] backdrop-blur finding-panel-delay">
                <p className="text-xs font-semibold uppercase tracking-[0.14em] text-[#748579]">AI confidence</p>
                <div className="mt-3 flex items-end gap-3">
                  <p className="text-4xl font-semibold text-[#087a3a]">{confidence}%</p>
                  <p className="pb-2 text-sm text-[#5f6f66]">{confidenceLabel(confidence)}</p>
                </div>
                <div className="mt-4 grid gap-2">
                  <PulseLine label="Evidence" value={hasEvidence ? confidence : 0} />
                  <PulseLine label="Remediation" value={hasRemediation ? confidence : 0} />
                </div>
              </div>
            </div>
          </div>
        </header>

        <section className="mt-5 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <MetricCard label="Risk score" value={`${riskScore}/100`} helper={riskLabel(riskScore)} valueClass={scoreTone(riskScore)} />
          <MetricCard label="AI confidence" value={`${confidence}%`} helper={confidenceLabel(confidence)} />
          <MetricCard label="Review state" value={review} helper={finding.status} />
          <MetricCard label="Extraction" value={extractionMethod} helper="Parser provenance" />
        </section>

        <section className="mt-6 grid gap-6 xl:grid-cols-[1fr_430px]">
          <div className="space-y-6">
            <SectionCard title="Finding summary">
              <p className="text-base leading-8 text-[#173128]">
                {safeText(finding.summary, 'No description is available for this finding.')}
              </p>
            </SectionCard>

            <SectionCard title="Evidence extracted by AI">
              <div className="rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] p-5">
                <p className="text-sm leading-7 text-[#173128]">
                  {safeText(finding.evidence, 'Evidence was not extracted and should be reviewed manually.')}
                </p>
              </div>
            </SectionCard>

            <section className="grid gap-6 xl:grid-cols-2">
              <SectionCard title="Impact">
                <p className="text-sm leading-7 text-[#173128]">
                  {safeText(finding.impact, 'Impact was not extracted and should be reviewed manually.')}
                </p>
              </SectionCard>

              <SectionCard title="Remediation">
                <p className="text-sm leading-7 text-[#173128]">
                  {safeText(finding.remediation, 'Remediation was not extracted and should be reviewed manually.')}
                </p>
              </SectionCard>
            </section>

            <SectionCard title={`Related findings (${related.length})`}>
              {related.length === 0 ? (
                <p className="text-sm text-[#5f6f66]">No related findings were found.</p>
              ) : (
                <div className="grid gap-3">
                  {related.map((item) => (
                    <article key={item.id} className="rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] p-4">
                      <div className="flex flex-wrap items-center gap-3">
                        <Badge className={severityBadgeClass[item.severity]}>{item.severity}</Badge>
                        <span className={`text-sm font-semibold ${scoreTone(item.score ?? 0)}`}>Risk {item.score ?? 0}</span>
                        <span className="text-sm font-semibold text-[#173128]">Confidence {normalizeConfidence(item.provenance?.parserConfidence)}%</span>
                      </div>

                      <h3 className="mt-3 text-base font-semibold text-[#111827]">
                        {safeText(item.title, 'Untitled finding')}
                      </h3>

                      <p className="mt-2 line-clamp-2 text-sm leading-6 text-[#5f6f66]">
                        {safeText(item.summary, 'No summary available.')}
                      </p>

                      <div className="mt-3">
                        <Link href={`/results/${item.id}`} className="text-sm font-semibold text-[#087a3a] hover:underline">
                          View details
                        </Link>
                      </div>
                    </article>
                  ))}
                </div>
              )}
            </SectionCard>
          </div>

          <aside className="space-y-5">
            <SidePanel title="Actions">
              <div className="grid gap-3">
                <ActionLink href={`/results?reportId=${reportParam}`} primary>Report findings</ActionLink>
                <ActionLink href={`/reports/${reportParam}`}>Open report</ActionLink>
                <ActionLink href={`/risk-scoring?reportId=${reportParam}`}>Risk scoring</ActionLink>
                <ActionLink href={`/graph?reportId=${reportParam}`}>Knowledge graph</ActionLink>
                <ActionLink href={`/attack-paths?reportId=${reportParam}`}>Attack paths</ActionLink>
                <ActionLink href={`/recommendations?reportId=${reportParam}`}>Recommendations</ActionLink>
                <ActionLink href={`/export?reportId=${reportParam}`}>Export report</ActionLink>
              </div>
            </SidePanel>

            <SidePanel title="Finding context">
              <ContextLine label="Asset" value={safeText(finding.asset, 'investigation-scope')} />
              <ContextLine label="CVE" value={safeText(finding.cve, 'N/A')} />
              <ContextLine label="Report ID" value={finding.reportId} />
              <ContextLine label="Report name" value={reportName} />
              <ContextLine label="Report type" value={report?.type ?? 'Unknown'} />
              <ContextLine label="Report status" value={report?.status ?? 'Unknown'} />
              <ContextLine label="Uploaded" value={report?.uploadedAt ? shortDateTime(report.uploadedAt) : 'Unknown'} />
            </SidePanel>

            <SidePanel title="AI validation">
              <div className="flex items-center gap-5">
                <div
                  className="grid h-28 w-28 shrink-0 place-items-center rounded-full"
                  style={{ background: `conic-gradient(#087a3a ${confidence * 3.6}deg, #e6f5eb 0deg)` }}
                >
                  <div className="grid h-20 w-20 place-items-center rounded-full bg-white text-center shadow-inner">
                    <div>
                      <p className="text-2xl font-semibold text-[#111827]">{confidence}%</p>
                      <p className="text-xs text-[#748579]">Overall</p>
                    </div>
                  </div>
                </div>

                <div className="flex-1 space-y-3">
                  <ConfidenceLine label="Source coverage" value={confidence} />
                  <ConfidenceLine label="Evidence quality" value={hasEvidence ? confidence : 0} />
                  <ConfidenceLine label="Remediation quality" value={hasRemediation ? confidence : 0} />
                  <ConfidenceLine label="Extraction method" value={confidence} />
                </div>
              </div>
            </SidePanel>
          </aside>
        </section>
      </section>

      <style>{`
        @keyframes finding-orb {
          0%, 100% { transform: translateY(0) rotate(0deg) scale(1); }
          50% { transform: translateY(-14px) rotate(10deg) scale(1.03); }
        }

        @keyframes finding-panel {
          0%, 100% { transform: translateY(0); }
          50% { transform: translateY(-9px); }
        }

        .finding-orb { animation: finding-orb 7s ease-in-out infinite; }
        .finding-panel { animation: finding-panel 6.5s ease-in-out infinite; }
        .finding-panel-delay { animation: finding-panel 7.4s ease-in-out infinite; animation-delay: -1.4s; }
        .finding-platform { transform: perspective(800px) rotateX(58deg); }

        @media (prefers-reduced-motion: reduce) {
          .finding-orb,
          .finding-panel,
          .finding-panel-delay {
            animation: none;
          }
        }
      `}</style>
    </main>
  )
}

function ActionLink({
  href,
  children,
  primary = false,
}: {
  href: string
  children: React.ReactNode
  primary?: boolean
}) {
  return (
    <Link
      href={href}
      className={
        primary
          ? 'inline-flex items-center justify-center rounded-2xl bg-[#087a3a] px-5 py-3 text-sm font-semibold text-white shadow-[0_16px_32px_rgba(8,122,58,0.18)] transition hover:-translate-y-0.5 hover:bg-[#066b33]'
          : 'inline-flex items-center justify-center rounded-2xl border border-[#c4e3cf] bg-white px-5 py-3 text-sm font-semibold text-[#173128] transition hover:-translate-y-0.5 hover:bg-[#f4fff7]'
      }
    >
      {children}
    </Link>
  )
}

function Badge({ className, children }: { className: string; children: React.ReactNode }) {
  return <span className={`inline-flex rounded-full border px-3 py-1 text-xs font-semibold ${className}`}>{children}</span>
}

function InfoPill({ label, value }: { label: string; value: string }) {
  return (
    <span className="rounded-full border border-[#c4e3cf] bg-[#f6fff9] px-3 py-1.5 text-xs font-semibold text-[#173128]">
      {label}: {value}
    </span>
  )
}

function MetricCard({
  label,
  value,
  helper,
  valueClass,
}: {
  label: string
  value: string
  helper: string
  valueClass?: string
}) {
  return (
    <article className="rounded-[26px] border border-[#dceee3] bg-white p-5 shadow-[0_22px_60px_rgba(15,43,29,0.05)] transition hover:-translate-y-1 hover:shadow-[0_30px_80px_rgba(15,43,29,0.09)]">
      <p className="text-sm font-medium text-[#5a7668]">{label}</p>
      <p className={`mt-3 text-3xl font-semibold tracking-tight ${valueClass ?? 'text-[#0d2217]'}`}>{value}</p>
      <p className="mt-2 text-sm leading-6 text-[#5a7668]">{helper}</p>
    </article>
  )
}

function SectionCard({
  title,
  children,
}: {
  title: string
  children: React.ReactNode
}) {
  return (
    <section className="rounded-[32px] border border-[#dceee3] bg-white/95 p-6 shadow-[0_22px_60px_rgba(15,43,29,0.06)] backdrop-blur">
      <h2 className="mb-4 text-xl font-semibold text-[#111827]">{title}</h2>
      {children}
    </section>
  )
}

function SidePanel({
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

function ContextLine({ label, value }: { label: string; value: string }) {
  return (
    <div className="border-b border-[#e8f4ec] py-3 last:border-b-0">
      <p className="text-xs font-semibold uppercase tracking-[0.14em] text-[#748579]">{label}</p>
      <p className="mt-1 break-words text-sm font-semibold text-[#111827]">{value}</p>
    </div>
  )
}

function ConfidenceLine({ label, value }: { label: string; value: number }) {
  return (
    <div>
      <div className="mb-1 flex items-center justify-between gap-3 text-xs">
        <span className="font-semibold text-[#44554b]">{label}</span>
        <span className="text-[#748579]">{value}%</span>
      </div>
      <div className="h-2 overflow-hidden rounded-full bg-[#e6f5eb]">
        <div className="h-full rounded-full bg-[#087a3a]" style={{ width: `${value}%` }} />
      </div>
    </div>
  )
}

function PulseLine({ label, value }: { label: string; value: number }) {
  return (
    <div>
      <div className="mb-1 flex items-center justify-between text-xs font-semibold text-[#5f6f66]">
        <span>{label}</span>
        <span>{value}%</span>
      </div>
      <div className="h-1.5 overflow-hidden rounded-full bg-[#e6f5eb]">
        <div className="h-full rounded-full bg-[#087a3a]" style={{ width: `${value}%` }} />
      </div>
    </div>
  )
}
