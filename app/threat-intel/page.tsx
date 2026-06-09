import Link from 'next/link'
import type { ReactNode } from 'react'
import { redirect } from 'next/navigation'

import { listAnalysisReportsForUser } from '@/lib/server/analysis-repository'
import { getCurrentSessionFromCookies } from '@/lib/server/current-session'
import { getReportThreatIntel } from '@/lib/server/threat-intel/read-report-intel'

export const dynamic = 'force-dynamic'

type PageProps = {
  searchParams?: Promise<Record<string, string | string[] | undefined>>
}

type SourceStatus = {
  source?: string
  status?: string
  cveId?: string
  message?: string
  configured?: boolean
  error?: string
}

type ThreatIntelCve = {
  cveId?: string
  description?: string
  nvd?: boolean
  cisaKev?: boolean
  knownExploited?: boolean
  cvssScore?: number | null
  cvssSeverity?: string | null
  cvssVector?: string | null
  advisory?: {
    title?: string
    source?: string
    published?: string
    lastModified?: string
    description?: string
  } | null
  kev?: {
    vendorProject?: string
    product?: string
    vulnerabilityName?: string
    dateAdded?: string
    dueDate?: string
    requiredAction?: string
    knownRansomwareCampaignUse?: string
  } | null
  references?: string[]
  misp?: {
    enabled?: boolean | null
    matches?: number
    note?: string | null
  } | null
  mispItems?: Array<Record<string, unknown>>
  sourceStatuses?: SourceStatus[]
}

type ThreatIntelResult = {
  reportId: string
  cveCount: number
  cves?: ThreatIntelCve[]
  sourceStatuses?: SourceStatus[]
  warnings?: string[]
  notes?: string[]
}

function getParamValue(
  params: Record<string, string | string[] | undefined>,
  key: string
) {
  const value = params[key]
  return Array.isArray(value) ? value[0] ?? '' : value ?? ''
}

function extractCvesFromOwnedReport(value: unknown) {
  const text =
    JSON.stringify(value ?? '', (_key, item) =>
      typeof item === 'bigint' ? item.toString() : item
    ) ?? ''

  return Array.from(
    new Set((text.match(/CVE-\d{4}-\d{4,}/gi) ?? []).map((item) => item.toUpperCase()))
  ).sort()
}

function sourceTone(status: string | undefined) {
  if (status === 'ok') return 'border-emerald-200 bg-emerald-50 text-emerald-700'
  if (status === 'disabled') return 'border-slate-200 bg-slate-50 text-slate-700'
  if (status === 'not_found') return 'border-yellow-200 bg-yellow-50 text-yellow-700'
  if (status === 'error' || status === 'timeout') return 'border-red-200 bg-red-50 text-red-700'
  return 'border-[#c4e3cf] bg-[#f6fff9] text-[#173128]'
}

function boolLabel(value: boolean | undefined | null) {
  return value ? 'Yes' : 'No'
}

function safeNumber(value: number | null | undefined) {
  return typeof value === 'number' && Number.isFinite(value) ? String(value) : 'Not available'
}

function formatDate(value: string | undefined) {
  if (!value) return 'Not reported'
  const parsed = new Date(value)
  if (Number.isNaN(parsed.getTime())) return value
  return new Intl.DateTimeFormat('en', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  }).format(parsed)
}

function summarizeSources(statuses: SourceStatus[] = []) {
  return {
    ok: statuses.filter((item) => item.status === 'ok').length,
    notFound: statuses.filter((item) => item.status === 'not_found').length,
    disabled: statuses.filter((item) => item.status === 'disabled').length,
    errors: statuses.filter((item) => item.status === 'error' || item.status === 'timeout').length,
  }
}

export default async function ThreatIntelPage({ searchParams }: PageProps) {
  const session = await getCurrentSessionFromCookies()

  if (!session) {
    redirect('/login?next=/threat-intel')
  }

  const resolvedParams = searchParams ? await searchParams : {}
  const requestedReportId = getParamValue(resolvedParams, 'reportId').trim()
  const reports = await listAnalysisReportsForUser(session.userId)

  const selectedReport = requestedReportId
    ? reports.find((report) => report.id === requestedReportId) ?? null
    : reports[0] ?? null

  let intel: ThreatIntelResult | null = null
  let loadError: string | null = null

  if (selectedReport) {
    try {
      intel = (await getReportThreatIntel(selectedReport.id, {
        userId: session.userId,
        fallbackCves: extractCvesFromOwnedReport(selectedReport),
      })) as ThreatIntelResult
    } catch (error) {
      loadError = error instanceof Error ? error.message : String(error)
    }
  }

  const cves = intel?.cves ?? []
  const statuses = intel?.sourceStatuses ?? []
  const sourceSummary = summarizeSources(statuses)
  const knownExploitedCount = cves.filter((cve) => cve.knownExploited || cve.cisaKev).length
  const nvdCount = cves.filter((cve) => cve.nvd).length
  const mispEnabled = cves.some((cve) => cve.misp?.enabled === true)
  const mispMatches = cves.reduce((sum, cve) => sum + Number(cve.misp?.matches ?? 0), 0)
  const encodedReportId = selectedReport ? encodeURIComponent(selectedReport.id) : ''

  return (
    <main className="relative min-h-screen overflow-hidden bg-[#fbfefd] text-[#111827]">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_18%_10%,rgba(34,197,94,0.10),transparent_30%),radial-gradient(circle_at_86%_18%,rgba(8,122,58,0.08),transparent_34%)]" />
      <div className="pointer-events-none absolute right-0 top-24 h-[420px] w-[560px] rounded-full bg-[#dcf7e7]/60 blur-3xl" />
      <div className="pointer-events-none absolute left-0 top-[540px] h-[320px] w-[520px] rounded-full bg-[#eefaf3] blur-3xl" />

      <section className="relative mx-auto max-w-[1480px] px-6 pb-16 pt-10 lg:px-8">
        <header className="relative overflow-hidden rounded-[34px] border border-[#dceee3] bg-white/92 p-7 shadow-[0_24px_80px_rgba(15,43,29,0.07)] backdrop-blur">
          <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(135deg,rgba(8,122,58,0.05),transparent_42%),radial-gradient(circle_at_86%_24%,rgba(22,163,74,0.12),transparent_28%)]" />
          <div className="pointer-events-none absolute right-[180px] bottom-8 h-20 w-52 rounded-[50%] border border-[#bfe6cc] bg-gradient-to-b from-white to-[#e5f8ec] shadow-[0_24px_60px_rgba(8,122,58,0.12)]" />
          <div className="pointer-events-none absolute right-20 top-12 h-24 w-24 rounded-full bg-gradient-to-br from-[#dff7e8] to-[#7ddf9b] shadow-[0_22px_55px_rgba(8,122,58,0.14)]" />
          <div className="relative grid gap-8 lg:grid-cols-[1fr_0.82fr]">
            <div className="max-w-4xl">
              <p className="text-xs font-bold uppercase tracking-[0.22em] text-[#087a3a]">
                SOC Threat Intelligence Center
              </p>
              <h1 className="mt-3 text-3xl font-semibold tracking-tight text-[#0d2217] sm:text-4xl">
                Source-backed CVE enrichment
              </h1>
              <p className="mt-3 text-sm leading-7 text-[#5a7668]">
                This page reads report-scoped threat intelligence from the secured API/graph layer.
                NVD, CISA KEV, and MISP status are shown explicitly as ok, not found, disabled, or error.
                No CVSS, KEV, known-exploited, or MISP result is fabricated in the UI.
              </p>
            </div>

            <div className="w-full rounded-[28px] border border-[#dceee3] bg-white/78 p-5 shadow-[0_20px_60px_rgba(15,43,29,0.07)] backdrop-blur xl:max-w-[560px]">
              <p className="text-xs font-bold uppercase tracking-[0.16em] text-[#5a7668]">
                Report scope
              </p>
              <form className="mt-3 grid gap-3 sm:grid-cols-[1fr_auto]" action="/threat-intel">
                <select
                  name="reportId"
                  defaultValue={selectedReport?.id ?? ''}
                  className="h-12 rounded-2xl border border-[#c4e3cf] bg-white px-4 text-sm font-bold text-[#173128] outline-none focus:border-[#087a3a]"
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
                <button
                  type="submit"
                  className="h-12 rounded-2xl bg-[#087a3a] px-5 text-sm font-semibold text-white shadow-[0_16px_32px_rgba(8,122,58,0.18)] transition hover:-translate-y-0.5 hover:bg-[#066b33]"
                >
                  Load
                </button>
              </form>

              {selectedReport ? (
                <div className="mt-4 flex flex-wrap gap-2">
                  <ActionLink href={`/api/threat-intel/enrich/${encodedReportId}`} primary>
                    Run Enrichment API
                  </ActionLink>
                  <ActionLink href={`/api/threat-intel/${encodedReportId}`}>Open JSON</ActionLink>
                  <ActionLink href={`/risk-scoring?reportId=${encodedReportId}`}>Risk</ActionLink>
                  <ActionLink href={`/graph?reportId=${encodedReportId}`}>Graph</ActionLink>
                </div>
              ) : null}
            </div>
          </div>
        </header>

        {selectedReport ? (
          <section className="mt-5 rounded-[28px] border border-[#dceee3] bg-white p-5 shadow-[0_22px_60px_rgba(15,43,29,0.05)]">
            <div className="flex flex-wrap items-center gap-2">
              <Pill>{selectedReport.id}</Pill>
              <Pill>{selectedReport.type ?? 'Report'}</Pill>
              <Pill>{selectedReport.status ?? 'Ready'}</Pill>
              <Pill>{selectedReport.findings ?? 0} findings</Pill>
            </div>
            <h2 className="mt-3 text-2xl font-semibold text-[#0d2217]">{selectedReport.name}</h2>
            {selectedReport.summary ? (
              <p className="mt-2 max-w-6xl text-sm leading-7 text-[#5a7668]">
                {selectedReport.summary}
              </p>
            ) : null}
          </section>
        ) : null}

        {loadError ? (
          <section className="mt-5 rounded-[28px] border border-red-200 bg-red-50 p-5 text-sm font-semibold text-red-700">
            Threat intelligence could not be loaded: {loadError}
          </section>
        ) : null}

        <section className="mt-5 grid gap-3 md:grid-cols-2 xl:grid-cols-6">
          <MetricCard label="CVEs" value={String(cves.length)} helper="Report scoped" />
          <MetricCard label="NVD records" value={String(nvdCount)} helper="Source status: ok" />
          <MetricCard label="CISA KEV" value={String(knownExploitedCount)} helper="Known exploited" />
          <MetricCard label="MISP matches" value={String(mispMatches)} helper={mispEnabled ? 'Configured' : 'Disabled or none'} />
          <MetricCard label="Source OK" value={String(sourceSummary.ok)} helper={`${sourceSummary.notFound} not found`} />
          <MetricCard label="Errors" value={String(sourceSummary.errors)} helper={`${sourceSummary.disabled} disabled`} />
        </section>

        {(intel?.warnings?.length ?? 0) > 0 || (intel?.notes?.length ?? 0) > 0 ? (
          <section className="mt-5 rounded-[28px] border border-yellow-200 bg-yellow-50 p-5 text-sm leading-7 text-yellow-800">
            {[...(intel?.warnings ?? []), ...(intel?.notes ?? [])].map((note, index) => (
              <p key={`note-${index}`}>{note}</p>
            ))}
          </section>
        ) : null}

        {!selectedReport ? (
          <EmptyPanel
            title="No reports available"
            message="Analyze a report first so the SOC dashboard can display real CVE enrichment."
            href="/analyzer"
            action="Analyze Report"
          />
        ) : cves.length === 0 ? (
          <EmptyPanel
            title="No CVEs found for this report"
            message="The selected report has no report-scoped CVE enrichment and no extracted fallback CVEs."
            href={`/reports/${encodedReportId}`}
            action="Open Report"
          />
        ) : (
          <section className="mt-5 grid gap-5 xl:grid-cols-[1fr_360px]">
            <div className="space-y-4">
              {cves.map((cve, index) => (
                <CveCard key={cve.cveId ?? `cve-${index}`} cve={cve} />
              ))}
            </div>

            <aside className="space-y-4 xl:sticky xl:top-24 xl:self-start">
              <Panel title="Source status">
                <div className="space-y-2">
                  {statuses.length === 0 ? (
                    <p className="text-sm leading-6 text-[#5a7668]">No source statuses were returned yet.</p>
                  ) : (
                    statuses.map((status, index) => (
                      <StatusRow key={`${status.source}-${status.cveId}-${index}`} status={status} />
                    ))
                  )}
                </div>
              </Panel>

              <Panel title="Negative CVE test">
                <p className="text-sm leading-7 text-[#5a7668]">
                  Use the lookup endpoint to verify that unknown CVEs return null CVSS, no KEV,
                  and explicit not_found/disabled statuses instead of fabricated enrichment.
                </p>
                <div className="mt-3">
                  <ActionLink href="/api/threat-intel/lookup?cve=CVE-2099-99999">
                    Test CVE-2099-99999
                  </ActionLink>
                </div>
              </Panel>
            </aside>
          </section>
        )}
      </section>
    </main>
  )
}

function CveCard({ cve }: { cve: ThreatIntelCve }) {
  const mispEnabled = cve.misp?.enabled === true

  return (
    <article className="rounded-[32px] border border-[#dceee3] bg-white p-5 shadow-[0_22px_60px_rgba(15,43,29,0.06)]">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div className="min-w-0">
          <div className="flex flex-wrap gap-2">
            <Pill>{cve.cveId ?? 'Unknown CVE'}</Pill>
            <Pill>NVD: {boolLabel(cve.nvd)}</Pill>
            <Pill>CISA KEV: {boolLabel(cve.cisaKev)}</Pill>
            <Pill>Known exploited: {boolLabel(cve.knownExploited)}</Pill>
          </div>
          <h2 className="mt-3 text-2xl font-semibold text-[#0d2217]">
            {cve.cveId ?? 'Unmapped CVE'}
          </h2>
          <p className="mt-2 max-w-5xl text-sm leading-7 text-[#5a7668]">
            {cve.description || 'No NVD description is linked to this CVE in the report graph.'}
          </p>
        </div>
        <div className="rounded-[22px] border border-[#e4f2e9] bg-[#f8fffa] p-4 text-right lg:min-w-[220px]">
          <p className="text-xs font-semibold uppercase tracking-[0.16em] text-[#5a7668]">Intel CVSS</p>
          <p className="mt-2 text-3xl font-semibold text-[#0d2217]">{safeNumber(cve.cvssScore)}</p>
          <p className="mt-1 text-sm font-bold text-[#087a3a]">{cve.cvssSeverity ?? 'No severity'}</p>
        </div>
      </div>

      <div className="mt-5 grid gap-4 lg:grid-cols-3">
        <InfoBox label="CVSS vector" value={cve.cvssVector ?? 'Not available'} />
        <InfoBox label="NVD published" value={formatDate(cve.advisory?.published)} />
        <InfoBox label="NVD modified" value={formatDate(cve.advisory?.lastModified)} />
      </div>

      {cve.kev ? (
        <div className="mt-4 rounded-2xl border border-red-200 bg-red-50 p-4">
          <p className="text-xs font-semibold uppercase tracking-[0.16em] text-red-700">CISA KEV evidence</p>
          <div className="mt-3 grid gap-3 text-sm leading-6 text-red-900 md:grid-cols-2">
            <p><strong>Vendor:</strong> {cve.kev.vendorProject ?? 'Not reported'}</p>
            <p><strong>Product:</strong> {cve.kev.product ?? 'Not reported'}</p>
            <p><strong>Added:</strong> {formatDate(cve.kev.dateAdded)}</p>
            <p><strong>Due:</strong> {formatDate(cve.kev.dueDate)}</p>
            <p className="md:col-span-2"><strong>Required action:</strong> {cve.kev.requiredAction ?? 'Not reported'}</p>
          </div>
        </div>
      ) : null}

      <div className="mt-4 grid gap-4 lg:grid-cols-[1fr_340px]">
        <div className="rounded-2xl border border-[#e4f2e9] bg-[#fbfffc] p-4">
          <p className="text-xs font-semibold uppercase tracking-[0.16em] text-[#087a3a]">References</p>
          {(cve.references ?? []).length === 0 ? (
            <p className="mt-2 text-sm text-[#5a7668]">No references are linked in the graph.</p>
          ) : (
            <ul className="mt-3 space-y-2 text-xs leading-5 text-[#173128]">
              {(cve.references ?? []).slice(0, 8).map((reference, index) => (
                <li key={`${cve.cveId}-ref-${index}`} className="break-all rounded-xl border border-[#e4f2e9] bg-white p-2">
                  {reference}
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="rounded-2xl border border-[#e4f2e9] bg-[#fbfffc] p-4">
          <p className="text-xs font-semibold uppercase tracking-[0.16em] text-[#087a3a]">MISP status</p>
          <p className="mt-2 text-sm font-bold text-[#173128]">
            {mispEnabled ? 'Configured' : 'Disabled or no linked data'} · {cve.misp?.matches ?? 0} matches
          </p>
          <p className="mt-2 text-xs leading-5 text-[#5a7668]">
            {cve.misp?.note ?? 'MISP attributes are displayed only when the source is configured and linked.'}
          </p>
        </div>
      </div>

      {(cve.sourceStatuses ?? []).length > 0 ? (
        <div className="mt-4 flex flex-wrap gap-2">
          {(cve.sourceStatuses ?? []).map((status, index) => (
            <span key={`${cve.cveId}-status-${index}`} className={`rounded-full border px-3 py-1 text-xs font-semibold ${sourceTone(status.status)}`}>
              {status.source}: {status.status}
            </span>
          ))}
        </div>
      ) : null}
    </article>
  )
}

function StatusRow({ status }: { status: SourceStatus }) {
  return (
    <div className="rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] p-3">
      <div className="flex items-center justify-between gap-3">
        <p className="text-sm font-semibold text-[#173128]">{status.source ?? 'Source'}</p>
        <span className={`rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase ${sourceTone(status.status)}`}>
          {status.status ?? 'unknown'}
        </span>
      </div>
      {status.cveId ? <p className="mt-1 text-xs font-semibold text-[#5a7668]">{status.cveId}</p> : null}
      {status.message || status.error ? (
        <p className="mt-2 text-xs leading-5 text-[#5a7668]">{status.message ?? status.error}</p>
      ) : null}
    </div>
  )
}

function EmptyPanel({ title, message, href, action }: { title: string; message: string; href: string; action: string }) {
  return (
    <section className="rounded-[32px] border border-dashed border-[#b9dcc7] bg-[#f8fffa] p-8 text-center">
      <h2 className="text-2xl font-semibold text-[#0d2217]">{title}</h2>
      <p className="mx-auto mt-3 max-w-2xl text-sm leading-7 text-[#5a7668]">{message}</p>
      <div className="mt-5 flex justify-center">
        <ActionLink href={href} primary>{action}</ActionLink>
      </div>
    </section>
  )
}

function ActionLink({ href, children, primary }: { href: string; children: ReactNode; primary?: boolean }) {
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

function Pill({ children }: { children: ReactNode }) {
  return (
    <span className="rounded-full border border-[#c4e3cf] bg-[#f6fff9] px-3 py-1 text-xs font-bold text-[#173128]">
      {children}
    </span>
  )
}

function MetricCard({ label, value, helper }: { label: string; value: string; helper: string }) {
  return (
    <div className="rounded-[26px] border border-[#dceee3] bg-white/95 p-5 shadow-[0_22px_60px_rgba(15,43,29,0.05)]">
      <p className="text-xs font-bold uppercase tracking-[0.12em] text-[#5a7668]">{label}</p>
      <p className="mt-2 text-2xl font-semibold text-[#0d2217]">{value}</p>
      <p className="mt-1 text-xs leading-5 text-[#5a7668]">{helper}</p>
    </div>
  )
}

function InfoBox({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-2xl border border-[#e4f2e9] bg-[#fbfffc] p-4">
      <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-[#5a7668]">{label}</p>
      <p className="mt-1 break-words text-xs font-bold leading-5 text-[#173128]">{value}</p>
    </div>
  )
}

function Panel({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="rounded-[28px] border border-[#dceee3] bg-white/95 p-5 shadow-[0_22px_60px_rgba(15,43,29,0.05)]">
      <h2 className="mb-3 text-base font-semibold text-[#0d2217]">{title}</h2>
      {children}
    </section>
  )
}
