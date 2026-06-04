// app/reports/page.tsx
import { getReports } from '@/lib/data-service'
import type { Report } from '@/lib/mock-data'
import Link from 'next/link'

export const dynamic = 'force-dynamic'

type ReportStatus = Report['status']

const statusTone: Record<string, string> = {
  Ready: 'border-[#bce7cb] bg-[#effaf3] text-[#087a3a]',
  Reviewed: 'border-[#cfd8ff] bg-[#f1f4ff] text-[#3b5bdb]',
}

const typeTone: Record<string, string> = {
  TXT: 'border-[#bce7cb] bg-[#effaf3] text-[#087a3a]',
  PDF: 'border-[#fecaca] bg-[#fff1f2] text-[#dc2626]',
  DOCX: 'border-[#bfdbfe] bg-[#eff6ff] text-[#2563eb]',
}

function getStatusClass(status: string) {
  return statusTone[status] ?? 'border-[#dceee3] bg-[#fbfffd] text-[#44554b]'
}

function getTypeClass(type: string) {
  return typeTone[type] ?? 'border-[#dceee3] bg-[#fbfffd] text-[#44554b]'
}

const APP_TIME_ZONE = 'Africa/Cairo'

function shortDate(value: string) {
  try {
    return new Intl.DateTimeFormat('en', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      timeZone: APP_TIME_ZONE,
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
      timeZone: APP_TIME_ZONE,
    }).format(new Date(value))
  } catch {
    return ''
  }
}

function percent(part: number, total: number) {
  if (total === 0) return 0
  return Math.round((part / total) * 100)
}

function countByStatus(reports: Report[], status: ReportStatus) {
  return reports.filter((report) => report.status === status).length
}

function countExportReady(reports: Report[]) {
  return reports.filter((report) => report.findings > 0).length
}

function getParamValue(
  params: Record<string, string | string[] | undefined>,
  key: string,
  fallback = ''
) {
  const value = params[key]
  return Array.isArray(value) ? value[0] ?? fallback : value ?? fallback
}

function filterReports(
  reports: Report[],
  filters: { q: string; status: string; type: string }
) {
  const query = filters.q.trim().toLowerCase()

  return reports.filter((report) => {
    const matchesQuery =
      query.length === 0 ||
      [report.name, report.id, report.owner, report.type, report.status]
        .filter(Boolean)
        .some((value) => String(value).toLowerCase().includes(query))

    const matchesStatus =
      filters.status === '' || report.status === filters.status

    const matchesType =
      filters.type === '' || report.type === filters.type

    return matchesQuery && matchesStatus && matchesType
  })
}

function reportRisk(report: Report) {
  const critical = report.critical ?? 0
  const high = report.high ?? 0
  const medium = report.medium ?? 0
  const low = report.low ?? 0
  const total = critical + high + medium + low || report.findings || 1
  return Math.min(
    100,
    Math.round(((critical * 95 + high * 75 + medium * 45 + low * 20) / total) || 0)
  )
}

function riskLabel(score: number) {
  if (score >= 80) return 'High'
  if (score >= 55) return 'Medium'
  if (score >= 30) return 'Low'
  return 'Info'
}

function riskClass(score: number) {
  if (score >= 80) return 'text-red-600'
  if (score >= 55) return 'text-orange-500'
  if (score >= 30) return 'text-[#087a3a]'
  return 'text-[#64748b]'
}

export default async function ReportsPage({
  searchParams,
}: {
  searchParams?: Promise<Record<string, string | string[] | undefined>>
}) {
  const reports = await getReports()
  const params = (await searchParams) ?? {}

  const filters = {
    q: getParamValue(params, 'q'),
    status: getParamValue(params, 'status'),
    type: getParamValue(params, 'type'),
  }

  const visibleReports = filterReports(reports, filters)

  const totalReports = reports.length
  const readyReports = countByStatus(reports, 'Ready')
  const totalFindings = reports.reduce((sum, report) => sum + (report.findings ?? 0), 0)
  const exportReady = countExportReady(reports)

  const recentActivity = visibleReports.slice(0, 6).map((report, index) => ({
    id: `${report.id}-${index}`,
    title: report.name,
    description:
      report.status === 'Ready'
        ? 'Ready for analyst review'
        : report.status === 'Reviewed'
          ? 'Review completed'
          : report.status === 'Pending'
            ? 'Processing started'
            : 'Action required',
    time: shortTime(report.uploadedAt),
    status: report.status,
  }))

  return (
    <main className="relative min-h-screen overflow-hidden bg-[#fbfefd] text-[#111827]">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_18%_10%,rgba(34,197,94,0.14),transparent_28%),radial-gradient(circle_at_85%_26%,rgba(8,122,58,0.10),transparent_34%)]" />
      <div className="pointer-events-none absolute right-0 top-20 h-[460px] w-[520px] rounded-full bg-[#dcf7e7]/70 blur-3xl" />
      <div className="pointer-events-none absolute left-0 top-[410px] h-[340px] w-[500px] rounded-full bg-[#eefaf3] blur-3xl" />

      <section className="relative mx-auto max-w-[1500px] px-6 pb-16 pt-10 lg:px-8">
        <header className="relative overflow-hidden rounded-[34px] border border-[#dceee3] bg-white/92 px-7 py-9 shadow-[0_24px_80px_rgba(15,43,29,0.07)] backdrop-blur">
          <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(135deg,rgba(8,122,58,0.05),transparent_42%),radial-gradient(circle_at_86%_24%,rgba(22,163,74,0.14),transparent_28%)]" />
          <div className="pointer-events-none absolute right-16 top-8 h-20 w-20 rounded-full bg-gradient-to-br from-[#dff7e8] to-[#7ddf9b] shadow-[0_22px_55px_rgba(8,122,58,0.18)] report-float" />
          <div className="pointer-events-none absolute left-10 bottom-6 h-28 w-52 rounded-[50%] border border-[#bfe6cc] bg-gradient-to-b from-white to-[#e4f8eb] shadow-[0_22px_60px_rgba(8,122,58,0.12)] report-platform" />
          <div className="pointer-events-none absolute right-0 top-0 h-full w-1/2 opacity-25">
            <div className="absolute inset-0 bg-[linear-gradient(135deg,rgba(8,122,58,0.10)_25%,transparent_25%,transparent_50%,rgba(8,122,58,0.10)_50%,rgba(8,122,58,0.10)_75%,transparent_75%,transparent)] bg-[length:24px_24px]" />
          </div>

          <div className="relative grid gap-8 lg:grid-cols-[0.9fr_1.1fr]">
            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.22em] text-[#087a3a]">
                Welcome back
              </p>
              <h1 className="mt-4 max-w-3xl text-5xl font-semibold tracking-[-0.055em] text-[#111827] md:text-6xl">
                Report <span className="text-[#087a3a]">Intelligence</span> Center
              </h1>
              <p className="mt-4 max-w-2xl text-base leading-7 text-[#5f6f66]">
                Explore, analyze, and manage uploaded reports with clean intelligence cards,
                export readiness, and live archive activity.
              </p>

              <div className="mt-7 flex flex-wrap gap-3">
                <Link
                  href="/analyzer"
                  className="rounded-2xl bg-[#087a3a] px-5 py-3 text-sm font-semibold text-white shadow-[0_18px_35px_rgba(8,122,58,0.22)] transition duration-300 hover:-translate-y-1 hover:bg-[#066b33]"
                >
                  Analyze Report
                </Link>
                <Link
                  href="/dashboard"
                  className="rounded-2xl border border-[#b8dec7] bg-white px-5 py-3 text-sm font-semibold text-[#087a3a] shadow-sm transition duration-300 hover:-translate-y-1 hover:bg-[#f4fff7]"
                >
                  View Dashboard
                </Link>
              </div>
            </div>

            <div className="relative min-h-[260px]">
              <div className="absolute left-[12%] top-[10%] h-24 w-40 rounded-[50%] border border-[#bfe6cc] bg-gradient-to-b from-white to-[#e5f8ec] shadow-[0_24px_60px_rgba(8,122,58,0.14)] report-float-slow" />
              <div className="absolute right-[10%] top-[16%] h-28 w-28 rounded-full bg-gradient-to-br from-[#dcf7e8] via-[#b9edc8] to-[#16a34a] shadow-[0_24px_65px_rgba(8,122,58,0.18)] report-float" />
              <div className="absolute right-[30%] bottom-[8%] h-16 w-16 rounded-2xl border border-white/70 bg-gradient-to-br from-[#effaf3] to-[#aeeabd] shadow-[0_22px_55px_rgba(8,122,58,0.13)] report-cube" />

              <div className="absolute left-[14%] bottom-[10%] w-[250px] rounded-[26px] border border-[#d2eadb] bg-white/88 p-4 shadow-[0_24px_70px_rgba(15,43,29,0.12)] backdrop-blur report-panel">
                <p className="text-xs font-semibold uppercase tracking-[0.14em] text-[#748579]">
                  Archive health
                </p>
                <p className="mt-2 text-3xl font-semibold text-[#111827]">{totalReports}</p>
                <p className="mt-1 text-sm text-[#5f6f66]">reports currently indexed</p>
                <div className="mt-4 h-2 overflow-hidden rounded-full bg-[#e6f5eb]">
                  <div className="h-full w-[72%] rounded-full bg-[#087a3a]" />
                </div>
              </div>

              <div className="absolute right-[7%] bottom-[15%] w-[260px] rounded-[26px] border border-[#d2eadb] bg-white/88 p-4 shadow-[0_24px_70px_rgba(15,43,29,0.12)] backdrop-blur report-panel-delay">
                <p className="text-xs font-semibold uppercase tracking-[0.14em] text-[#748579]">
                  Export pulse
                </p>
                <div className="mt-3 flex items-end gap-3">
                  <p className="text-3xl font-semibold text-[#087a3a]">{exportReady}</p>
                  <p className="pb-1 text-sm text-[#5f6f66]">ready packages</p>
                </div>
                <div className="mt-4 flex gap-1">
                  {[42, 64, 38, 78, 56, 90, 70].map((height, index) => (
                    <span
                      key={index}
                      className="w-full rounded-full bg-[#087a3a]/80"
                      style={{ height: `${height}px`, opacity: 0.22 + index * 0.09 }}
                    />
                  ))}
                </div>
              </div>
            </div>
          </div>
        </header>

        <form
          action="/reports"
          className="relative z-10 -mt-7 mx-auto max-w-[1160px] rounded-[26px] border border-[#dceee3] bg-white/95 p-4 shadow-[0_22px_60px_rgba(15,43,29,0.08)] backdrop-blur"
        >
          <div className="grid gap-3 lg:grid-cols-[1.4fr_0.7fr_0.7fr_0.55fr_0.45fr]">
            <input
              name="q"
              defaultValue={filters.q}
              placeholder="Search reports by name, owner, or ID..."
              className="rounded-2xl border border-[#dceee3] bg-[#fbfffd] px-4 py-3 text-sm text-[#44554b] outline-none transition focus:border-[#087a3a] focus:bg-white"
            />

            <select
              name="status"
              defaultValue={filters.status}
              className="rounded-2xl border border-[#dceee3] bg-[#fbfffd] px-4 py-3 text-sm font-semibold text-[#44554b] outline-none transition focus:border-[#087a3a] focus:bg-white"
            >
              <option value="">All status</option>
              <option value="Ready">Ready</option>
              <option value="Reviewed">Reviewed</option>
            </select>

            <select
              name="type"
              defaultValue={filters.type}
              className="rounded-2xl border border-[#dceee3] bg-[#fbfffd] px-4 py-3 text-sm font-semibold text-[#44554b] outline-none transition focus:border-[#087a3a] focus:bg-white"
            >
              <option value="">All types</option>
              <option value="TXT">TXT</option>
              <option value="PDF">PDF</option>
              <option value="DOCX">DOCX</option>
            </select>

            <button
              type="submit"
              className="rounded-2xl bg-[#087a3a] px-4 py-3 text-center text-sm font-semibold text-white shadow-[0_16px_32px_rgba(8,122,58,0.18)] transition hover:-translate-y-0.5 hover:bg-[#066b33]"
            >
              Apply
            </button>

            <Link
              href="/reports"
              className="rounded-2xl border border-[#dceee3] bg-white px-4 py-3 text-center text-sm font-semibold text-[#44554b] transition hover:bg-[#f4fff7]"
            >
              Reset
            </Link>
          </div>
        </form>

        <section className="mt-6 grid gap-4 md:grid-cols-4">
          <StatCard label="Total reports" value={totalReports} note="+20% vs last 7 days" />
          <StatCard label="Ready reports" value={readyReports} note={`${percent(readyReports, totalReports)}% of total`} />
          <StatCard label="Total findings" value={totalFindings} note="+18% vs last 7 days" />
          <StatCard label="Export ready" value={exportReady} note="Ready to download" />
        </section>

        <section className="mt-6 grid gap-6 xl:grid-cols-[1fr_390px]">
          <div className="grid gap-5 md:grid-cols-2 xl:grid-cols-3">
            {visibleReports.length === 0 ? (
              <div className="rounded-[30px] border border-[#dceee3] bg-white p-8 shadow-[0_22px_60px_rgba(15,43,29,0.06)] md:col-span-2 xl:col-span-3">
                <p className="text-xl font-semibold text-[#111827]">No matching reports</p>
                <p className="mt-2 text-sm text-[#5f6f66]">Try changing the filters or analyze a new report.</p>
                <Link
                  href="/analyzer"
                  className="mt-5 inline-flex rounded-2xl bg-[#087a3a] px-5 py-3 text-sm font-semibold text-white"
                >
                  Analyze report
                </Link>
              </div>
            ) : (
              visibleReports.map((report) => (
                <ReportCard key={report.id} report={report} />
              ))
            )}
          </div>

          <aside className="rounded-[32px] border border-[#dceee3] bg-white/95 p-6 shadow-[0_22px_60px_rgba(15,43,29,0.06)] backdrop-blur">
            <div className="flex items-start justify-between gap-4">
              <div>
                <h2 className="text-xl font-semibold tracking-tight text-[#111827]">Live archive pulse</h2>
                <p className="mt-1 text-sm text-[#748579]">Real-time report activity</p>
              </div>
              <span className="relative flex h-3 w-3">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-[#16a34a] opacity-30" />
                <span className="relative inline-flex h-3 w-3 rounded-full bg-[#16a34a]" />
              </span>
            </div>

            <div className="mt-6 space-y-4">
              {recentActivity.length === 0 ? (
                <p className="text-sm text-[#748579]">No activity yet.</p>
              ) : (
                recentActivity.map((item, index) => (
                  <div key={item.id} className="relative flex gap-4">
                    <div className="flex flex-col items-center">
                      <span
                        className={`mt-1 h-3 w-3 rounded-full ${
                          item.status === 'Reviewed'
                            ? 'bg-blue-500'
                            : item.status === 'Pending'
                              ? 'bg-orange-500'
                              : 'bg-[#16a34a]'
                        }`}
                      />
                      {index < recentActivity.length - 1 ? (
                        <span className="mt-2 h-10 w-px bg-[#dceee3]" />
                      ) : null}
                    </div>

                    <div className="min-w-0 flex-1">
                      <div className="flex items-start justify-between gap-3">
                        <p className="truncate font-semibold text-[#111827]">{item.title}</p>
                        <p className="shrink-0 text-xs text-[#748579]">{item.time}</p>
                      </div>
                      <p className="mt-1 text-sm text-[#748579]">{item.description}</p>
                    </div>
                  </div>
                ))
              )}
            </div>

            <div className="relative mt-8 h-32 overflow-hidden rounded-[26px] border border-[#dceee3] bg-[#fbfffd]">
              <div className="absolute left-1/2 top-12 h-20 w-64 -translate-x-1/2 rounded-[50%] border border-[#bde6ca] bg-gradient-to-b from-white to-[#e6f8ed] shadow-[0_18px_45px_rgba(8,122,58,0.10)] report-platform" />
              <div className="absolute left-1/2 top-8 h-16 w-36 -translate-x-1/2 rounded-[50%] border border-[#bde6ca] bg-gradient-to-b from-white to-[#d9f5e4]" />
            </div>
          </aside>
        </section>
      </section>

      <style>{`
        @keyframes report-float {
          0%, 100% { transform: translateY(0) rotate(0deg); }
          50% { transform: translateY(-12px) rotate(2deg); }
        }

        @keyframes report-cube {
          0%, 100% { transform: translateY(0) rotate(0deg); }
          50% { transform: translateY(-16px) rotate(12deg); }
        }

        @keyframes report-panel {
          0%, 100% { transform: translateY(0); }
          50% { transform: translateY(-9px); }
        }

        .report-float { animation: report-float 6.2s ease-in-out infinite; }
        .report-float-slow { animation: report-float 8s ease-in-out infinite; animation-delay: -1s; }
        .report-cube { animation: report-cube 7s ease-in-out infinite; }
        .report-panel { animation: report-panel 6.5s ease-in-out infinite; }
        .report-panel-delay { animation: report-panel 7.4s ease-in-out infinite; animation-delay: -1.4s; }
        .report-platform { transform: perspective(800px) rotateX(58deg); }
      `}</style>
    </main>
  )
}

function StatCard({
  label,
  value,
  note,
}: {
  label: string
  value: number
  note: string
}) {
  return (
    <article className="group relative overflow-hidden rounded-[26px] border border-[#dceee3] bg-white p-5 shadow-[0_22px_60px_rgba(15,43,29,0.05)] transition duration-300 hover:-translate-y-1 hover:shadow-[0_30px_80px_rgba(15,43,29,0.09)]">
      <div className="pointer-events-none absolute right-4 top-4 h-20 w-20 rounded-full bg-[#e8f8ee] opacity-80 blur-2xl transition duration-500 group-hover:scale-150" />
      <p className="relative text-xs font-semibold uppercase tracking-[0.16em] text-[#44554b]">{label}</p>
      <p className="relative mt-4 text-4xl font-semibold tracking-tight text-[#111827]">{value.toLocaleString()}</p>
      <p className="relative mt-3 text-sm font-medium text-[#087a3a]">{note}</p>
      <div className="relative mt-4 h-1.5 overflow-hidden rounded-full bg-[#e6f5eb]">
        <div className="h-full w-[58%] rounded-full bg-[#16a34a]" />
      </div>
    </article>
  )
}

function ReportCard({ report }: { report: Report }) {
  const score = reportRisk(report)

  return (
    <article className="group relative overflow-hidden rounded-[30px] border border-[#dceee3] bg-white p-6 shadow-[0_22px_60px_rgba(15,43,29,0.05)] transition duration-300 hover:-translate-y-2 hover:border-[#b6dec5] hover:shadow-[0_34px_90px_rgba(15,43,29,0.11)]">
      <div className="pointer-events-none absolute inset-x-0 top-0 h-[3px] bg-gradient-to-r from-[#16a34a] via-transparent to-transparent opacity-80" />
      <div className="pointer-events-none absolute right-5 top-5 h-24 w-24 rounded-[28px] bg-[#e7f8ed] opacity-70 [transform:perspective(700px)_rotateX(60deg)_rotateZ(-35deg)] transition duration-500 group-hover:rotate-6" />

      <div className="relative">
        <h2 className="truncate text-xl font-semibold text-[#111827]">{report.name}</h2>
        <p className="mt-2 text-sm text-[#748579]">
          {report.id} - {shortDate(report.uploadedAt)} - {shortTime(report.uploadedAt)}
        </p>

        <div className="mt-7 grid grid-cols-3 gap-4">
          <Metric label="Type" value={report.type} chipClass={getTypeClass(report.type)} />
          <Metric label="Findings" value={String(report.findings)} />
          <Metric
            label="Risk score"
            value={String(score)}
            valueClass={riskClass(score)}
            subLabel={riskLabel(score)}
          />
        </div>

        <div className="mt-7 flex flex-wrap items-center justify-between gap-3">
          <span
            className={`inline-flex items-center gap-2 rounded-full border px-3 py-1.5 text-xs font-semibold ${getStatusClass(report.status)}`}
          >
            <span className="h-2 w-2 rounded-full bg-current" />
            {report.status}
          </span>

          <div className="flex items-center gap-2">
            <Link
              href={`/reports/${report.id}`}
              className="rounded-xl border border-[#dceee3] bg-white px-3 py-2 text-xs font-semibold text-[#111827] transition hover:bg-[#f4fff7]"
            >
              View report
            </Link>
            <Link
              href={`/export?reportId=${encodeURIComponent(report.id)}`}
              className="rounded-xl border border-[#b8dec7] bg-[#fbfffd] px-3 py-2 text-xs font-semibold text-[#087a3a] transition hover:bg-[#effaf3]"
            >
              Export
            </Link>
          </div>
        </div>
      </div>
    </article>
  )
}

function Metric({
  label,
  value,
  chipClass,
  valueClass = 'text-[#111827]',
  subLabel,
}: {
  label: string
  value: string
  chipClass?: string
  valueClass?: string
  subLabel?: string
}) {
  return (
    <div>
      <p className="text-xs text-[#748579]">{label}</p>
      {chipClass ? (
        <p className={`mt-2 inline-flex rounded-full border px-3 py-1 text-sm font-semibold ${chipClass}`}>
          {value}
        </p>
      ) : (
        <p className={`mt-2 text-2xl font-semibold ${valueClass}`}>{value}</p>
      )}
      {subLabel ? <p className="mt-1 text-xs text-[#748579]">{subLabel}</p> : null}
    </div>
  )
}
