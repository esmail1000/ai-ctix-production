import type { FindingStatus, ReportStatus, Severity } from '@/lib/mock-data'
import Link from 'next/link'
import type { ReactNode } from 'react'

export function severityClass(severity: Severity | string) {
  switch (severity) {
    case 'Critical':
      return 'border-red-200 bg-red-50 text-red-700'
    case 'High':
      return 'border-orange-200 bg-orange-50 text-orange-700'
    case 'Medium':
      return 'border-amber-200 bg-amber-50 text-amber-700'
    case 'Low':
      return 'border-[#d9eadf] bg-[#ecfdf3] text-[#2f6b4f]'
    default:
      return 'border-[#c4e3cf] bg-[#edfdf3] text-[#425b50]'
  }
}

export function findingStatusClass(status: FindingStatus | string) {
  switch (status) {
    case 'Open':
      return 'border-[#f0dfbf] bg-[#fefce8] text-[#9a6b16]'
    case 'In Review':
      return 'border-[#bbf7d0] bg-[#ecfdf5] text-[#14532d]'
    case 'Resolved':
      return 'border-[#bbebc8] bg-[#e8faef] text-[#0f6b3f]'
    default:
      return 'border-[#c4e3cf] bg-[#edfdf3] text-[#425b50]'
  }
}

export function reportStatusClass(status: ReportStatus | string) {
  switch (status) {
    case 'Ready':
      return 'border-[#bbebc8] bg-[#e8faef] text-[#0f6b3f]'
    case 'Reviewed':
      return 'border-[#bbf7d0] bg-[#ecfdf5] text-[#14532d]'
    case 'Pending':
      return 'border-[#f0dfbf] bg-[#fefce8] text-[#9a6b16]'
    default:
      return 'border-[#c4e3cf] bg-[#edfdf3] text-[#425b50]'
  }
}

export function toneClass(tone: 'success' | 'warning' | 'danger' | 'neutral' | 'info' = 'neutral') {
  switch (tone) {
    case 'success':
      return 'border-emerald-200 bg-emerald-50 text-emerald-700'
    case 'warning':
      return 'border-amber-200 bg-amber-50 text-amber-700'
    case 'danger':
      return 'border-red-200 bg-red-50 text-red-700'
    case 'info':
      return 'border-sky-200 bg-sky-50 text-sky-700'
    default:
      return 'border-[#c4e3cf] bg-white text-[#173128]'
  }
}

export function Badge({
  children,
  className = '',
  tone = 'neutral',
}: {
  children: ReactNode
  className?: string
  tone?: 'success' | 'warning' | 'danger' | 'neutral' | 'info'
}) {
  return (
    <span className={`inline-flex items-center rounded-full border px-3 py-1 text-xs font-semibold ${toneClass(tone)} ${className}`}>
      {children}
    </span>
  )
}

export function SeverityBadge({ severity }: { severity: Severity | string }) {
  return <span className={`inline-flex rounded-full border px-3 py-1 text-xs font-semibold ${severityClass(severity)}`}>{severity}</span>
}

export function StatusBadge({ status }: { status: FindingStatus | ReportStatus | string }) {
  const isFindingStatus = status === 'Open' || status === 'In Review' || status === 'Resolved'
  return (
    <span className={`inline-flex rounded-full border px-3 py-1 text-xs font-semibold ${isFindingStatus ? findingStatusClass(status) : reportStatusClass(status)}`}>
      {status}
    </span>
  )
}

export function ConfidenceBadge({ value }: { value?: number }) {
  const tone = typeof value !== 'number' ? 'neutral' : value >= 85 ? 'success' : value >= 70 ? 'info' : value >= 50 ? 'warning' : 'danger'
  return <Badge tone={tone}>{typeof value === 'number' ? `${Math.round(value)}% confidence` : 'Confidence unavailable'}</Badge>
}

export function ExtractionMethodBadge({ method }: { method?: string }) {
  const label =
    method === 'nlp-hybrid'
      ? 'NLP Hybrid'
      : method === 'structured-parser'
      ? 'Structured Parser'
      : method === 'heuristic-fallback'
      ? 'Heuristic Fallback'
      : method === 'manual'
      ? 'Manual Review'
      : method === 'seed'
      ? 'Seed Data'
      : 'Unknown Method'

  const tone = method === 'heuristic-fallback' ? 'warning' : method === 'nlp-hybrid' || method === 'structured-parser' ? 'success' : 'neutral'
  return <Badge tone={tone}>{label}</Badge>
}

export function ReadinessBadge({ state }: { state: 'Ready' | 'Needs Review' | 'Incomplete' }) {
  return <Badge tone={state === 'Ready' ? 'success' : state === 'Needs Review' ? 'warning' : 'danger'}>{state}</Badge>
}

export function StatCard({
  label,
  value,
  note,
  tone = 'default',
}: {
  label: string
  value: ReactNode
  note?: ReactNode
  tone?: 'default' | 'danger' | 'warning' | 'success' | 'info'
}) {
  const valueClass =
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
    <div className="panel-green p-5">
      <p className="text-sm text-[#6b8477]">{label}</p>
      <div className={`mt-2 text-3xl font-semibold tracking-tight ${valueClass}`}>{value}</div>
      {note ? <p className="mt-2 text-sm text-[#5a7668]">{note}</p> : null}
    </div>
  )
}

export function SectionCard({
  title,
  eyebrow,
  children,
  className = '',
}: {
  title: string
  eyebrow?: string
  children: ReactNode
  className?: string
}) {
  return (
    <section className={`rounded-[28px] border border-[#dcefe2] bg-white p-6 shadow-sm ${className}`}>
      {eyebrow ? <p className="text-sm font-medium text-[#4d6b5b]">{eyebrow}</p> : null}
      <h2 className={`${eyebrow ? 'mt-1' : ''} text-2xl font-semibold text-[#0d2217]`}>{title}</h2>
      <div className="mt-5">{children}</div>
    </section>
  )
}

export function EmptyState({
  title = 'No data available',
  message,
  action,
}: {
  title?: string
  message: string
  action?: { href: string; label: string }
}) {
  return (
    <div className="rounded-[24px] border border-dashed border-[#cfe5d7] bg-white/75 px-5 py-8 text-center">
      <p className="text-base font-semibold text-[#0d2217]">{title}</p>
      <p className="mx-auto mt-2 max-w-md text-sm leading-6 text-[#5a7668]">{message}</p>
      {action ? (
        <Link href={action.href} className="mt-5 inline-flex rounded-2xl bg-gradient-to-r from-[#16a34a] to-[#15803d] px-5 py-3 text-sm font-medium text-white transition hover:from-[#15803d] hover:to-[#166534]">
          {action.label}
        </Link>
      ) : null}
    </div>
  )
}

export function Alert({
  children,
  tone = 'info',
}: {
  children: ReactNode
  tone?: 'success' | 'warning' | 'danger' | 'neutral' | 'info'
}) {
  return <div className={`rounded-2xl border p-4 text-sm leading-6 ${toneClass(tone)}`}>{children}</div>
}

export function EvidenceBlock({
  label = 'Technical Evidence',
  body,
}: {
  label?: string
  body?: string
}) {
  return (
    <div className="rounded-2xl border border-[#cfe9d7] bg-[#f8fffa] p-5">
      <p className="text-sm font-semibold text-[#173128]">{label}</p>
      <blockquote className="mt-3 border-l-4 border-[#16a34a] pl-4 text-base leading-7 text-[#425b50]">
        {body?.trim() || 'No evidence was extracted for this finding.'}
      </blockquote>
    </div>
  )
}

export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow: string
  title: ReactNode
  description?: string
  actions?: ReactNode
}) {
  return (
    <div className="mb-8">
      <p className="page-kicker">{eyebrow}</p>
      <h1 className="page-heading">{title}</h1>
      {description ? <p className="mt-3 max-w-3xl text-base leading-7 text-[#5a7668]">{description}</p> : null}
      {actions ? <div className="mt-6 flex flex-wrap gap-3">{actions}</div> : null}
    </div>
  )
}
