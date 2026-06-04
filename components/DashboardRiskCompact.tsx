'use client'

import Link from 'next/link'
import { useEffect, useState } from 'react'

type Severity = 'Critical' | 'High' | 'Medium' | 'Low'
type RiskBand = 'Low' | 'Medium' | 'High' | 'Critical'

type RiskApiResponse = {
  report: {
    id: string
    name: string
    type: 'PDF' | 'DOCX' | 'TXT'
    uploadedAt: string
    status: 'Ready' | 'Reviewed' | 'Pending'
  }
  summary: {
    confidence: number
    executiveSummary: string
    severityOverview: Record<Severity, number>
  }
  risk: {
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
    topRiskFindings: Array<{
      findingId: string
      title: string
      asset: string
      severity: Severity
      riskScore: number
      riskBand: RiskBand
    }>
  }
}

function riskBandClass(band: RiskBand) {
  switch (band) {
    case 'Critical':
      return 'border-red-200 bg-red-100 text-red-700'
    case 'High':
      return 'border-orange-200 bg-orange-100 text-orange-700'
    case 'Medium':
      return 'border-yellow-200 bg-yellow-100 text-yellow-700'
    case 'Low':
      return 'border-emerald-200 bg-emerald-100 text-emerald-700'
    default:
      return 'border-slate-200 bg-slate-100 text-slate-700'
  }
}

function scoreTone(score: number) {
  if (score >= 85) return 'text-red-700'
  if (score >= 65) return 'text-orange-700'
  if (score >= 40) return 'text-yellow-700'
  return 'text-emerald-700'
}

export default function DashboardRiskCompact({
  reportId,
}: {
  reportId?: string
}) {
  const [data, setData] = useState<RiskApiResponse | null>(null)
  const [isLoading, setIsLoading] = useState(Boolean(reportId))
  const [error, setError] = useState('')

  useEffect(() => {
    if (!reportId) return

    let isMounted = true

    async function loadRisk() {
      try {
        setIsLoading(true)
        setError('')

        const response = await fetch(`/api/risk-scoring/${reportId}`, {
          cache: 'no-store',
        })
        const result = await response.json()

        if (!response.ok) {
          throw new Error(result.error ?? 'Failed to load risk overview.')
        }

        if (!isMounted) return
        setData(result)
      } catch (error) {
        if (!isMounted) return
        setError(error instanceof Error ? error.message : 'Failed to load risk overview.')
      } finally {
        if (!isMounted) return
        setIsLoading(false)
      }
    }

    loadRisk()

    return () => {
      isMounted = false
    }
  }, [reportId])

  if (!reportId) return null

  if (isLoading) {
    return (
      <div className="mt-4 rounded-[24px] border border-[#cbe8d6] bg-white/90 p-5 shadow-[0_16px_34px_rgba(22,101,52,0.06)]">
        <p className="text-sm text-[#5a7668]">Loading risk pulse…</p>
      </div>
    )
  }

  if (error) {
    return (
      <div className="mt-4 rounded-[24px] border border-red-200 bg-red-50 p-5">
        <p className="text-sm text-red-700">{error}</p>
      </div>
    )
  }

  if (!data) return null

  return (
    <div className="mt-4 rounded-[24px] border border-[#cbe8d6] bg-white/90 p-5 shadow-[0_16px_34px_rgba(22,101,52,0.06)]">
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-sm font-semibold uppercase tracking-[0.16em] text-[#15803d]">
            Risk Pulse
          </p>
          <p className="mt-2 text-sm text-[#5a7668]">
            {data.report.name}
          </p>
        </div>

        <Link
          href="/risk-scoring"
          className="rounded-xl border border-[#cfe5d7] bg-white px-3 py-2 text-xs font-medium text-[#173128] transition hover:bg-[#edfdf3]"
        >
          Open
        </Link>
      </div>

      <div className="mt-4 grid gap-3 sm:grid-cols-3">
        <div className="rounded-2xl border border-[#e2f3e8] bg-[#f8fffa] p-4">
          <p className="text-xs uppercase tracking-wide text-[#5a7668]">Overall</p>
          <p className={`mt-2 text-3xl font-semibold ${scoreTone(data.risk.overallRiskScore)}`}>
            {data.risk.overallRiskScore}
          </p>
        </div>

        <div className="rounded-2xl border border-[#e2f3e8] bg-[#f8fffa] p-4">
          <p className="text-xs uppercase tracking-wide text-[#5a7668]">Band</p>
          <div className="mt-3">
            <span className={`inline-flex rounded-full border px-3 py-1 text-xs font-medium ${riskBandClass(data.risk.overallRiskBand)}`}>
              {data.risk.overallRiskBand}
            </span>
          </div>
        </div>

        <div className="rounded-2xl border border-[#e2f3e8] bg-[#f8fffa] p-4">
          <p className="text-xs uppercase tracking-wide text-[#5a7668]">Open</p>
          <p className="mt-2 text-3xl font-semibold text-[#0d2217]">
            {data.risk.stats.openFindings}
          </p>
        </div>
      </div>

      <div className="mt-4 rounded-2xl border border-[#e2f3e8] bg-[#f8fffa] p-4">
        <p className="text-xs uppercase tracking-wide text-[#5a7668]">Top risk</p>
        <p className="mt-2 text-sm font-semibold text-[#173128]">
          {data.risk.topRiskFindings[0]?.title ?? 'No top finding'}
        </p>
        <p className="mt-1 text-xs text-[#5a7668]">
          {data.risk.topRiskFindings[0]?.asset ?? '—'}
        </p>
      </div>
    </div>
  )
}