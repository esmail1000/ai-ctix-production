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
    topRisks: Array<{
      id: string
      title: string
      severity: Severity
      score: number
      asset: string
      reason: string
    }>
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

export default function DashboardRiskSection({
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
          throw new Error(result.error ?? 'Failed to load dashboard risk section.')
        }

        if (!isMounted) return
        setData(result)
      } catch (error) {
        if (!isMounted) return
        setError(error instanceof Error ? error.message : 'Failed to load dashboard risk section.')
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

  if (!reportId) {
    return (
      <section className="mt-6 rounded-[28px] border border-[#dcefe2] bg-white p-6 shadow-sm">
        <p className="text-sm text-[#5a7668]">No report is available for the dashboard risk overview.</p>
      </section>
    )
  }

  if (isLoading) {
    return (
      <section className="mt-6 rounded-[28px] border border-[#dcefe2] bg-white p-6 shadow-sm">
        <p className="text-sm text-[#5a7668]">Loading dashboard risk overview…</p>
      </section>
    )
  }

  if (error) {
    return (
      <section className="mt-6 rounded-[28px] border border-red-200 bg-red-50 p-6 shadow-sm">
        <p className="text-sm text-red-700">{error}</p>
      </section>
    )
  }

  if (!data) return null

  return (
    <section className="mt-6 rounded-[28px] border border-[#dcefe2] bg-white p-6 shadow-sm">
      <div className="flex flex-wrap items-start justify-between gap-4 border-b border-[#e7f3eb] pb-4">
        <div>
          <p className="text-sm font-medium text-[#4d6b5b]">Dashboard Risk Overview</p>
          <h2 className="mt-2 text-2xl font-semibold text-[#0d2217]">
            Current report risk snapshot
          </h2>
          <p className="mt-2 max-w-3xl text-sm leading-7 text-[#5a7668]">
            {data.summary.executiveSummary}
          </p>
        </div>

        <Link
          href="/risk-scoring"
          className="inline-flex items-center justify-center rounded-2xl border border-[#c4e3cf] bg-white px-4 py-2 text-sm font-medium text-[#173128] transition hover:bg-[#edfdf3]"
        >
          Open Risk Scoring
        </Link>
      </div>

      <div className="mt-5 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <div className="rounded-[24px] border border-[#e7f3eb] bg-[#f8fffa] p-5">
          <p className="text-sm text-[#6b8477]">Overall Risk Score</p>
          <p className={`mt-2 text-4xl font-semibold tracking-tight ${scoreTone(data.risk.overallRiskScore)}`}>
            {data.risk.overallRiskScore}
          </p>
        </div>

        <div className="rounded-[24px] border border-[#e7f3eb] bg-[#f8fffa] p-5">
          <p className="text-sm text-[#6b8477]">Risk Band</p>
          <div className="mt-3">
            <span className={`inline-flex rounded-full border px-3 py-1 text-sm font-medium ${riskBandClass(data.risk.overallRiskBand)}`}>
              {data.risk.overallRiskBand}
            </span>
          </div>
        </div>

        <div className="rounded-[24px] border border-[#e7f3eb] bg-[#f8fffa] p-5">
          <p className="text-sm text-[#6b8477]">Open Findings</p>
          <p className="mt-2 text-4xl font-semibold tracking-tight text-[#0d2217]">
            {data.risk.stats.openFindings}
          </p>
        </div>

        <div className="rounded-[24px] border border-[#e7f3eb] bg-[#f8fffa] p-5">
          <p className="text-sm text-[#6b8477]">Findings With CVE</p>
          <p className="mt-2 text-4xl font-semibold tracking-tight text-[#0d2217]">
            {data.risk.stats.findingsWithCve}
          </p>
        </div>
      </div>

      <div className="mt-6 grid gap-6 lg:grid-cols-[1fr_1fr]">
        <div className="rounded-[24px] border border-[#e7f3eb] bg-[#f8fffa] p-5">
          <p className="text-sm font-medium text-[#4d6b5b]">Top Risk Findings</p>

          <div className="mt-4 space-y-3">
            {data.risk.topRiskFindings.slice(0, 3).map((item) => (
              <div
                key={item.findingId}
                className="rounded-2xl border border-[#dcefe2] bg-white p-4"
              >
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <p className="text-sm font-semibold text-[#173128]">{item.title}</p>
                    <p className="mt-1 text-xs text-[#5a7668]">{item.asset}</p>
                  </div>

                  <span className={`inline-flex rounded-full border px-3 py-1 text-xs font-medium ${riskBandClass(item.riskBand)}`}>
                    {item.riskScore}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="rounded-[24px] border border-[#e7f3eb] bg-[#f8fffa] p-5">
          <p className="text-sm font-medium text-[#4d6b5b]">Report Rationale</p>

          <ul className="mt-4 space-y-3">
            {data.risk.rationale.slice(0, 4).map((item, index) => (
              <li
                key={`${item}-${index}`}
                className="rounded-2xl border border-[#dcefe2] bg-white p-4 text-sm leading-7 text-[#264336]"
              >
                {item}
              </li>
            ))}
          </ul>
        </div>
      </div>
    </section>
  )
}