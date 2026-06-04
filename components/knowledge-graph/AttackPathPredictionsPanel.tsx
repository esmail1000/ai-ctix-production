'use client'

import { useEffect, useState } from 'react'

type AttackPathPrediction = {
  findingId: string
  findingTitle: string
  severity: string
  riskScore: number
  attackPathScore: number
  exploitLikelihood?: string
  confidence?: number
  predictedOutcome?: string
  reasoning?: string[]
  path?: {
    nodes: Array<{
      type: string
      id: string
      name: string
    }>
    relationships: Array<{
      type: string
    }>
  }
}

export function AttackPathPredictionsPanel({
  reportId,
}: {
  reportId: string
}) {
  const [paths, setPaths] = useState<AttackPathPrediction[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    let cancelled = false

    async function loadAttackPaths() {
      try {
        setLoading(true)
        setError('')

        const response = await fetch(
          `/api/attack-paths/${encodeURIComponent(reportId)}?limit=10`,
          { cache: 'no-store' }
        )

        if (!response.ok) {
          throw new Error('Failed to load attack path predictions')
        }

        const data = await response.json()

        if (!cancelled) {
          setPaths(data.paths ?? [])
        }
      } catch (err) {
        if (!cancelled) {
          setError(
            err instanceof Error
              ? err.message
              : 'Failed to load attack path predictions'
          )
        }
      } finally {
        if (!cancelled) {
          setLoading(false)
        }
      }
    }

    if (reportId) {
      loadAttackPaths()
    }

    return () => {
      cancelled = true
    }
  }, [reportId])

  if (loading) {
    return (
      <Panel title="Attack Path Prediction">
        <p className="text-xs leading-5 text-[#5a7668]">
          Loading attack path predictions...
        </p>
      </Panel>
    )
  }

  if (error) {
    return (
      <Panel title="Attack Path Prediction">
        <p className="text-xs leading-5 text-red-600">{error}</p>
      </Panel>
    )
  }

  if (!paths.length) {
    return (
      <Panel title="Attack Path Prediction">
        <p className="text-xs leading-5 text-[#5a7668]">
          No attack path predictions found for this report.
        </p>
      </Panel>
    )
  }

  return (
    <Panel title="Attack Path Prediction">
      <div className="space-y-3">
        {paths.map((item) => {
          const sequence =
            item.path?.nodes?.map((node) => node.name).join(' → ') ??
            'No graph path available'

          return (
            <article
              key={item.findingId}
              className="rounded-2xl border border-[#e4f2e9] bg-white p-3"
            >
              <div className="flex items-start justify-between gap-2">
                <div>
                  <h3 className="text-xs font-bold leading-5 text-[#173128]">
                    {item.findingTitle}
                  </h3>

                  <p className="mt-1 text-[11px] text-[#5a7668]">
                    {item.findingId}
                  </p>
                </div>

                <span className={badgeClass(item.exploitLikelihood)}>
                  {item.exploitLikelihood ?? 'Unknown'}
                </span>
              </div>

              <div className="mt-3 grid grid-cols-2 gap-2">
                <MiniMetric label="Severity" value={item.severity} />
                <MiniMetric
                  label="Risk"
                  value={String(item.riskScore ?? 0)}
                />
                <MiniMetric
                  label="Path Score"
                  value={String(item.attackPathScore ?? 0)}
                />
                <MiniMetric
                  label="Confidence"
                  value={`${item.confidence ?? 0}%`}
                />
              </div>

              {item.predictedOutcome ? (
                <div className="mt-3 rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] p-3">
                  <p className="text-[10px] font-semibold uppercase tracking-wide text-[#5a7668]">
                    Predicted Outcome
                  </p>

                  <p className="mt-1 text-xs leading-5 text-[#173128]">
                    {item.predictedOutcome}
                  </p>
                </div>
              ) : null}

              <div className="mt-3 rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] p-3">
                <p className="text-[10px] font-semibold uppercase tracking-wide text-[#5a7668]">
                  Graph Path
                </p>

                <p className="mt-1 break-words text-[11px] leading-5 text-[#173128]">
                  {sequence}
                </p>
              </div>

              {item.reasoning?.length ? (
                <details className="mt-3">
                  <summary className="cursor-pointer text-xs font-semibold text-[#15803d]">
                    Reasoning
                  </summary>

                  <ul className="mt-2 list-disc space-y-1 pl-4 text-[11px] leading-5 text-[#5a7668]">
                    {item.reasoning.map((reason, index) => (
                      <li key={`${item.findingId}-reason-${index}`}>
                        {reason}
                      </li>
                    ))}
                  </ul>
                </details>
              ) : null}
            </article>
          )
        })}
      </div>
    </Panel>
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
    <section className="rounded-[20px] border border-[#dcefe2] bg-[#f8fffa] p-4">
      <h3 className="text-sm font-semibold uppercase tracking-wide text-[#4d6b5b]">
        {title}
      </h3>

      <div className="mt-3">{children}</div>
    </section>
  )
}

function MiniMetric({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-xl border border-[#e4f2e9] bg-[#f8fffa] p-2">
      <p className="text-[9px] font-semibold uppercase tracking-wide text-[#5a7668]">
        {label}
      </p>

      <p className="mt-1 break-words text-[11px] font-bold text-[#173128]">
        {value}
      </p>
    </div>
  )
}

function badgeClass(value?: string) {
  const normalized = String(value ?? '').toLowerCase()

  if (normalized.includes('critical')) {
    return 'rounded-full bg-red-100 px-2 py-1 text-[10px] font-bold text-red-700'
  }

  if (normalized.includes('high')) {
    return 'rounded-full bg-orange-100 px-2 py-1 text-[10px] font-bold text-orange-700'
  }

  if (normalized.includes('medium')) {
    return 'rounded-full bg-yellow-100 px-2 py-1 text-[10px] font-bold text-yellow-700'
  }

  if (normalized.includes('low')) {
    return 'rounded-full bg-green-100 px-2 py-1 text-[10px] font-bold text-green-700'
  }

  return 'rounded-full bg-slate-100 px-2 py-1 text-[10px] font-bold text-slate-700'
}