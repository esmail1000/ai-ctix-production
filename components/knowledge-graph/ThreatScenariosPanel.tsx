'use client'

import { useEffect, useState } from 'react'

type ThreatScenarioResponse = {
  reportId: string
  scenarioCount: number
  scenarios: Array<{
    findingId: string
    title: string
    likelihood: string
    confidence: number
    attackerGoal: string
    attackScenario: string
    killChain: Array<{
      phase: string
      description: string
    }>
    recommendedDefenses: string[]
  }>
}

export function ThreatScenariosPanel({ reportId }: { reportId: string }) {
  const [data, setData] = useState<ThreatScenarioResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    let cancelled = false

    async function loadScenarios() {
      try {
        setLoading(true)
        setError('')

        const response = await fetch(
          `/api/llm-threat-analysis/${encodeURIComponent(reportId)}`,
          { cache: 'no-store' }
        )

        const result = await response.json().catch(() => null)

        if (!response.ok) {
          throw new Error(
            result?.details ||
              result?.error ||
              `Failed to load threat scenarios: ${response.status}`
          )
        }

        if (!cancelled) {
          setData(result)
        }
      } catch (err) {
        if (!cancelled) {
          setError(
            err instanceof Error
              ? err.message
              : 'Failed to load threat scenarios'
          )
        }
      } finally {
        if (!cancelled) {
          setLoading(false)
        }
      }
    }

    if (reportId) {
      loadScenarios()
    }

    return () => {
      cancelled = true
    }
  }, [reportId])

  if (loading) {
    return <Panel title="Threat Scenarios">Loading threat scenarios...</Panel>
  }

  if (error) {
    return (
      <Panel title="Threat Scenarios">
        <p className="text-xs leading-5 text-red-600">{error}</p>
      </Panel>
    )
  }

  if (!data || data.scenarioCount === 0) {
    return (
      <Panel title="Threat Scenarios">
        <p className="text-xs leading-5 text-[#5a7668]">
          No threat scenarios found for this report.
        </p>
      </Panel>
    )
  }

  return (
    <Panel title="Threat Scenarios">
      <div className="space-y-3">
        {data.scenarios.slice(0, 5).map((scenario) => (
          <article
            key={scenario.findingId}
            className="rounded-2xl border border-[#e4f2e9] bg-white p-3"
          >
            <h3 className="text-xs font-bold leading-5 text-[#173128]">
              {scenario.title}
            </h3>

            <div className="mt-2 grid grid-cols-2 gap-2">
              <MiniMetric label="Likelihood" value={scenario.likelihood} />
              <MiniMetric
                label="Confidence"
                value={`${scenario.confidence ?? 0}%`}
              />
            </div>

            <div className="mt-3 rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] p-3">
              <p className="text-[10px] font-semibold uppercase tracking-wide text-[#5a7668]">
                Attack Scenario
              </p>

              <p className="mt-1 text-xs leading-5 text-[#173128]">
                {scenario.attackScenario}
              </p>
            </div>

            <details className="mt-3">
              <summary className="cursor-pointer text-xs font-semibold text-[#15803d]">
                Kill Chain & Defenses
              </summary>

              <div className="mt-2 space-y-2">
                {scenario.killChain.map((step) => (
                  <p
                    key={`${scenario.findingId}-${step.phase}`}
                    className="text-[11px] leading-5 text-[#5a7668]"
                  >
                    <strong>{step.phase}:</strong> {step.description}
                  </p>
                ))}

                <ul className="list-disc space-y-1 pl-4 text-[11px] leading-5 text-[#5a7668]">
                  {scenario.recommendedDefenses.slice(0, 4).map((defense) => (
                    <li key={defense}>{defense}</li>
                  ))}
                </ul>
              </div>
            </details>
          </article>
        ))}
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