'use client'

import { useEffect, useState } from 'react'

type ThreatIntelResponse = {
  reportId: string
  cveCount: number
  cves: Array<{
    cveId: string
    description?: string
    cvssScore?: number | null
    cvssSeverity?: string | null
    knownExploited?: boolean
    references?: string[]
    mispItems?: any[]
  }>
}

export function ThreatIntelPanel({ reportId }: { reportId: string }) {
  const [data, setData] = useState<ThreatIntelResponse | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    async function loadIntel() {
      try {
        setLoading(true)

        const response = await fetch(
          `/api/threat-intel/${encodeURIComponent(reportId)}`
        )

        if (!response.ok) {
          throw new Error('Failed to load threat intelligence')
        }

        const result = await response.json()
        setData(result)
      } catch (error) {
        console.error(error)
      } finally {
        setLoading(false)
      }
    }

    loadIntel()
  }, [reportId])

  if (loading) {
    return <Panel title="CVE Intelligence">Loading CVE intelligence...</Panel>
  }

  if (!data || data.cveCount === 0) {
    return (
      <Panel title="CVE Intelligence">
        No CVE intelligence found for this report.
      </Panel>
    )
  }

  return (
    <Panel title="CVE Intelligence">
      {data.cves.map((cve) => (
        <div
          key={cve.cveId}
          style={{
            border: '1px solid #e5e7eb',
            borderRadius: 12,
            padding: 12,
            marginBottom: 10,
            background: '#fff',
          }}
        >
          <div style={{ fontWeight: 800 }}>{cve.cveId}</div>

          <div style={{ fontSize: 13, marginTop: 4 }}>
            CVSS:{' '}
            <strong>
              {cve.cvssScore ?? 'N/A'} {cve.cvssSeverity ?? ''}
            </strong>
          </div>

          <div style={{ fontSize: 13, marginTop: 4 }}>
            Known Exploited:{' '}
            <strong>{cve.knownExploited ? 'Yes' : 'No'}</strong>
          </div>

          {cve.description ? (
            <p style={{ fontSize: 12, marginTop: 8, color: '#475569' }}>
              {cve.description.slice(0, 220)}
              {cve.description.length > 220 ? '...' : ''}
            </p>
          ) : null}

          <div style={{ fontSize: 12, marginTop: 8, color: '#64748b' }}>
            References: {cve.references?.length ?? 0} | MISP matches:{' '}
            {cve.mispItems?.length ?? 0}
          </div>
        </div>
      ))}
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
    <section
      style={{
        padding: 16,
        border: '1px solid #dbeafe',
        borderRadius: 16,
        background: '#f8fafc',
      }}
    >
      <h2 style={{ fontSize: 18, fontWeight: 800, marginBottom: 12 }}>
        {title}
      </h2>

      {children}
    </section>
  )
}