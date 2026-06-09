'use client'

import Link from 'next/link'
import {
  useCallback,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react'

type ApiReport = {
  id: string
  name: string
  type?: string
  uploadedAt?: string
  status?: string
  findings?: number
  critical?: number
  high?: number
  medium?: number
  low?: number
  summary?: string
}

type ReportsResponse = {
  reports?: ApiReport[]
  error?: string
}

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

type AttackPathsResponse = {
  paths?: AttackPathPrediction[]
  error?: string
  details?: string
}

type AttackPathStats = {
  total: number
  criticalHigh: number
  maxPathScore: number
  averageConfidence: number
  findings: number
}

const LIKELIHOOD_FILTERS = ['All', 'Critical', 'High', 'Medium', 'Low']

function getReportIdFromUrl() {
  if (typeof window === 'undefined') return ''

  return new URLSearchParams(window.location.search).get('reportId')?.trim() ?? ''
}

function setReportIdInUrl(reportId: string) {
  if (typeof window === 'undefined') return

  const next = reportId
    ? `/attack-paths?reportId=${encodeURIComponent(reportId)}`
    : '/attack-paths'

  window.history.replaceState(null, '', next)
}

function stringValue(value: unknown, fallback = ''): string {
  if (typeof value === 'string') return value.trim() || fallback
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  return fallback
}

function numberValue(value: unknown, fallback = 0): number {
  if (typeof value === 'number' && Number.isFinite(value)) return value
  const parsed = Number(value)
  return Number.isFinite(parsed) ? parsed : fallback
}

function normalizeText(value: unknown) {
  return stringValue(value).toLowerCase()
}

function selectedReportParam(reportId: string) {
  return reportId ? encodeURIComponent(reportId) : ''
}

function clampScore(value: unknown) {
  const score = Math.round(numberValue(value, 0))
  return Math.max(0, Math.min(score, 100))
}

function riskTone(value?: string) {
  const normalized = normalizeText(value)

  if (normalized.includes('critical')) return 'border-red-200 bg-red-50 text-red-700'
  if (normalized.includes('high')) return 'border-orange-200 bg-orange-50 text-orange-700'
  if (normalized.includes('medium')) return 'border-yellow-200 bg-yellow-50 text-yellow-700'
  if (normalized.includes('low')) return 'border-emerald-200 bg-emerald-50 text-emerald-700'
  return 'border-slate-200 bg-slate-50 text-slate-700'
}

function severityTone(value?: string) {
  const normalized = normalizeText(value)

  if (normalized.includes('critical')) return 'bg-red-100 text-red-700 border-red-200'
  if (normalized.includes('high')) return 'bg-orange-100 text-orange-700 border-orange-200'
  if (normalized.includes('medium')) return 'bg-yellow-100 text-yellow-700 border-yellow-200'
  if (normalized.includes('low')) return 'bg-emerald-100 text-emerald-700 border-emerald-200'
  return 'bg-slate-100 text-slate-700 border-slate-200'
}

function getPathNodes(path: AttackPathPrediction) {
  return path.path?.nodes ?? []
}

function getPathRelationships(path: AttackPathPrediction) {
  return path.path?.relationships ?? []
}

function getPathTypes(path: AttackPathPrediction) {
  const types = new Set<string>()
  for (const node of getPathNodes(path)) {
    const type = stringValue(node.type, 'Node')
    if (type) types.add(type)
  }

  return Array.from(types)
}

function hasPathType(path: AttackPathPrediction, typeName: string) {
  const target = typeName.toLowerCase()

  return getPathNodes(path).some(
    (node) => stringValue(node.type).toLowerCase() === target
  )
}

function buildPathSequence(path: AttackPathPrediction) {
  const nodes = getPathNodes(path)
  const relationships = getPathRelationships(path)

  if (nodes.length === 0) return []

  const sequence: Array<{ label: string; type: 'node' | 'relationship' }> = []

  for (let index = 0; index < nodes.length; index += 1) {
    sequence.push({
      label: stringValue(nodes[index].name || nodes[index].id || nodes[index].type, 'Unknown'),
      type: 'node',
    })

    if (index < relationships.length) {
      sequence.push({
        label: stringValue(relationships[index].type, 'related to').replace(/_/g, ' '),
        type: 'relationship',
      })
    }
  }

  return sequence
}

function deriveRecommendedAction(path: AttackPathPrediction) {
  const likelihood = normalizeText(path.exploitLikelihood)
  const severity = normalizeText(path.severity)
  const outcome = normalizeText(path.predictedOutcome)
  const hasCve = hasPathType(path, 'CVE')
  const hasExploit = hasPathType(path, 'Exploit')
  const pathScore = clampScore(path.attackPathScore)

  if (hasExploit || likelihood.includes('critical') || pathScore >= 85) {
    return {
      title: 'Immediate containment and remediation',
      details:
        'Review the linked finding first, apply the available remediation or compensating control, and reduce exposure on the affected asset before further deployment.',
      priority: 'Immediate',
    }
  }

  if (hasCve || likelihood.includes('high') || severity.includes('high')) {
    return {
      title: 'Patch validation and exposure reduction',
      details:
        'Validate patch or advisory status, confirm the affected component, and apply network or configuration controls while remediation is scheduled.',
      priority: 'High',
    }
  }

  if (outcome.includes('credential') || outcome.includes('authentication')) {
    return {
      title: 'Identity control review',
      details:
        'Review authentication controls, credential exposure evidence, and access boundaries for the affected service or asset.',
      priority: 'High',
    }
  }

  return {
    title: 'Verify finding evidence and plan mitigation',
    details:
      'Validate the graph path against the original finding evidence, then apply the finding remediation or create a short-term mitigation task.',
    priority: 'Standard',
  }
}

function calculateStats(paths: AttackPathPrediction[]): AttackPathStats {
  const findingIds = new Set<string>()
  let confidenceTotal = 0
  let maxPathScore = 0
  let criticalHigh = 0

  for (const path of paths) {
    if (path.findingId) findingIds.add(path.findingId)

    confidenceTotal += clampScore(path.confidence)
    maxPathScore = Math.max(maxPathScore, clampScore(path.attackPathScore))

    const likelihood = normalizeText(path.exploitLikelihood)
    if (likelihood.includes('critical') || likelihood.includes('high')) {
      criticalHigh += 1
    }
  }

  return {
    total: paths.length,
    criticalHigh,
    maxPathScore,
    averageConfidence:
      paths.length > 0 ? Math.round(confidenceTotal / paths.length) : 0,
    findings: findingIds.size,
  }
}

function sortPaths(paths: AttackPathPrediction[]) {
  return [...paths].sort((left, right) => {
    const scoreDiff = clampScore(right.attackPathScore) - clampScore(left.attackPathScore)
    if (scoreDiff !== 0) return scoreDiff

    return clampScore(right.riskScore) - clampScore(left.riskScore)
  })
}

function filterPaths(
  paths: AttackPathPrediction[],
  query: string,
  likelihoodFilter: string
) {
  const search = query.trim().toLowerCase()
  const likelihoodTarget = likelihoodFilter.toLowerCase()

  return paths.filter((path) => {
    const likelihood = normalizeText(path.exploitLikelihood || 'Unknown')
    const matchesLikelihood =
      likelihoodTarget === 'all' || likelihood.includes(likelihoodTarget)

    if (!matchesLikelihood) return false
    if (!search) return true

    const haystack = [
      path.findingId,
      path.findingTitle,
      path.severity,
      path.exploitLikelihood,
      path.predictedOutcome,
      getPathNodes(path)
        .map((node) => `${node.type} ${node.name} ${node.id}`)
        .join(' '),
      path.reasoning?.join(' '),
    ]
      .filter(Boolean)
      .join(' ')
      .toLowerCase()

    return haystack.includes(search)
  })
}

function buildExplanation(stats: AttackPathStats, selectedReportName?: string) {
  if (stats.total === 0) {
    return 'No attack paths were returned for the selected report yet. Analyze the report and build graph relationships first.'
  }

  const scope = selectedReportName ? ` for ${selectedReportName}` : ''

  return `The system found ${stats.total} graph-derived attack path prediction${
    stats.total === 1 ? '' : 's'
  }${scope}. ${stats.criticalHigh} path${
    stats.criticalHigh === 1 ? '' : 's'
  } have High/Critical likelihood labels, with a maximum path score of ${
    stats.maxPathScore
  }/100 and average evidence confidence of ${stats.averageConfidence}%.`
}

export default function AttackPathsPage() {
  const [reports, setReports] = useState<ApiReport[]>([])
  const [selectedReportId, setSelectedReportId] = useState('')
  const [paths, setPaths] = useState<AttackPathPrediction[]>([])
  const [isLoadingReports, setIsLoadingReports] = useState(true)
  const [isLoadingPaths, setIsLoadingPaths] = useState(false)
  const [error, setError] = useState('')
  const [query, setQuery] = useState('')
  const [likelihoodFilter, setLikelihoodFilter] = useState('All')

  const selectedReport = useMemo(
    () => reports.find((report) => report.id === selectedReportId) ?? null,
    [reports, selectedReportId]
  )

  const sortedPaths = useMemo(() => sortPaths(paths), [paths])

  const filteredPaths = useMemo(
    () => filterPaths(sortedPaths, query, likelihoodFilter),
    [likelihoodFilter, query, sortedPaths]
  )

  const stats = useMemo(() => calculateStats(paths), [paths])
  const encodedReportId = selectedReportParam(selectedReportId)
  const explanation = buildExplanation(stats, selectedReport?.name)

  const loadReports = useCallback(async () => {
    try {
      setIsLoadingReports(true)
      setError('')

      const response = await fetch('/api/reports', { cache: 'no-store' })
      const payload: ReportsResponse = await response.json().catch(() => ({}))

      if (!response.ok) {
        throw new Error(payload.error || `Failed to load reports: ${response.status}`)
      }

      const nextReports = payload.reports ?? []
      const requestedReportId = getReportIdFromUrl()
      const requestedExists = nextReports.some(
        (report) => report.id === requestedReportId
      )
      const nextSelected = requestedExists
        ? requestedReportId
        : requestedReportId || nextReports[0]?.id || ''

      setReports(nextReports)
      setSelectedReportId(nextSelected)
      if (nextSelected) setReportIdInUrl(nextSelected)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load reports.')
    } finally {
      setIsLoadingReports(false)
    }
  }, [])

  const loadAttackPaths = useCallback(async (reportId: string) => {
    if (!reportId) {
      setPaths([])
      return
    }

    try {
      setIsLoadingPaths(true)
      setError('')

      const response = await fetch(
        `/api/attack-paths/${encodeURIComponent(reportId)}?limit=25`,
        { cache: 'no-store' }
      )
      const payload: AttackPathsResponse = await response.json().catch(() => ({}))

      if (!response.ok) {
        throw new Error(
          payload.details || payload.error || `Failed to load attack paths: ${response.status}`
        )
      }

      setPaths(payload.paths ?? [])
    } catch (err) {
      setPaths([])
      setError(err instanceof Error ? err.message : 'Failed to load attack paths.')
    } finally {
      setIsLoadingPaths(false)
    }
  }, [])

  useEffect(() => {
    void loadReports()
  }, [loadReports])

  useEffect(() => {
    if (!isLoadingReports && selectedReportId) {
      void loadAttackPaths(selectedReportId)
    }
  }, [isLoadingReports, loadAttackPaths, selectedReportId])

  function handleReportChange(reportId: string) {
    setSelectedReportId(reportId)
    setReportIdInUrl(reportId)
  }

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
            <div>
              <p className="text-xs font-bold uppercase tracking-[0.22em] text-[#087a3a]">
                AI Attack Path Prediction Center
              </p>
              <h1 className="mt-3 text-3xl font-semibold tracking-[-0.04em] text-[#0d2217] md:text-4xl">
                Graph-derived exploitation paths
              </h1>
              <p className="mt-3 max-w-4xl text-sm leading-7 text-[#5a7668]">
                Review attack paths returned by the secured graph API. Each path is tied to a real finding, graph nodes, likelihood, confidence, and predicted outcome.
              </p>

              <div className="mt-4 flex flex-wrap gap-2">
                <ActionLink href="/reports">Reports</ActionLink>
                <ActionLink href="/results">Findings</ActionLink>
                {encodedReportId ? (
                  <>
                    <ActionLink href={`/reports/${encodedReportId}`}>Open Report</ActionLink>
                    <ActionLink href={`/results?reportId=${encodedReportId}`}>Report Findings</ActionLink>
                    <ActionLink href={`/risk-scoring?reportId=${encodedReportId}`}>Risk Scoring</ActionLink>
                    <ActionLink href={`/graph?reportId=${encodedReportId}`}>Knowledge Graph</ActionLink>
                    <ActionLink href={`/recommendations?reportId=${encodedReportId}`}>Recommendations</ActionLink>
                    <ActionLink href={`/export?reportId=${encodedReportId}`} primary>
                      Export
                    </ActionLink>
                  </>
                ) : null}
              </div>
            </div>

            <div className="rounded-[28px] border border-[#dceee3] bg-white/78 p-5 shadow-[0_20px_60px_rgba(15,43,29,0.07)] backdrop-blur">
              <label className="text-xs font-bold uppercase tracking-[0.16em] text-[#5a7668]">
                Report scope
              </label>
              <select
                value={selectedReportId}
                onChange={(event) => handleReportChange(event.target.value)}
                disabled={isLoadingReports || reports.length === 0}
                className="mt-2 h-12 w-full rounded-2xl border border-[#c4e3cf] bg-white px-4 text-sm font-semibold text-[#173128] outline-none focus:border-[#087a3a] disabled:cursor-not-allowed disabled:opacity-60"
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
                type="button"
                onClick={() => void loadAttackPaths(selectedReportId)}
                disabled={!selectedReportId || isLoadingPaths}
                className="mt-3 h-12 w-full rounded-2xl bg-[#087a3a] px-5 text-sm font-semibold text-white shadow-[0_16px_32px_rgba(8,122,58,0.18)] transition hover:-translate-y-0.5 hover:bg-[#066b33] disabled:cursor-not-allowed disabled:opacity-60"
              >
                {isLoadingPaths ? 'Loading paths…' : 'Refresh Attack Paths'}
              </button>
            </div>
          </div>
        </header>

        <section className="mt-5 grid gap-3 md:grid-cols-2 xl:grid-cols-5">
          <MetricCard label="Attack paths" value={String(stats.total)} helper={`${filteredPaths.length} visible`} />
          <MetricCard label="High signal" value={String(stats.criticalHigh)} helper="High/Critical likelihood" />
          <MetricCard label="Max path score" value={`${stats.maxPathScore}/100`} helper="Highest graph path score" />
          <MetricCard label="Avg confidence" value={`${stats.averageConfidence}%`} helper="Evidence confidence" />
          <MetricCard label="Findings" value={String(stats.findings)} helper="Linked source findings" />
        </section>

        {selectedReport ? (
          <section className="mt-5 rounded-[28px] border border-[#dceee3] bg-white/95 p-5 shadow-[0_22px_60px_rgba(15,43,29,0.05)]">
            <div className="flex flex-wrap items-center gap-2">
              <Pill>{selectedReport.id}</Pill>
              <Pill>{selectedReport.status ?? 'Ready'}</Pill>
              {selectedReport.findings !== undefined ? <Pill>{selectedReport.findings} findings</Pill> : null}
              {selectedReport.critical !== undefined ? <Pill>{selectedReport.critical} critical</Pill> : null}
              {selectedReport.high !== undefined ? <Pill>{selectedReport.high} high</Pill> : null}
            </div>
            <h2 className="mt-3 text-xl font-semibold text-[#0d2217]">{selectedReport.name}</h2>
            <p className="mt-2 text-sm leading-7 text-[#5a7668]">{explanation}</p>
          </section>
        ) : null}

        <section className="mt-5 grid gap-5 xl:grid-cols-[minmax(0,1fr)_360px]">
          <div className="space-y-4">
            <div className="flex flex-col gap-3 rounded-[28px] border border-[#dceee3] bg-white/95 p-5 shadow-[0_22px_60px_rgba(15,43,29,0.05)] lg:flex-row lg:items-center lg:justify-between">
              <div>
                <p className="text-sm font-semibold text-[#0d2217]">Attack path list</p>
                <p className="mt-1 text-xs text-[#5a7668]">
                  Sorted by path score, then base risk score.
                </p>
              </div>

              <div className="flex flex-col gap-2 sm:flex-row">
                <input
                  value={query}
                  onChange={(event) => setQuery(event.target.value)}
                  placeholder="Search finding, node, CVE, outcome…"
                  className="h-11 min-w-[280px] rounded-2xl border border-[#c4e3cf] bg-[#f8fffa] px-4 text-sm font-medium text-[#173128] outline-none focus:border-[#087a3a]"
                />
                <select
                  value={likelihoodFilter}
                  onChange={(event) => setLikelihoodFilter(event.target.value)}
                  className="h-11 rounded-2xl border border-[#c4e3cf] bg-[#f8fffa] px-4 text-sm font-semibold text-[#173128] outline-none focus:border-[#087a3a]"
                >
                  {LIKELIHOOD_FILTERS.map((item) => (
                    <option key={item} value={item}>{item}</option>
                  ))}
                </select>
              </div>
            </div>

            {error ? (
              <div className="rounded-[28px] border border-red-200 bg-red-50 p-5 text-red-700">
                <p className="text-sm font-bold">Attack path error</p>
                <p className="mt-2 text-sm leading-6">{error}</p>
              </div>
            ) : null}

            {isLoadingPaths ? (
              <div className="rounded-[32px] border border-[#dceee3] bg-white p-8 text-center shadow-[0_22px_60px_rgba(15,43,29,0.05)]">
                <div className="mx-auto h-12 w-12 animate-spin rounded-full border-4 border-[#087a3a] border-t-transparent" />
                <p className="mt-4 text-sm font-bold text-[#087a3a]">Loading graph-derived attack paths…</p>
              </div>
            ) : null}

            {!isLoadingPaths && !error && filteredPaths.length === 0 ? (
              <div className="rounded-[32px] border border-dashed border-[#c4e3cf] bg-[#f8fffa] p-8 text-center">
                <p className="text-lg font-semibold text-[#0d2217]">No attack paths found</p>
                <p className="mt-2 text-sm leading-7 text-[#5a7668]">
                  The API did not return matching attack paths for this report/filter. Re-analyze the report or review graph generation.
                </p>
                <div className="mt-5 flex justify-center gap-3">
                  <ActionLink href="/analyzer" primary>Analyze Report</ActionLink>
                  {encodedReportId ? <ActionLink href={`/graph?reportId=${encodedReportId}`}>Open Graph</ActionLink> : null}
                </div>
              </div>
            ) : null}

            {!isLoadingPaths && !error ? (
              <div className="space-y-4">
                {filteredPaths.map((path, index) => (
                  <AttackPathCard
                    key={`${path.findingId}-${index}`}
                    path={path}
                    reportId={selectedReportId}
                  />
                ))}
              </div>
            ) : null}
          </div>

          <aside className="space-y-4 xl:sticky xl:top-24 xl:max-h-[calc(100vh-120px)] xl:overflow-y-auto xl:pr-1">
            <Panel title="Review priority">
              <div className="space-y-3">
                {sortedPaths.slice(0, 5).map((path, index) => (
                  <Link
                    key={`${path.findingId}-priority-${index}`}
                    href={`/results/${encodeURIComponent(path.findingId)}`}
                    className="block rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] p-3 transition hover:border-[#087a3a] hover:bg-white"
                  >
                    <div className="flex items-center justify-between gap-3">
                      <span className="text-xs font-semibold text-[#0d2217]">#{index + 1}</span>
                      <span className={`rounded-full border px-2 py-1 text-[10px] font-bold ${riskTone(path.exploitLikelihood)}`}>
                        {path.exploitLikelihood ?? 'Unknown'}
                      </span>
                    </div>
                    <p className="mt-2 line-clamp-2 text-xs font-semibold leading-5 text-[#173128]">
                      {path.findingTitle}
                    </p>
                    <p className="mt-1 text-[11px] text-[#5a7668]">
                      Path {clampScore(path.attackPathScore)}/100 · Confidence {clampScore(path.confidence)}%
                    </p>
                  </Link>
                ))}
              </div>
            </Panel>

            <Panel title="Next actions">
              <div className="grid gap-2">
                {encodedReportId ? (
                  <>
                    <ActionLink href={`/recommendations?reportId=${encodedReportId}`} primary>
                      Open Recommendations
                    </ActionLink>
                    <ActionLink href={`/risk-scoring?reportId=${encodedReportId}`}>Risk Scoring</ActionLink>
                    <ActionLink href={`/graph?reportId=${encodedReportId}`}>Knowledge Graph</ActionLink>
                    <ActionLink href={`/results?reportId=${encodedReportId}`}>Report Findings</ActionLink>
                    <ActionLink href={`/export?reportId=${encodedReportId}`}>Export Report</ActionLink>
                  </>
                ) : (
                  <ActionLink href="/reports">Select Report</ActionLink>
                )}
              </div>
            </Panel>

            <Panel title="How to read this">
              <p className="text-sm leading-7 text-[#5a7668]">
                Attack path score combines the stored finding risk with graph evidence such as CVE, CWE, OWASP, MITRE, exploit, and impact nodes. Review High/Critical paths first, then confirm the linked finding evidence before applying remediation.
              </p>
            </Panel>
          </aside>
        </section>
      </section>
    </main>
  )
}

function AttackPathCard({ path, reportId }: { path: AttackPathPrediction; reportId: string }) {
  const action = deriveRecommendedAction(path)
  const pathTypes = getPathTypes(path)
  const sequence = buildPathSequence(path)
  const encodedReportId = selectedReportParam(reportId)

  return (
    <article className="overflow-hidden rounded-[32px] border border-[#dceee3] bg-white shadow-[0_22px_60px_rgba(15,43,29,0.06)]">
      <div className="border-b border-[#e4f2e9] bg-[#f8fffa] p-5">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <span className={`rounded-full border px-3 py-1 text-xs font-semibold ${severityTone(path.severity)}`}>
                {path.severity || 'Unknown'}
              </span>
              <span className={`rounded-full border px-3 py-1 text-xs font-semibold ${riskTone(path.exploitLikelihood)}`}>
                {path.exploitLikelihood ?? 'Unknown likelihood'}
              </span>
              <span className="rounded-full border border-[#c4e3cf] bg-white px-3 py-1 text-xs font-bold text-[#173128]">
                {path.findingId}
              </span>
            </div>
            <h3 className="mt-3 text-xl font-semibold leading-8 text-[#0d2217]">
              {path.findingTitle}
            </h3>
            {path.predictedOutcome ? (
              <p className="mt-2 max-w-5xl text-sm leading-7 text-[#5a7668]">
                {path.predictedOutcome}
              </p>
            ) : null}
          </div>

          <div className="grid min-w-[280px] grid-cols-3 gap-2">
            <MiniMetric label="Risk" value={`${clampScore(path.riskScore)}`} />
            <MiniMetric label="Path" value={`${clampScore(path.attackPathScore)}`} />
            <MiniMetric label="Conf." value={`${clampScore(path.confidence)}%`} />
          </div>
        </div>
      </div>

      <div className="grid gap-5 p-5 xl:grid-cols-[minmax(0,1fr)_320px]">
        <div className="space-y-4">
          <section className="rounded-3xl border border-[#e4f2e9] bg-[#fbfffc] p-4">
            <p className="text-xs font-semibold uppercase tracking-[0.16em] text-[#087a3a]">
              Graph path sequence
            </p>
            {sequence.length > 0 ? (
              <div className="mt-3 flex flex-wrap items-center gap-2">
                {sequence.map((item, index) => (
                  <span
                    key={`${item.label}-${index}`}
                    className={
                      item.type === 'node'
                        ? 'rounded-2xl border border-[#c4e3cf] bg-white px-3 py-2 text-xs font-bold text-[#173128]'
                        : 'rounded-full bg-[#eaf8ef] px-2 py-1 text-[10px] font-bold uppercase tracking-wide text-[#087a3a]'
                    }
                  >
                    {item.label}
                  </span>
                ))}
              </div>
            ) : (
              <p className="mt-2 text-sm leading-6 text-[#5a7668]">No graph sequence was returned for this path.</p>
            )}
          </section>

          <section className="rounded-3xl border border-[#e4f2e9] bg-white p-4">
            <p className="text-xs font-semibold uppercase tracking-[0.16em] text-[#087a3a]">
              Reasoning
            </p>
            {path.reasoning?.length ? (
              <ul className="mt-3 space-y-2">
                {path.reasoning.map((reason, index) => (
                  <li key={`${path.findingId}-reason-${index}`} className="rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] px-3 py-2 text-sm leading-6 text-[#173128]">
                    {reason}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="mt-2 text-sm leading-6 text-[#5a7668]">No reasoning details were returned by the API.</p>
            )}
          </section>
        </div>

        <aside className="space-y-4">
          <section className="rounded-3xl border border-[#e4f2e9] bg-[#f8fffa] p-4">
            <p className="text-xs font-semibold uppercase tracking-[0.16em] text-[#087a3a]">
              Evidence types
            </p>
            <div className="mt-3 flex flex-wrap gap-2">
              {pathTypes.length > 0 ? (
                pathTypes.map((type) => (
                  <span key={type} className="rounded-full border border-[#c4e3cf] bg-white px-3 py-1 text-xs font-bold text-[#173128]">
                    {type}
                  </span>
                ))
              ) : (
                <span className="text-sm text-[#5a7668]">No node types returned</span>
              )}
            </div>
          </section>

          <section className="rounded-3xl border border-[#e4f2e9] bg-white p-4">
            <p className="text-xs font-semibold uppercase tracking-[0.16em] text-[#087a3a]">
              Derived next action
            </p>
            <div className="mt-3 rounded-2xl border border-[#c4e3cf] bg-[#f8fffa] p-3">
              <p className="text-sm font-semibold text-[#0d2217]">{action.title}</p>
              <p className="mt-2 text-sm leading-6 text-[#5a7668]">{action.details}</p>
              <span className="mt-3 inline-flex rounded-full border border-[#c4e3cf] bg-white px-3 py-1 text-xs font-bold text-[#087a3a]">
                Priority: {action.priority}
              </span>
            </div>
          </section>

          <section className="mt-5 grid gap-2">
            <ActionLink href={`/results/${encodeURIComponent(path.findingId)}`} primary>
              Open Finding
            </ActionLink>
            {encodedReportId ? (
              <>
                <ActionLink href={`/graph?reportId=${encodedReportId}`}>Open Graph</ActionLink>
                <ActionLink href={`/recommendations?reportId=${encodedReportId}`}>Recommendations</ActionLink>
                <ActionLink href={`/risk-scoring?reportId=${encodedReportId}`}>Risk Scoring</ActionLink>
              </>
            ) : null}
          </section>
        </aside>
      </div>
    </article>
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

function MetricCard({ label, value, helper }: { label: string; value: string; helper: string }) {
  return (
    <div className="rounded-[26px] border border-[#dceee3] bg-white/95 p-5 shadow-[0_22px_60px_rgba(15,43,29,0.05)]">
      <p className="text-xs font-semibold uppercase tracking-[0.12em] text-[#5a7668]">{label}</p>
      <p className="mt-2 text-2xl font-semibold tracking-tight text-[#0d2217]">{value}</p>
      <p className="mt-1 text-xs leading-5 text-[#5a7668]">{helper}</p>
    </div>
  )
}

function MiniMetric({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-2xl border border-[#dceee3] bg-white px-3 py-2 text-center">
      <p className="text-[10px] font-bold uppercase tracking-wide text-[#5a7668]">{label}</p>
      <p className="mt-1 text-lg font-semibold text-[#0d2217]">{value}</p>
    </div>
  )
}

function Panel({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="rounded-[28px] border border-[#dceee3] bg-white p-4 shadow-[0_16px_45px_rgba(15,43,29,0.055)]">
      <h2 className="mb-3 text-base font-semibold text-[#0d2217]">{title}</h2>
      {children}
    </section>
  )
}

function Pill({ children }: { children: ReactNode }) {
  return (
    <span className="rounded-full border border-[#c4e3cf] bg-[#f6fff9] px-3 py-1 text-xs font-bold text-[#173128]">
      {children}
    </span>
  )
}
