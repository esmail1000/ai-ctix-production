'use client'

import cytoscape, { Core } from 'cytoscape'
import Link from 'next/link'
import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react'

import { AttackPathPredictionsPanel } from '@/components/knowledge-graph/AttackPathPredictionsPanel'
import { ThreatIntelPanel } from '@/components/knowledge-graph/ThreatIntelPanel'
import { ThreatScenariosPanel } from '@/components/knowledge-graph/ThreatScenariosPanel'

type ApiReport = {
  id: string
  slug?: string
  name: string
  type?: string
  uploadedAt?: string
  owner?: string
  status?: string
  findings?: number
  critical?: number
  high?: number
  medium?: number
  low?: number
  summary?: string
}

type ApiFinding = {
  id: string
  slug?: string
  reportId: string
  title: string
  summary: string
  severity: 'Critical' | 'High' | 'Medium' | 'Low'
  score: number
  status: 'Open' | 'In Review' | 'Resolved'
  cve?: string
  asset: string
  impact?: string
  evidence?: string
  remediation?: string
  detectedAt?: string
  provenance?: {
    extractionMethod?: string
    parserConfidence?: number
  }
}

type ReportsResponse = {
  reports?: ApiReport[]
}

type FindingsResponse = {
  findings?: ApiFinding[]
}

type Neo4jGraphResponse = {
  nodes: Array<{
    data: Record<string, any>
  }>
  edges: Array<{
    data: Record<string, any>
  }>
}

type GraphStats = {
  reports: number
  findings: number
  nodes: number
  edges: number
}

function getReportIdFromUrl() {
  if (typeof window === 'undefined') return ''

  return (
    new URLSearchParams(window.location.search).get('reportId')?.trim() ?? ''
  )
}

function safeId(value: string) {
  return value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9:_-]+/gi, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
}

function cleanValue(value: string | undefined | null, fallback = 'Unknown') {
  const next = (value ?? '').trim()
  return next.length > 0 ? next : fallback
}

function shortLabel(value: string, maxLength = 34) {
  const cleaned = cleanValue(value, 'Unknown')

  return cleaned.length > maxLength
    ? `${cleaned.slice(0, maxLength - 1)}…`
    : cleaned
}

function isUsefulCve(value: string | undefined) {
  const normalized = cleanValue(value, '').toLowerCase()

  return Boolean(
    normalized &&
      normalized !== '-' &&
      normalized !== '—' &&
      normalized !== 'n/a' &&
      normalized !== 'none' &&
      normalized !== 'unknown'
  )
}

function attackTypeFromFinding(finding: ApiFinding) {
  const text = `${finding.title} ${finding.summary} ${
    finding.evidence ?? ''
  }`.toLowerCase()

  if (text.includes('sql') || text.includes('sqli')) return 'SQL Injection'
  if (text.includes('xss') || text.includes('cross-site')) {
    return 'Cross-Site Scripting'
  }
  if (text.includes('command injection') || text.includes('cmd')) {
    return 'Command Injection'
  }
  if (text.includes('path traversal') || text.includes('../')) {
    return 'Path Traversal'
  }
  if (text.includes('brute force')) return 'Brute Force'
  if (text.includes('credential')) return 'Credential Attack'
  if (text.includes('ssrf')) return 'SSRF'
  if (text.includes('rce') || text.includes('remote code')) {
    return 'Remote Code Execution'
  }
  if (text.includes('waf') || text.includes('blocked')) return 'WAF Event'

  return cleanValue(finding.title.split(' related ')[0], 'Detected Threat')
}

function riskBandFromFinding(finding: ApiFinding) {
  if (finding.severity === 'Critical' || finding.score >= 90) {
    return 'Critical Risk'
  }

  if (finding.severity === 'High' || finding.score >= 70) {
    return 'High Risk'
  }

  if (finding.severity === 'Medium' || finding.score >= 40) {
    return 'Medium Risk'
  }

  return 'Low Risk'
}

function edgeId(source: string, target: string, label: string) {
  return `${source}->${target}:${safeId(label)}`
}

function makeGraphBuilder() {
  const nodes: cytoscape.ElementDefinition[] = []
  const edges: cytoscape.ElementDefinition[] = []
  const ids = new Set<string>()

  const addNode = (
    id: string,
    label: string,
    type: string,
    extra: Record<string, unknown> = {}
  ) => {
    if (ids.has(id)) return

    ids.add(id)

    nodes.push({
      data: {
        id,
        label,
        type,
        ...extra,
      },
    })
  }

  const addEdge = (source: string, target: string, label: string, weight = 1) => {
    const id = edgeId(source, target, label)

    if (ids.has(id)) return

    ids.add(id)

    edges.push({
      data: {
        id,
        source,
        target,
        label,
        weight,
      },
    })
  }

  return {
    addNode,
    addEdge,
    getElements: () => [...nodes, ...edges],
  }
}

function getFindingText(finding: ApiFinding) {
  return [
    finding.title,
    finding.summary,
    finding.impact,
    finding.evidence,
    finding.remediation,
    finding.cve,
    finding.asset,
  ]
    .filter(Boolean)
    .join(' ')
}

function extractIps(text: string) {
  return Array.from(
    new Set(text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) ?? [])
  ).filter((ip) =>
    ip.split('.').every((part) => {
      const value = Number(part)
      return Number.isInteger(value) && value >= 0 && value <= 255
    })
  )
}

function extractDomains(text: string) {
  const normalized = text.replace(/\[\.\]/g, '.').replace(/\(\.\)/g, '.')

  return Array.from(
    new Set(normalized.match(/\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b/gi) ?? [])
  ).filter((domain) => !domain.match(/^\d+(?:\.\d+){3}$/))
}

function extractHashes(text: string) {
  return Array.from(
    new Set(
      text.match(/\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b/gi) ??
        []
    )
  )
}

function extractMitreTechniques(text: string) {
  return Array.from(new Set(text.match(/\bT\d{4}(?:\.\d{3})?\b/g) ?? []))
}

function buildReportGraph(
  reports: ApiReport[],
  findings: ApiFinding[],
  focusedReportId: string
) {
  const builder = makeGraphBuilder()
  const reportById = new Map(reports.map((report) => [report.id, report]))

  const selectedFindings = focusedReportId
    ? findings.filter((finding) => finding.reportId === focusedReportId)
    : [...findings].sort((a, b) => b.score - a.score).slice(0, 35)

  const selectedReportIds = Array.from(
    new Set(selectedFindings.map((finding) => finding.reportId))
  )

  selectedReportIds.forEach((reportId) => {
    const report = reportById.get(reportId) ?? {
      id: reportId,
      name: `Report ${reportId}`,
      status: 'Unknown',
    }

    const reportNode = `report:${safeId(report.id)}`

    builder.addNode(reportNode, report.name, 'report', {
      reportId: report.id,
      status: report.status ?? 'Unknown',
      summary: report.summary ?? '',
      findings: selectedFindings.filter(
        (finding) => finding.reportId === report.id
      ).length,
    })
  })

  selectedFindings.forEach((finding) => {
    const reportNode = `report:${safeId(finding.reportId)}`
    const findingNode = `finding:${safeId(finding.id)}`
    const attackType = attackTypeFromFinding(finding)
    const attackNode = `attack:${safeId(attackType)}`
    const assetNode = `asset:${safeId(finding.asset)}`
    const severityNode = `severity:${safeId(finding.severity)}`
    const statusNode = `status:${safeId(finding.status)}`
    const riskBand = riskBandFromFinding(finding)
    const riskNode = `risk:${safeId(riskBand)}`
    const findingText = getFindingText(finding)

    const ips = extractIps(findingText)
    const domains = extractDomains(findingText)
    const hashes = extractHashes(findingText)
    const mitreTechniques = extractMitreTechniques(findingText)

    builder.addNode(findingNode, finding.title, 'finding', {
      findingId: finding.id,
      reportId: finding.reportId,
      severity: finding.severity,
      score: finding.score,
      status: finding.status,
      cve: finding.cve ?? '',
      asset: finding.asset,
      summary: finding.summary,
      evidence: finding.evidence ?? '',
      mitigation: finding.remediation ?? '',
      extractionMethod: finding.provenance?.extractionMethod ?? 'unknown',
    })

    builder.addNode(attackNode, attackType, 'attackType')
    builder.addNode(assetNode, finding.asset, 'asset')
    builder.addNode(severityNode, finding.severity, 'severity', {
      severity: finding.severity,
    })
    builder.addNode(statusNode, finding.status, 'status', {
      status: finding.status,
    })
    builder.addNode(riskNode, riskBand, 'risk', { riskBand })

    builder.addEdge(reportNode, findingNode, 'contains', 2)
    builder.addEdge(findingNode, attackNode, 'classified as', 1.6)
    builder.addEdge(findingNode, assetNode, 'affects', 1.4)
    builder.addEdge(findingNode, severityNode, 'severity', 1.3)
    builder.addEdge(findingNode, statusNode, 'status', 0.9)
    builder.addEdge(findingNode, riskNode, 'risk', 1.4)

    if (isUsefulCve(finding.cve)) {
      const cve = cleanValue(finding.cve)
      const cveNode = `cve:${safeId(cve)}`

      builder.addNode(cveNode, cve, 'cve')
      builder.addEdge(findingNode, cveNode, 'references', 1.5)
      builder.addEdge(cveNode, attackNode, 'maps to', 0.8)
    }

    ips.slice(0, 8).forEach((ip) => {
      const ipNode = `ip:${safeId(ip)}`

      builder.addNode(ipNode, ip, 'sourceIp')
      builder.addEdge(findingNode, ipNode, 'mentions IP', 1.2)
    })

    domains.slice(0, 8).forEach((domain) => {
      const domainNode = `domain:${safeId(domain)}`

      builder.addNode(domainNode, domain, 'domain')
      builder.addEdge(findingNode, domainNode, 'mentions domain', 1.2)
    })

    hashes.slice(0, 6).forEach((hash) => {
      const hashNode = `hash:${safeId(hash)}`

      builder.addNode(hashNode, shortLabel(hash, 18), 'hash', { hash })
      builder.addEdge(findingNode, hashNode, 'mentions hash', 1.2)
    })

    mitreTechniques.slice(0, 10).forEach((technique) => {
      const techniqueNode = `mitre:${safeId(technique)}`

      builder.addNode(techniqueNode, technique, 'mitre')
      builder.addEdge(findingNode, techniqueNode, 'maps to MITRE', 1.3)
      builder.addEdge(techniqueNode, attackNode, 'supports', 0.9)
    })
  })

  return builder.getElements()
}

function neo4jTypeToUiType(type: string) {
  switch (type) {
    case 'Report':
      return 'report'
    case 'Finding':
      return 'finding'
    case 'Asset':
      return 'asset'
    case 'CVE':
      return 'cve'
    case 'CWE':
      return 'cwe'
    case 'OWASP':
      return 'owasp'
    case 'MITRETechnique':
      return 'mitre'
    case 'Impact':
      return 'impact'
    case 'Remediation':
      return 'remediation'
    case 'Exploit':
      return 'exploit'
    case 'Advisory':
      return 'advisory'
    case 'CVSS':
      return 'cvss'
    case 'KnownExploitedVulnerability':
      return 'kev'
    case 'Reference':
      return 'reference'
    case 'MISPAttribute':
      return 'misp'
    default:
      return safeId(type || 'node')
  }
}

function neo4jGraphToCytoscapeElements(
  graph: Neo4jGraphResponse
): cytoscape.ElementDefinition[] {
  const nodes = (graph.nodes ?? []).map((node) => {
    const data = node.data ?? {}
    const id = String(data.id)
    const type = neo4jTypeToUiType(String(data.type ?? 'Node'))

    return {
      data: {
        ...data,
        id,
        label: shortLabel(
          String(data.name ?? data.title ?? data.text ?? data.domainId ?? id),
          42
        ),
        type,
        score: data.riskScore ?? data.score ?? 0,
        reportId: data.reportId ?? data.domainId,
        findingId: type === 'finding' ? data.domainId : data.findingId,
        summary: data.description ?? data.summary ?? data.text ?? '',
        mitigation: data.text ?? data.remediation ?? '',
      },
    }
  })

  const edges = (graph.edges ?? []).map((edge) => {
    const data = edge.data ?? {}

    return {
      data: {
        ...data,
        id: String(data.id),
        source: String(data.source),
        target: String(data.target),
        label: String(data.label ?? data.type ?? 'related to').toLowerCase(),
        weight: data.weight ?? 1.4,
      },
    }
  })

  return [...nodes, ...edges]
}

function ActionLink(props: {
  href: string
  children: ReactNode
  primary?: boolean
}) {
  return (
    <Link
      href={props.href}
      className={
        props.primary
          ? 'inline-flex items-center justify-center rounded-xl bg-[#15803d] px-3 py-1.5 text-xs font-semibold text-white transition hover:bg-[#166534]'
          : 'inline-flex items-center justify-center rounded-xl border border-[#c4e3cf] bg-white px-3 py-1.5 text-xs font-semibold text-[#173128] transition hover:bg-[#edfdf3]'
      }
    >
      {props.children}
    </Link>
  )
}

function nodeTypeLabel(type: string) {
  switch (type) {
    case 'report':
      return 'Report'
    case 'finding':
      return 'Finding'
    case 'attackType':
      return 'Attack Type'
    case 'asset':
      return 'Asset / Target'
    case 'targetPath':
      return 'Target Path'
    case 'severity':
      return 'Severity'
    case 'risk':
      return 'Risk'
    case 'cve':
      return 'CVE'
    case 'cwe':
      return 'CWE'
    case 'owasp':
      return 'OWASP'
    case 'mitre':
      return 'MITRE Technique'
    case 'impact':
      return 'Impact'
    case 'remediation':
      return 'Remediation'
    case 'exploit':
      return 'Exploit'
    case 'advisory':
      return 'Advisory'
    case 'cvss':
      return 'CVSS'
    case 'kev':
      return 'Known Exploited Vulnerability'
    case 'reference':
      return 'Reference'
    case 'misp':
      return 'MISP Intel'
    case 'sourceIp':
      return 'Source IP'
    case 'status':
      return 'Status'
    case 'action':
      return 'Action'
    case 'blocked':
      return 'Blocked Status'
    case 'domain':
      return 'Domain'
    case 'hash':
      return 'File Hash'
    default:
      return type
  }
}

const LEGEND = [
  { type: 'report', label: 'App Report', color: '#15803d' },
  { type: 'finding', label: 'Finding', color: '#0f766e' },
  { type: 'attackType', label: 'Attack Type', color: '#7c3aed' },
  { type: 'asset', label: 'Asset / Target', color: '#2563eb' },
  { type: 'cve', label: 'CVE', color: '#dc2626' },
  { type: 'cwe', label: 'CWE', color: '#ef4444' },
  { type: 'owasp', label: 'OWASP', color: '#9333ea' },
  { type: 'mitre', label: 'MITRE Technique', color: '#be123c' },
  { type: 'impact', label: 'Impact', color: '#f97316' },
  { type: 'remediation', label: 'Remediation', color: '#16a34a' },
  { type: 'advisory', label: 'Advisory', color: '#0f766e' },
  { type: 'cvss', label: 'CVSS', color: '#ca8a04' },
  { type: 'kev', label: 'CISA KEV', color: '#991b1b' },
  { type: 'reference', label: 'Reference', color: '#64748b' },
  { type: 'misp', label: 'MISP', color: '#7c3aed' },
  { type: 'sourceIp', label: 'Source IP', color: '#ea580c' },
  { type: 'targetPath', label: 'Target Path', color: '#0891b2' },
  { type: 'severity', label: 'Severity', color: '#b91c1c' },
  { type: 'status', label: 'Status', color: '#65a30d' },
  { type: 'domain', label: 'Domain', color: '#0891b2' },
  { type: 'hash', label: 'Hash', color: '#4338ca' },
]

const GRAPH_FILTERS = [
  { type: 'finding', label: 'Findings' },
  { type: 'asset', label: 'Assets' },
  { type: 'cve', label: 'CVEs' },
  { type: 'cwe', label: 'CWEs' },
  { type: 'owasp', label: 'OWASP' },
  { type: 'mitre', label: 'MITRE' },
  { type: 'impact', label: 'Impacts' },
  { type: 'remediation', label: 'Remediations' },
  { type: 'advisory', label: 'Advisories' },
  { type: 'cvss', label: 'CVSS' },
  { type: 'kev', label: 'CISA KEV' },
  { type: 'reference', label: 'References' },
  { type: 'misp', label: 'MISP' },
  { type: 'attackType', label: 'Attack Types' },
  { type: 'severity', label: 'Severity' },
  { type: 'status', label: 'Status' },
  { type: 'sourceIp', label: 'Source IPs' },
  { type: 'targetPath', label: 'Target Paths' },
  { type: 'domain', label: 'Domains' },
  { type: 'hash', label: 'Hashes' },
]

function defaultVisibleTypes() {
  return Object.fromEntries(
    GRAPH_FILTERS.map((item) => [item.type, true])
  ) as Record<string, boolean>
}

export default function AttackGraphPage() {
  const containerRef = useRef<HTMLDivElement>(null)
  const cyRef = useRef<Core | null>(null)

  const [reports, setReports] = useState<ApiReport[]>([])
  const [focusedReportId, setFocusedReportId] = useState('')
  const [selectedNode, setSelectedNode] =
    useState<Record<string, unknown> | null>(null)
  const [layout, setLayout] = useState('cose')
  const [stats, setStats] = useState<GraphStats>({
    reports: 0,
    findings: 0,
    nodes: 0,
    edges: 0,
  })
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [visibleTypes, setVisibleTypes] = useState<Record<string, boolean>>(
    () => defaultVisibleTypes()
  )

  const focusedReport = useMemo(() => {
    if (!focusedReportId) return null

    return reports.find((report) => report.id === focusedReportId) ?? null
  }, [focusedReportId, reports])

  const applyLayout = useCallback((name: string) => {
    const cy = cyRef.current

    if (!cy) return

    setLayout(name)

    const options: Record<string, unknown> = {
      name,
      animate: true,
      animationDuration: 650,
      padding: 30,
      fit: true,
    }

    if (name === 'cose') {
      Object.assign(options, {
        nodeRepulsion: () => 9000,
        idealEdgeLength: () => 95,
        edgeElasticity: () => 120,
        nestingFactor: 1.1,
        gravity: 0.38,
        numIter: 1400,
        initialTemp: 140,
        coolingFactor: 0.92,
        minTemp: 1,
        componentSpacing: 80,
        nodeDimensionsIncludeLabels: true,
      })
    }

    if (name === 'breadthfirst') {
      const roots = cy.nodes('[type = "report"]')

      Object.assign(options, {
        directed: true,
        spacingFactor: 1.25,
        roots: roots.length > 0 ? roots : undefined,
      })
    }

    if (name === 'concentric') {
      Object.assign(options, {
        minNodeSpacing: 70,
        concentric: (node: any) => {
          const type = node.data('type')

          if (type === 'report') return 10
          if (type === 'finding') return 8
          if (type === 'cve' || type === 'cwe') return 7
          if (type === 'owasp' || type === 'mitre') return 6

          return node.degree()
        },
        levelWidth: () => 2,
      })
    }

    cy.layout(options as any).run()

    window.setTimeout(() => {
      cy.fit(undefined, 35)
      cy.center()
    }, 750)
  }, [])

  function zoomBy(factor: number) {
    const cy = cyRef.current

    if (!cy) return

    cy.zoom({
      level: cy.zoom() * factor,
      renderedPosition: {
        x: cy.width() / 2,
        y: cy.height() / 2,
      },
    })
  }

  function fitGraph() {
    const cy = cyRef.current

    if (!cy) return

    cy.fit(undefined, 35)
    cy.center()
  }

  useEffect(() => {
    let cancelled = false

    async function loadData() {
      try {
        setLoading(true)
        setError('')

        const requestedReportId = getReportIdFromUrl()
        setFocusedReportId(requestedReportId)

        let nextReports: ApiReport[] = []
        let elements: cytoscape.ElementDefinition[] = []
        let findingsCount = 0

        if (requestedReportId) {
          const [reportsResponse, graphResponse] = await Promise.all([
            fetch('/api/reports', { cache: 'no-store' }),
            fetch(
              `/api/knowledge-graph/${encodeURIComponent(
                requestedReportId
              )}?depth=4`,
              { cache: 'no-store' }
            ),
          ])

          if (!reportsResponse.ok) {
            throw new Error('Failed to load reports from /api/reports')
          }

          if (!graphResponse.ok) {
            throw new Error('Failed to load Neo4j knowledge graph')
          }

          const reportsPayload: ReportsResponse = await reportsResponse.json()
          const graphPayload: Neo4jGraphResponse = await graphResponse.json()

          nextReports = reportsPayload.reports ?? []
          elements = neo4jGraphToCytoscapeElements(graphPayload)

          findingsCount = (graphPayload.nodes ?? []).filter(
            (node) => node.data?.type === 'Finding'
          ).length

          const graphReportNode = (graphPayload.nodes ?? []).find(
            (node) => node.data?.type === 'Report'
          )

          if (!nextReports.some((report) => report.id === requestedReportId)) {
            nextReports.push({
              id: requestedReportId,
              name: String(
                graphReportNode?.data?.name ?? `Report ${requestedReportId}`
              ),
              status: 'Ready',
              findings: findingsCount,
            })
          }
        } else {
          const [reportsResponse, findingsResponse] = await Promise.all([
            fetch('/api/reports', { cache: 'no-store' }),
            fetch('/api/findings', { cache: 'no-store' }),
          ])

          if (!reportsResponse.ok) {
            throw new Error('Failed to load reports from /api/reports')
          }

          if (!findingsResponse.ok) {
            throw new Error('Failed to load findings from /api/findings')
          }

          const reportsPayload: ReportsResponse = await reportsResponse.json()
          const findingsPayload: FindingsResponse =
            await findingsResponse.json()

          nextReports = reportsPayload.reports ?? []
          const nextFindings = findingsPayload.findings ?? []

          findingsCount = nextFindings.length

          elements =
            nextFindings.length > 0
              ? buildReportGraph(nextReports, nextFindings, '')
              : []
        }

        if (cancelled) return

        setReports(nextReports)

        setStats({
          reports: requestedReportId ? 1 : nextReports.length,
          findings: findingsCount,
          nodes: elements.filter((element) => !element.data.source).length,
          edges: elements.filter((element) => Boolean(element.data.source))
            .length,
        })

        if (!containerRef.current) {
          setLoading(false)
          return
        }

        cyRef.current?.destroy()

        const cy = cytoscape({
          container: containerRef.current,
          elements,
          minZoom: 0.18,
          maxZoom: 3,
          wheelSensitivity: 0.18,
          style: [
            {
              selector: 'node',
              style: {
                label: 'data(label)',
                'font-family': 'Inter, system-ui, sans-serif',
                'font-size': '9px',
                'font-weight': 700,
                color: '#173128',
                'text-valign': 'bottom',
                'text-halign': 'center',
                'text-margin-y': 7,
                'text-wrap': 'wrap',
                'text-max-width': '88px',
                'text-outline-color': '#ffffff',
                'text-outline-width': 3,
                width: 38,
                height: 38,
                'border-width': 2,
                'border-color': '#ffffff',
                'overlay-padding': 6,
                'transition-property': 'opacity border-width width height',
                'transition-duration': 160,
              } as any,
            },
            {
              selector: 'node[type="report"]',
              style: {
                'background-color': '#15803d',
                shape: 'round-rectangle',
                width: 78,
                height: 36,
                'font-size': '10px',
              } as any,
            },
            {
              selector: 'node[type="finding"]',
              style: {
                'background-color': '#0f766e',
                shape: 'round-rectangle',
                width: 68,
                height: 32,
                'font-size': '8px',
              } as any,
            },
            {
              selector: 'node[type="attackType"]',
              style: {
                'background-color': '#7c3aed',
                shape: 'diamond',
                width: 38,
                height: 38,
              } as any,
            },
            {
              selector: 'node[type="asset"], node[type="targetPath"]',
              style: {
                'background-color': '#2563eb',
                shape: 'ellipse',
              } as any,
            },
            {
              selector: 'node[type="cve"]',
              style: {
                'background-color': '#dc2626',
                shape: 'hexagon',
                width: 44,
                height: 44,
              } as any,
            },
            {
              selector: 'node[type="cwe"]',
              style: {
                'background-color': '#ef4444',
                shape: 'hexagon',
                width: 44,
                height: 44,
              } as any,
            },
            {
              selector: 'node[type="owasp"]',
              style: {
                'background-color': '#9333ea',
                shape: 'round-rectangle',
                width: 58,
                height: 34,
              } as any,
            },
            {
              selector: 'node[type="mitre"]',
              style: {
                'background-color': '#be123c',
                shape: 'triangle',
                width: 50,
                height: 50,
              } as any,
            },
            {
              selector: 'node[type="impact"]',
              style: {
                'background-color': '#f97316',
                shape: 'diamond',
                width: 48,
                height: 48,
              } as any,
            },
            {
              selector: 'node[type="remediation"]',
              style: {
                'background-color': '#16a34a',
                shape: 'round-tag',
                width: 58,
                height: 32,
                'font-size': '8px',
              } as any,
            },
            {
              selector: 'node[type="exploit"]',
              style: {
                'background-color': '#ea580c',
                shape: 'star',
                width: 46,
                height: 46,
              } as any,
            },
            {
              selector: 'node[type="advisory"]',
              style: {
                'background-color': '#0f766e',
                shape: 'round-rectangle',
                width: 70,
                height: 36,
              } as any,
            },
            {
              selector: 'node[type="cvss"]',
              style: {
                'background-color': '#ca8a04',
                shape: 'vee',
                width: 46,
                height: 46,
              } as any,
            },
            {
              selector: 'node[type="kev"]',
              style: {
                'background-color': '#991b1b',
                shape: 'star',
                width: 54,
                height: 54,
              } as any,
            },
            {
              selector: 'node[type="reference"]',
              style: {
                'background-color': '#64748b',
                shape: 'tag',
                width: 58,
                height: 32,
                'font-size': '7px',
              } as any,
            },
            {
              selector: 'node[type="misp"]',
              style: {
                'background-color': '#7c3aed',
                shape: 'diamond',
                width: 48,
                height: 48,
              } as any,
            },
            {
              selector: 'node[type="sourceIp"]',
              style: {
                'background-color': '#ea580c',
                shape: 'ellipse',
              } as any,
            },
            {
              selector: 'node[type="domain"]',
              style: {
                'background-color': '#0891b2',
                shape: 'ellipse',
                width: 44,
                height: 44,
                'font-size': '7px',
              } as any,
            },
            {
              selector: 'node[type="hash"]',
              style: {
                'background-color': '#4338ca',
                shape: 'hexagon',
                width: 44,
                height: 44,
                'font-size': '7px',
              } as any,
            },
            {
              selector: 'node[type="severity"]',
              style: {
                'background-color': '#b91c1c',
                shape: 'star',
                width: 42,
                height: 42,
              } as any,
            },
            {
              selector: 'node[type="risk"]',
              style: {
                'background-color': '#ca8a04',
                shape: 'vee',
              } as any,
            },
            {
              selector:
                'node[type="status"], node[type="action"], node[type="blocked"]',
              style: {
                'background-color': '#65a30d',
                shape: 'round-tag',
                width: 45,
                height: 30,
              } as any,
            },
            {
              selector: 'edge',
              style: {
                width: 'mapData(weight, 0.5, 2, 0.8, 2.4)',
                'line-color': '#b7d8c2',
                'target-arrow-color': '#83b895',
                'target-arrow-shape': 'triangle',
                'curve-style': 'bezier',
                'line-opacity': 0.72,
                opacity: 0.75,
                label: '',
                'font-size': '8px',
                color: '#4d6b5b',
                'text-outline-color': '#ffffff',
                'text-outline-width': 3,
                'transition-property': 'opacity line-color width',
                'transition-duration': 160,
              } as any,
            },
            {
              selector: 'edge.highlighted',
              style: {
                label: 'data(label)',
                width: 2.6,
                'line-color': '#15803d',
                'target-arrow-color': '#15803d',
                opacity: 1,
              } as any,
            },
            {
              selector: 'node.highlighted',
              style: {
                'border-width': 4,
                'border-color': '#f59e0b',
                width: 48,
                height: 48,
                opacity: 1,
                'font-size': '10px',
              } as any,
            },
            {
              selector: '.faded',
              style: {
                opacity: 0.12,
              } as any,
            },
            {
              selector: '.type-hidden',
              style: {
                display: 'none',
              } as any,
            },
            {
              selector: 'node:selected',
              style: {
                'border-color': '#f59e0b',
                'border-width': 4,
              } as any,
            },
          ],
        })

        cyRef.current = cy

        cy.on('tap', 'node', (event) => {
          const node = event.target

          setSelectedNode(node.data())

          cy.elements().removeClass('highlighted faded')

          const neighborhood = node.closedNeighborhood()

          cy.elements().not(neighborhood).addClass('faded')
          neighborhood.addClass('highlighted')
        })

        cy.on('tap', (event) => {
          if (event.target === cy) {
            setSelectedNode(null)
            cy.elements().removeClass('highlighted faded')
          }
        })

        cy.layout({
          name: 'cose',
          animate: false,
          padding: 30,
          nodeRepulsion: () => 9000,
          idealEdgeLength: () => 95,
          edgeElasticity: () => 120,
          nestingFactor: 1.1,
          gravity: 0.38,
          numIter: 1400,
          initialTemp: 140,
          coolingFactor: 0.92,
          minTemp: 1,
          componentSpacing: 80,
          nodeDimensionsIncludeLabels: true,
        } as any).run()

        window.setTimeout(() => {
          cy.fit(undefined, 35)
          cy.center()
        }, 500)

        setLoading(false)
      } catch (err) {
        if (!cancelled) {
          setError(
            err instanceof Error ? err.message : 'Failed to load attack graph.'
          )
          setLoading(false)
        }
      }
    }

    loadData()

    return () => {
      cancelled = true
      cyRef.current?.destroy()
    }
  }, [])

  useEffect(() => {
    const cy = cyRef.current

    if (!cy) return

    cy.batch(() => {
      cy.elements().removeClass('type-hidden')

      for (const [type, isVisible] of Object.entries(visibleTypes)) {
        if (!isVisible) {
          cy.nodes(`[type = "${type}"]`).addClass('type-hidden')
        }
      }

      cy.edges().forEach((edge) => {
        if (
          edge.source().hasClass('type-hidden') ||
          edge.target().hasClass('type-hidden')
        ) {
          edge.addClass('type-hidden')
        }
      })
    })
  }, [visibleTypes, loading])

  const graphTitle = focusedReport?.name ?? `Report ${focusedReportId}`

  return (
    <main className="min-h-screen bg-[#f7fbf8]" style={{ paddingTop: '78px' }}>
      <div className="mx-auto max-w-[1850px] px-4 py-4">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3 rounded-[22px] border border-[#dcefe2] bg-white px-4 py-3 shadow-sm">
          <div>
            <h1 className="text-sm font-bold text-[#173128]">{graphTitle}</h1>
            <p className="text-xs text-[#5a7668]">
              Dynamic Neo4j Knowledge Graph and Attack Path Analysis
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <span className="rounded-full border border-[#c4e3cf] bg-[#f6fff9] px-3 py-1 text-xs font-semibold text-[#173128]">
              {stats.nodes} nodes
            </span>

            <span className="rounded-full border border-[#c4e3cf] bg-[#f6fff9] px-3 py-1 text-xs font-semibold text-[#173128]">
              {stats.edges} edges
            </span>

            <span className="rounded-full border border-[#c4e3cf] bg-[#f6fff9] px-3 py-1 text-xs font-semibold text-[#173128]">
              {stats.findings} findings
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {['cose', 'breadthfirst', 'concentric', 'circle', 'grid'].map(
              (item) => (
                <button
                  key={item}
                  onClick={() => applyLayout(item)}
                  className={`rounded-xl px-3 py-1.5 text-xs font-semibold capitalize transition ${
                    layout === item
                      ? 'bg-[#15803d] text-white'
                      : 'border border-[#c4e3cf] bg-white text-[#173128] hover:bg-[#edfdf3]'
                  }`}
                >
                  {item}
                </button>
              )
            )}

            <button
              onClick={() => zoomBy(1.2)}
              className="rounded-xl border border-[#c4e3cf] bg-white px-3 py-1.5 text-xs font-semibold text-[#173128] hover:bg-[#edfdf3]"
            >
              Zoom +
            </button>

            <button
              onClick={fitGraph}
              className="rounded-xl border border-[#c4e3cf] bg-white px-3 py-1.5 text-xs font-semibold text-[#173128] hover:bg-[#edfdf3]"
            >
              Fit
            </button>

            <button
              onClick={() => zoomBy(0.8)}
              className="rounded-xl border border-[#c4e3cf] bg-white px-3 py-1.5 text-xs font-semibold text-[#173128] hover:bg-[#edfdf3]"
            >
              Zoom -
            </button>
          </div>
        </div>

        <div
          className="flex overflow-hidden rounded-[26px] border border-[#dcefe2] bg-white shadow-sm"
          style={{ height: 'calc(100vh - 205px)', minHeight: 720 }}
        >
          <div className="relative flex-1 bg-[#fbfffc]">
            {loading ? (
              <div className="absolute inset-0 z-10 flex items-center justify-center bg-white/80">
                <div className="text-center">
                  <div className="mx-auto h-12 w-12 animate-spin rounded-full border-4 border-[#15803d] border-t-transparent" />
                  <p className="mt-4 text-sm font-medium text-[#15803d]">
                    Building attack graph...
                  </p>
                </div>
              </div>
            ) : null}

            {error ? (
              <div className="absolute inset-0 z-10 flex items-center justify-center bg-white">
                <div className="max-w-md rounded-3xl border border-red-200 bg-red-50 p-6 text-center">
                  <p className="text-lg font-semibold text-red-700">
                    Graph error
                  </p>

                  <p className="mt-2 text-sm leading-6 text-red-600">
                    {error}
                  </p>
                </div>
              </div>
            ) : null}

            {!loading && !error && stats.nodes === 0 ? (
              <div className="absolute inset-0 z-10 flex items-center justify-center bg-white">
                <div className="max-w-md rounded-3xl border border-[#dcefe2] bg-[#f8fffa] p-6 text-center">
                  <p className="text-lg font-semibold text-[#0d2217]">
                    No real attack graph data yet
                  </p>

                  <p className="mt-2 text-sm leading-6 text-[#5a7668]">
                    Analyze a report first to generate findings, assets, CVEs,
                    severities, and risk nodes.
                  </p>

                  <Link
                    href="/analyzer"
                    className="mt-4 inline-flex rounded-2xl bg-[#15803d] px-4 py-2 text-sm font-semibold text-white hover:bg-[#166534]"
                  >
                    Analyze report
                  </Link>
                </div>
              </div>
            ) : null}

            <div ref={containerRef} className="h-full w-full" />
          </div>

          <aside className="flex w-[360px] shrink-0 flex-col gap-4 overflow-y-auto border-l border-[#dcefe2] bg-white p-4">
            <section className="rounded-[20px] border border-[#dcefe2] bg-[#f8fffa] p-4">
              <h3 className="text-sm font-semibold uppercase tracking-wide text-[#4d6b5b]">
                Legend
              </h3>

              <div className="mt-3 grid gap-2">
                {LEGEND.map((item) => (
                  <div key={item.type} className="flex items-center gap-2">
                    <span
                      className="h-3 w-3 rounded-full border border-white shadow-sm"
                      style={{ backgroundColor: item.color }}
                    />

                    <span className="text-xs font-medium text-[#173128]">
                      {item.label}
                    </span>
                  </div>
                ))}
              </div>
            </section>

            <section className="rounded-[20px] border border-[#dcefe2] bg-white p-4">
              <div className="flex items-center justify-between gap-3">
                <h3 className="text-sm font-semibold uppercase tracking-wide text-[#4d6b5b]">
                  Graph Filters
                </h3>

                <button
                  type="button"
                  onClick={() => setVisibleTypes(defaultVisibleTypes())}
                  className="rounded-xl border border-[#c4e3cf] bg-white px-3 py-1.5 text-xs font-semibold text-[#173128] hover:bg-[#edfdf3]"
                >
                  Reset
                </button>
              </div>

              <div className="mt-3 grid gap-2">
                {GRAPH_FILTERS.map((item) => (
                  <button
                    key={item.type}
                    type="button"
                    onClick={() =>
                      setVisibleTypes((current) => ({
                        ...current,
                        [item.type]: !current[item.type],
                      }))
                    }
                    className={`flex items-center justify-between rounded-2xl border px-3 py-2 text-xs font-semibold transition ${
                      visibleTypes[item.type]
                        ? 'border-[#bbf7d0] bg-[#f0fdf4] text-[#15803d]'
                        : 'border-[#e4f2e9] bg-[#f8fffa] text-[#6b8477]'
                    }`}
                  >
                    <span>{item.label}</span>
                    <span>{visibleTypes[item.type] ? 'On' : 'Off'}</span>
                  </button>
                ))}
              </div>
            </section>

            <section className="rounded-[20px] border border-[#dcefe2] bg-white p-4">
              <h3 className="text-sm font-semibold uppercase tracking-wide text-[#4d6b5b]">
                Selected Node
              </h3>

              {selectedNode ? (
                <div className="mt-3 space-y-2 text-sm">
                  <InfoLine
                    label="Label"
                    value={String(selectedNode.label ?? '-')}
                  />

                  <InfoLine
                    label="Type"
                    value={nodeTypeLabel(String(selectedNode.type ?? '-'))}
                  />

                  {selectedNode.reportId ? (
                    <InfoLine
                      label="Report"
                      value={String(selectedNode.reportId)}
                    />
                  ) : null}

                  {selectedNode.findingId ? (
                    <InfoLine
                      label="Finding"
                      value={String(selectedNode.findingId)}
                    />
                  ) : null}

                  {selectedNode.severity ? (
                    <InfoLine
                      label="Severity"
                      value={String(selectedNode.severity)}
                    />
                  ) : null}

                  {selectedNode.score ? (
                    <InfoLine
                      label="Score"
                      value={`${String(selectedNode.score)}/100`}
                    />
                  ) : null}

                  {selectedNode.cve ? (
                    <InfoLine label="CVE" value={String(selectedNode.cve)} />
                  ) : null}

                  {selectedNode.cvssScore ? (
                    <InfoLine
                      label="CVSS"
                      value={String(selectedNode.cvssScore)}
                    />
                  ) : null}

                  {selectedNode.cvssSeverity ? (
                    <InfoLine
                      label="CVSS Severity"
                      value={String(selectedNode.cvssSeverity)}
                    />
                  ) : null}

                  {selectedNode.knownExploited ? (
                    <InfoLine label="Known Exploited" value="Yes" />
                  ) : null}

                  {selectedNode.evidence ? (
                    <TextBlock
                      label="Evidence"
                      value={String(selectedNode.evidence)}
                    />
                  ) : null}

                  {selectedNode.summary ? (
                    <TextBlock
                      label="Summary"
                      value={String(selectedNode.summary)}
                    />
                  ) : null}

                  {selectedNode.mitigation ? (
                    <TextBlock
                      label="Mitigation"
                      value={String(selectedNode.mitigation)}
                    />
                  ) : null}

                  {selectedNode.hash ? (
                    <TextBlock
                      label="Hash"
                      value={String(selectedNode.hash)}
                      mono
                    />
                  ) : null}

                  <div className="grid gap-2 pt-2">
                    {selectedNode.reportId ? (
                      <>
                        <ActionLink
                          href={`/reports/${encodeURIComponent(
                            String(selectedNode.reportId)
                          )}`}
                        >
                          Open Report
                        </ActionLink>

                        <ActionLink
                          href={`/results?reportId=${encodeURIComponent(
                            String(selectedNode.reportId)
                          )}`}
                        >
                          Report Findings
                        </ActionLink>
                      </>
                    ) : null}

                    {selectedNode.findingId ? (
                      <ActionLink
                        href={`/results/${encodeURIComponent(
                          String(selectedNode.findingId)
                        )}`}
                      >
                        Open Finding
                      </ActionLink>
                    ) : null}
                  </div>
                </div>
              ) : (
                <p className="mt-3 text-xs leading-5 text-[#5a7668]">
                  Click a node to highlight its connections and inspect its
                  data.
                </p>
              )}
            </section>

            <section className="rounded-[20px] border border-[#dcefe2] bg-white p-4">
              <h3 className="text-sm font-semibold uppercase tracking-wide text-[#4d6b5b]">
                Controls
              </h3>

              <ul className="mt-3 space-y-1 text-xs leading-5 text-[#5a7668]">
                <li>Click node → highlight neighbours.</li>
                <li>Click empty background → reset.</li>
                <li>Scroll to zoom, drag to pan.</li>
                <li>Use COSE for the old attack graph style.</li>
              </ul>
            </section>

            {focusedReportId ? (
              <>
                <AttackPathPredictionsPanel reportId={focusedReportId} />
                <ThreatIntelPanel reportId={focusedReportId} />
                <ThreatScenariosPanel reportId={focusedReportId} />
              </>
            ) : null}
          </aside>
        </div>
      </div>
    </main>
  )
}

function InfoLine({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] p-3">
      <p className="text-[10px] font-semibold uppercase tracking-wide text-[#5a7668]">
        {label}
      </p>

      <p className="mt-1 break-words text-xs font-semibold text-[#173128]">
        {value}
      </p>
    </div>
  )
}

function TextBlock({
  label,
  value,
  mono,
}: {
  label: string
  value: string
  mono?: boolean
}) {
  return (
    <div className="rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] p-3">
      <p className="text-[10px] font-semibold uppercase tracking-wide text-[#5a7668]">
        {label}
      </p>

      <p
        className={`mt-1 break-words text-xs leading-5 text-[#173128] ${
          mono ? 'font-mono' : ''
        }`}
      >
        {value}
      </p>
    </div>
  )
}