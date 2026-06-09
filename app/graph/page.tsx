  'use client'

  import cytoscape, { type Core, type ElementDefinition, type NodeSingular } from 'cytoscape'
import Link from 'next/link'
import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
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

  type GraphRecord = {
    data?: Record<string, unknown>
  }

  type KnowledgeGraphResponse = {
    nodes?: GraphRecord[]
    edges?: GraphRecord[]
    error?: string
    details?: string
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
      nodes: Array<{ type: string; id: string; name: string }>
      relationships: Array<{ type: string }>
    }
  }

  type AttackPathsResponse = {
    paths?: AttackPathPrediction[]
    error?: string
    details?: string
  }

  type NodeData = Record<string, unknown> & {
    id: string
    label: string
    type: string
    domainId?: string
    reportId?: string
    findingId?: string
    severity?: string
    score?: number
    riskScore?: number
    cve?: string
    summary?: string
    description?: string
    mitigation?: string
    text?: string
    name?: string
  }

  type GraphStats = {
    nodes: number
    edges: number
    findings: number
    assets: number
    cves: number
    mitre: number
    impacts: number
    remediations: number
    attackPaths: number
    highSignalPaths: number
  }

  const DEFAULT_DEPTH = 4
  const MAX_DEPTH = 6
  const TYPE_LABELS: Record<string, string> = {
    report: 'Report',
    finding: 'Finding',
    asset: 'Asset',
    cve: 'CVE',
    cwe: 'CWE',
    owasp: 'OWASP',
    mitre: 'MITRE',
    impact: 'Impact',
    remediation: 'Remediation',
    exploit: 'Exploit',
    advisory: 'Advisory',
    cvss: 'CVSS',
    kev: 'Known Exploited',
    reference: 'Reference',
    misp: 'MISP Intel',
    risk: 'Risk',
    status: 'Status',
    sourceIp: 'Source IP',
    domain: 'Domain',
    hash: 'Hash',
    unknown: 'Unknown',
  }

  const TYPE_ORDER = [
    'report',
    'finding',
    'asset',
    'cve',
    'cwe',
    'owasp',
    'mitre',
    'impact',
    'remediation',
    'exploit',
    'kev',
    'cvss',
    'advisory',
    'reference',
    'misp',
    'risk',
    'status',
    'sourceIp',
    'domain',
    'hash',
  ]

  const TYPE_COLORS: Record<string, string> = {
    report: '#087a3a',
    finding: '#0f766e',
    asset: '#2563eb',
    cve: '#dc2626',
    cwe: '#ef4444',
    owasp: '#7c3aed',
    mitre: '#be123c',
    impact: '#f97316',
    remediation: '#16a34a',
    exploit: '#ea580c',
    advisory: '#0f766e',
    cvss: '#ca8a04',
    kev: '#991b1b',
    reference: '#64748b',
    misp: '#7c3aed',
    risk: '#ca8a04',
    status: '#65a30d',
    sourceIp: '#ea580c',
    domain: '#0891b2',
    hash: '#4338ca',
    unknown: '#64748b',
  }

  function getReportIdFromUrl() {
    if (typeof window === 'undefined') return ''

    return new URLSearchParams(window.location.search).get('reportId')?.trim() ?? ''
  }

  function setReportIdInUrl(reportId: string) {
    if (typeof window === 'undefined') return

    const next = reportId ? `/graph?reportId=${encodeURIComponent(reportId)}` : '/graph'
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

  function shortLabel(value: unknown, maxLength = 44): string {
    const label = stringValue(value, 'Unknown')
    return label.length > maxLength ? `${label.slice(0, maxLength - 1)}…` : label
  }

  function normalizeType(value: unknown): string {
    const type = stringValue(value, 'unknown')

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
        return type
          .trim()
          .replace(/[^a-z0-9:_-]+/gi, '-')
          .replace(/-+/g, '-')
          .replace(/^-|-$/g, '')
          .toLowerCase() || 'unknown'
    }
  }

  function selectedReportParam(reportId: string) {
    return reportId ? encodeURIComponent(reportId) : ''
  }

  function graphToElements(graph: KnowledgeGraphResponse): ElementDefinition[] {
    const nodeIds = new Set<string>()
    const elements: ElementDefinition[] = []

    for (const node of graph.nodes ?? []) {
      const data = node.data ?? {}
      const id = stringValue(data.id || data.domainId, '')

      if (!id) continue

      const type = normalizeType(data.type || data.label)
      const domainId = stringValue(data.domainId || data.id, '')
      const name = stringValue(
        data.name || data.title || data.text || domainId || id,
        'Unknown'
      )
      const label = shortLabel(name)
      const findingId = type === 'finding' ? domainId : stringValue(data.findingId, '')
      const reportId = type === 'report' ? domainId : stringValue(data.reportId, '')
      const score = numberValue(data.riskScore ?? data.score, 0)

      nodeIds.add(id)

      elements.push({
        data: {
          ...data,
          id,
          domainId,
          label,
          type,
          name,
          findingId,
          reportId,
          score,
          riskScore: score,
          summary: stringValue(data.description || data.summary || data.text, ''),
          mitigation: stringValue(data.remediation || data.mitigation || data.text, ''),
        },
      })
    }

    const graphEdges = graph.edges ?? []

    for (let index = 0; index < graphEdges.length; index += 1) {
      const edge = graphEdges[index]
      const data = edge.data ?? {}
      const source = stringValue(data.source, '')
      const target = stringValue(data.target, '')

      if (!source || !target) continue
      if (!nodeIds.has(source) || !nodeIds.has(target)) continue

      elements.push({
        data: {
          ...data,
          id: stringValue(data.id, `${source}->${target}:${index}`),
          source,
          target,
          label: stringValue(data.label || data.type, 'related to')
            .replace(/_/g, ' ')
            .toLowerCase(),
          weight: numberValue(data.weight, 1.2),
        },
      })
    }

    return elements
  }

  function calculateStats(elements: ElementDefinition[], attackPaths: AttackPathPrediction[]): GraphStats {
    const nodes = elements.filter((element) => !element.data?.source)
    const edges = elements.filter((element) => Boolean(element.data?.source))

    const countType = (type: string) =>
      nodes.filter((node) => stringValue(node.data?.type) === type).length

    const countPathType = (type: string) =>
      new Set(
        attackPaths.flatMap((path) =>
          (path.path?.nodes ?? [])
            .filter((node) => stringValue(node.type).toLowerCase() === type)
            .map((node) => `${type}:${node.id || node.name}`)
        )
      ).size

    return {
      nodes: nodes.length,
      edges: edges.length,
      findings: Math.max(countType('finding'), countPathType('finding')),
      assets: Math.max(countType('asset'), countPathType('asset')),
      cves: Math.max(countType('cve'), countPathType('cve')),
      mitre: Math.max(countType('mitre'), countPathType('mitretechnique')),
      impacts: Math.max(countType('impact'), countPathType('impact')),
      remediations: Math.max(countType('remediation'), countPathType('remediation')),
      attackPaths: attackPaths.length,
      highSignalPaths: attackPaths.filter((item) => {
        const likelihood = stringValue(item.exploitLikelihood).toLowerCase()
        return likelihood.includes('critical') || likelihood.includes('high')
      }).length,
    }
  }

  function getNodeTypes(elements: ElementDefinition[]) {
    const found = new Set<string>()

    for (const element of elements) {
      if (!element.data?.source) {
        const type = stringValue(element.data?.type, 'unknown')
        found.add(type)
      }
    }

    return Array.from(found).sort((a, b) => {
      const left = TYPE_ORDER.indexOf(a)
      const right = TYPE_ORDER.indexOf(b)
      const leftOrder = left === -1 ? 999 : left
      const rightOrder = right === -1 ? 999 : right

      if (leftOrder !== rightOrder) return leftOrder - rightOrder
      return a.localeCompare(b)
    })
  }

  function buildExplanation(stats: GraphStats, attackPaths: AttackPathPrediction[]) {
    const lines: string[] = []

    if (stats.findings > 0) {
      lines.push(`Graph contains ${stats.findings} finding${stats.findings === 1 ? '' : 's'} linked to the selected report.`)
    }

    if (stats.cves > 0) {
      lines.push(`${stats.cves} CVE node${stats.cves === 1 ? '' : 's'} were connected from extracted finding data.`)
    }

    if (stats.assets > 0) {
      lines.push(`${stats.assets} affected asset${stats.assets === 1 ? '' : 's'} are visible in the graph scope.`)
    }

    if (stats.mitre > 0 || stats.impacts > 0) {
      lines.push(`Enrichment includes ${stats.mitre} MITRE technique node${stats.mitre === 1 ? '' : 's'} and ${stats.impacts} impact node${stats.impacts === 1 ? '' : 's'}.`)
    }

    if (stats.attackPaths > 0) {
      lines.push(`${stats.attackPaths} attack path prediction${stats.attackPaths === 1 ? '' : 's'} were derived from graph relationships.`)
    }

    if (stats.highSignalPaths > 0) {
      lines.push(`${stats.highSignalPaths} path${stats.highSignalPaths === 1 ? '' : 's'} have High/Critical likelihood labels and should be reviewed first.`)
    }

    const topPath = attackPaths[0]
    if (topPath?.predictedOutcome) {
      lines.push(`Top predicted outcome: ${topPath.predictedOutcome}`)
    }

    if (lines.length === 0) {
      lines.push('No graph-derived explanation is available yet. Generate graph data by analyzing a report first.')
    }

    return lines.slice(0, 6)
  }

  function riskTone(value?: string) {
    const normalized = stringValue(value).toLowerCase()

    if (normalized.includes('critical')) return 'border-red-200 bg-red-50 text-red-700'
    if (normalized.includes('high')) return 'border-orange-200 bg-orange-50 text-orange-700'
    if (normalized.includes('medium')) return 'border-yellow-200 bg-yellow-50 text-yellow-700'
    if (normalized.includes('low')) return 'border-emerald-200 bg-emerald-50 text-emerald-700'
    return 'border-slate-200 bg-slate-50 text-slate-700'
  }

  function nodeTypeLabel(type: string) {
    return TYPE_LABELS[type] ?? type
  }

  function applyTypeVisibility(cy: Core, visibleTypes: Record<string, boolean>) {
    cy.batch(() => {
      cy.elements().removeClass('type-hidden')

      for (const [type, isVisible] of Object.entries(visibleTypes)) {
        if (!isVisible) {
          cy.nodes(`[type = "${type}"]`).addClass('type-hidden')
        }
      }

      cy.edges().forEach((edge) => {
        if (edge.source().hasClass('type-hidden') || edge.target().hasClass('type-hidden')) {
          edge.addClass('type-hidden')
        }
      })
    })
  }

  function getCytoscapeStyles(): any[] {
    const base: any[] = [
      {
        selector: 'node',
        style: {
          label: 'data(label)',
          'font-family': 'Inter, system-ui, sans-serif',
          'font-size': '9px',
          'font-weight': 800,
          color: '#173128',
          'text-valign': 'bottom',
          'text-halign': 'center',
          'text-margin-y': 8,
          'text-wrap': 'wrap',
          'text-max-width': '95px',
          'text-outline-color': '#ffffff',
          'text-outline-width': 3,
          width: 42,
          height: 42,
          'background-color': '#64748b',
          'border-width': 2,
          'border-color': '#ffffff',
          'overlay-padding': 7,
          'transition-property': 'opacity border-width width height background-color',
          'transition-duration': 180,
        },
      },
      {
        selector: 'edge',
        style: {
          width: 'mapData(weight, 0.5, 3, 0.8, 2.8)',
          'line-color': '#b7d8c2',
          'target-arrow-color': '#83b895',
          'target-arrow-shape': 'triangle',
          'curve-style': 'bezier',
          'line-opacity': 0.74,
          opacity: 0.82,
          label: '',
          'font-size': '8px',
          color: '#4d6b5b',
          'text-outline-color': '#ffffff',
          'text-outline-width': 3,
          'transition-property': 'opacity line-color width',
          'transition-duration': 180,
        },
      },
      {
        selector: 'edge.highlighted',
        style: {
          label: 'data(label)',
          width: 3,
          'line-color': '#087a3a',
          'target-arrow-color': '#087a3a',
          opacity: 1,
        },
      },
      {
        selector: 'node.highlighted',
        style: {
          'border-width': 4,
          'border-color': '#f59e0b',
          width: 54,
          height: 54,
          opacity: 1,
          'font-size': '10px',
        },
      },
      {
        selector: '.faded',
        style: {
          opacity: 0.13,
        },
      },
      {
        selector: '.type-hidden',
        style: {
          display: 'none',
        },
      },
      {
        selector: 'node:selected',
        style: {
          'border-color': '#f59e0b',
          'border-width': 4,
        },
      },
    ]

    const typedStyles: any[] = Object.entries(TYPE_COLORS).map(([type, color]) => ({
      selector: `node[type = "${type}"]`,
      style: {
        'background-color': color,
        shape:
          type === 'report'
            ? 'round-rectangle'
            : type === 'finding'
              ? 'round-rectangle'
              : type === 'cve' || type === 'cwe' || type === 'hash'
                ? 'hexagon'
                : type === 'mitre'
                  ? 'triangle'
                  : type === 'impact' || type === 'misp'
                    ? 'diamond'
                    : type === 'kev' || type === 'exploit'
                      ? 'star'
                      : type === 'remediation' || type === 'status'
                        ? 'round-tag'
                        : 'ellipse',
        width: type === 'report' ? 86 : type === 'finding' ? 74 : type === 'remediation' ? 64 : 44,
        height: type === 'report' ? 40 : type === 'finding' ? 36 : type === 'remediation' ? 34 : 44,
        'font-size': type === 'report' ? '10px' : type === 'finding' ? '8px' : '9px',
      },
    }))

    return [...base, ...typedStyles]
  }

  export default function AIKnowledgeGraphCenter() {
    const containerRef = useRef<HTMLDivElement>(null)
    const cyRef = useRef<Core | null>(null)

    const [reports, setReports] = useState<ApiReport[]>([])
    const [selectedReportId, setSelectedReportId] = useState('')
    const [depth, setDepth] = useState(DEFAULT_DEPTH)
    const [elements, setElements] = useState<ElementDefinition[]>([])
    const [attackPaths, setAttackPaths] = useState<AttackPathPrediction[]>([])
    const [selectedNode, setSelectedNode] = useState<NodeData | null>(null)
    const [visibleTypes, setVisibleTypes] = useState<Record<string, boolean>>({})
    const [layout, setLayout] = useState('cose')
    const [isLoadingReports, setIsLoadingReports] = useState(true)
    const [isLoadingGraph, setIsLoadingGraph] = useState(false)
    const [error, setError] = useState('')
    const [attackPathError, setAttackPathError] = useState('')

    const selectedReport = useMemo(
      () => reports.find((report) => report.id === selectedReportId) ?? null,
      [reports, selectedReportId]
    )

    const nodeTypes = useMemo(() => getNodeTypes(elements), [elements])

    const stats = useMemo(
      () => calculateStats(elements, attackPaths),
      [elements, attackPaths]
    )

    const explanation = useMemo(
      () => buildExplanation(stats, attackPaths),
      [stats, attackPaths]
    )

    const encodedReportId = selectedReportParam(selectedReportId)

    const applyLayout = useCallback((name: string) => {
      const cy = cyRef.current
      if (!cy) return

      setLayout(name)

      const options: Record<string, unknown> = {
        name,
        animate: true,
        animationDuration: 650,
        padding: 42,
        fit: true,
      }

      if (name === 'cose') {
        Object.assign(options, {
          nodeRepulsion: () => 10500,
          idealEdgeLength: () => 110,
          edgeElasticity: () => 130,
          nestingFactor: 1.15,
          gravity: 0.34,
          numIter: 1500,
          initialTemp: 150,
          coolingFactor: 0.92,
          minTemp: 1,
          componentSpacing: 92,
          nodeDimensionsIncludeLabels: true,
        })
      }

      if (name === 'breadthfirst') {
        const roots = cy.nodes('[type = "report"]')
        Object.assign(options, {
          directed: true,
          spacingFactor: 1.24,
          roots: roots.length > 0 ? roots : undefined,
        })
      }

      if (name === 'concentric') {
        Object.assign(options, {
          minNodeSpacing: 72,
          concentric: (node: NodeSingular) => {
            const type = stringValue(node.data('type'))
            if (type === 'report') return 10
            if (type === 'finding') return 8
            if (type === 'cve' || type === 'cwe' || type === 'kev') return 7
            if (type === 'mitre' || type === 'impact') return 6
            return node.degree()
          },
          levelWidth: () => 2,
        })
      }

      cy.layout(options as any).run()

      window.setTimeout(() => {
        cy.fit(undefined, 42)
        cy.center()
      }, 760)
    }, [])

    const renderGraph = useCallback(
      (nextElements: ElementDefinition[], nextVisibleTypes: Record<string, boolean>) => {
        if (!containerRef.current) return

        cyRef.current?.destroy()

        const cy = cytoscape({
          container: containerRef.current,
          elements: nextElements,
          minZoom: 0.16,
          maxZoom: 3.2,
          wheelSensitivity: 0.18,
          style: getCytoscapeStyles(),
        })

        cyRef.current = cy

        cy.on('tap', 'node', (event) => {
          const node = event.target as NodeSingular
          const data = node.data() as NodeData
          setSelectedNode(data)

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

        applyTypeVisibility(cy, nextVisibleTypes)

        cy.layout({
          name: 'cose',
          animate: false,
          padding: 42,
          nodeRepulsion: () => 10500,
          idealEdgeLength: () => 110,
          edgeElasticity: () => 130,
          nestingFactor: 1.15,
          gravity: 0.34,
          numIter: 1500,
          initialTemp: 150,
          coolingFactor: 0.92,
          minTemp: 1,
          componentSpacing: 92,
          nodeDimensionsIncludeLabels: true,
        } as any).run()

        window.setTimeout(() => {
          cy.fit(undefined, 42)
          cy.center()
        }, 520)
      },
      []
    )

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
        const requestedExists = nextReports.some((report) => report.id === requestedReportId)
        const nextSelected = requestedExists ? requestedReportId : requestedReportId || nextReports[0]?.id || ''

        setReports(nextReports)
        setSelectedReportId(nextSelected)
        if (nextSelected) setReportIdInUrl(nextSelected)
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load reports.')
      } finally {
        setIsLoadingReports(false)
      }
    }, [])

    const loadGraph = useCallback(
      async (reportId: string, nextDepth: number) => {
        if (!reportId) {
          setElements([])
          setAttackPaths([])
          setVisibleTypes({})
          return
        }

        try {
          setIsLoadingGraph(true)
          setError('')
          setAttackPathError('')
          setSelectedNode(null)

          const [graphResponse, pathsResponse] = await Promise.all([
            fetch(
              `/api/knowledge-graph/${encodeURIComponent(reportId)}?depth=${encodeURIComponent(String(nextDepth))}`,
              { cache: 'no-store' }
            ),
            fetch(`/api/attack-paths/${encodeURIComponent(reportId)}?limit=8`, {
              cache: 'no-store',
            }),
          ])

          const graphPayload: KnowledgeGraphResponse = await graphResponse.json().catch(() => ({}))

          if (!graphResponse.ok) {
            throw new Error(
              graphPayload.details || graphPayload.error || `Failed to load graph: ${graphResponse.status}`
            )
          }

          let nextAttackPaths: AttackPathPrediction[] = []
          if (pathsResponse.ok) {
            const pathsPayload: AttackPathsResponse = await pathsResponse.json().catch(() => ({}))
            nextAttackPaths = pathsPayload.paths ?? []
          } else {
            const pathsPayload: AttackPathsResponse = await pathsResponse.json().catch(() => ({}))
            setAttackPathError(
              pathsPayload.details || pathsPayload.error || `Attack paths unavailable: ${pathsResponse.status}`
            )
          }

          const nextElements = graphToElements(graphPayload)
          const nextTypes = getNodeTypes(nextElements)
          const nextVisibleTypes = Object.fromEntries(nextTypes.map((type) => [type, true]))

          setElements(nextElements)
          setAttackPaths(nextAttackPaths)
          setVisibleTypes(nextVisibleTypes)
          setLayout('cose')
          renderGraph(nextElements, nextVisibleTypes)
        } catch (err) {
          setElements([])
          setAttackPaths([])
          setVisibleTypes({})
          cyRef.current?.destroy()
          cyRef.current = null
          setError(err instanceof Error ? err.message : 'Failed to load knowledge graph.')
        } finally {
          setIsLoadingGraph(false)
        }
      },
      [renderGraph]
    )

    useEffect(() => {
      void loadReports()

      return () => {
        cyRef.current?.destroy()
      }
    }, [loadReports])

    useEffect(() => {
      if (!isLoadingReports && selectedReportId) {
        void loadGraph(selectedReportId, depth)
      }
    }, [depth, isLoadingReports, loadGraph, selectedReportId])

    useEffect(() => {
      const cy = cyRef.current
      if (!cy) return
      applyTypeVisibility(cy, visibleTypes)
    }, [visibleTypes])

    function handleReportChange(reportId: string) {
      setSelectedReportId(reportId)
      setReportIdInUrl(reportId)
    }

    function zoomBy(factor: number) {
      const cy = cyRef.current
      if (!cy) return

      cy.zoom({
        level: cy.zoom() * factor,
        renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 },
      })
    }

    function fitGraph() {
      const cy = cyRef.current
      if (!cy) return
      cy.fit(undefined, 42)
      cy.center()
    }

    function openFullscreenGraph() {
      const target = containerRef.current?.parentElement
      if (!target || typeof target.requestFullscreen !== 'function') return

      void target.requestFullscreen()
    }

    const isEmpty = !isLoadingGraph && !error && elements.length === 0

    return (
      <main className="relative min-h-screen overflow-hidden bg-[#fbfefd] text-[#111827]">
        <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_18%_8%,rgba(34,197,94,0.12),transparent_31%),radial-gradient(circle_at_88%_15%,rgba(8,122,58,0.10),transparent_34%),linear-gradient(180deg,#fbfefd,#f6fbf7)]" />
        <div className="pointer-events-none absolute right-[-120px] top-24 h-[480px] w-[600px] rounded-full bg-[#dff7e8]/70 blur-3xl" />
        <div className="pointer-events-none absolute left-[-140px] top-[620px] h-[380px] w-[560px] rounded-full bg-[#edf9f2] blur-3xl" />

        <section className="relative mx-auto max-w-[1920px] px-4 pb-6 pt-4 lg:px-6">
          <header className="relative overflow-hidden rounded-[28px] border border-[#dceee3] bg-white/92 p-4 shadow-[0_18px_55px_rgba(15,43,29,0.06)] backdrop-blur">
            <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(135deg,rgba(8,122,58,0.06),transparent_48%),radial-gradient(circle_at_86%_24%,rgba(22,163,74,0.12),transparent_28%)]" />
            <div className="pointer-events-none absolute right-12 top-5 hidden h-20 w-20 rounded-full bg-gradient-to-br from-[#eafff0] via-[#8ee8aa] to-[#087a3a] shadow-[0_20px_50px_rgba(8,122,58,0.16)] graph-ai-core lg:block" />
            <div className="pointer-events-none absolute bottom-4 right-[120px] hidden h-12 w-48 rounded-[50%] border border-[#bfe6cc] bg-gradient-to-b from-white to-[#e5f8ec] shadow-[0_18px_45px_rgba(8,122,58,0.10)] graph-platform lg:block" />

            <div className="relative grid gap-4 xl:grid-cols-[1fr_460px]">
              <div>
                <p className="text-xs font-semibold uppercase tracking-[0.22em] text-[#087a3a]">
                  AI Knowledge Graph Center
                </p>
                <h1 className="mt-2 max-w-4xl text-3xl font-semibold tracking-[-0.04em] text-[#111827] md:text-4xl">
                  Report-to-risk relationship map
                </h1>
                <p className="mt-3 max-w-4xl text-sm leading-7 text-[#5f6f66]">
                  Visualize only real graph data returned from the secured knowledge graph API: reports, findings, assets, CVEs, weaknesses, MITRE techniques, impact, remediation, and attack-path evidence.
                </p>

                <div className="mt-4 flex flex-wrap gap-2">
                  <ActionLink href="/dashboard">Dashboard</ActionLink>
                  <ActionLink href="/reports">Reports</ActionLink>
                  {encodedReportId ? (
                    <>
                      <ActionLink href={`/reports/${encodedReportId}`}>Open Report</ActionLink>
                      <ActionLink href={`/results?reportId=${encodedReportId}`}>View Findings</ActionLink>
                      <ActionLink href={`/risk-scoring?reportId=${encodedReportId}`}>Risk Scoring</ActionLink>
                      <ActionLink href={`/attack-paths?reportId=${encodedReportId}`}>Attack Paths</ActionLink>
                      <ActionLink href={`/recommendations?reportId=${encodedReportId}`}>Recommendations</ActionLink>
                      <ActionLink href={`/export?reportId=${encodedReportId}`} primary>
                        Export
                      </ActionLink>
                    </>
                  ) : null}
                </div>
              </div>

              <div className="rounded-[24px] border border-[#dceee3] bg-white/80 p-4 shadow-[0_16px_45px_rgba(15,43,29,0.06)] backdrop-blur">
                <div className="grid gap-3">
                  <label className="text-xs font-semibold uppercase tracking-[0.16em] text-[#5a7668]">
                    Report scope
                  </label>
                  <select
                    value={selectedReportId}
                    onChange={(event) => handleReportChange(event.target.value)}
                    disabled={isLoadingReports || reports.length === 0}
                    className="h-12 rounded-2xl border border-[#c4e3cf] bg-[#f6fff9] px-4 text-sm font-semibold text-[#173128] outline-none focus:border-[#087a3a] disabled:cursor-not-allowed disabled:opacity-60"
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

                  <div className="grid gap-3 sm:grid-cols-[1fr_150px]">
                    <div>
                      <label className="text-xs font-semibold uppercase tracking-[0.16em] text-[#5a7668]">
                        Graph depth: {depth}
                      </label>
                      <input
                        type="range"
                        min={1}
                        max={MAX_DEPTH}
                        value={depth}
                        onChange={(event) => setDepth(Number(event.target.value))}
                        className="mt-3 w-full accent-[#087a3a]"
                      />
                    </div>

                    <button
                      type="button"
                      onClick={() => void loadGraph(selectedReportId, depth)}
                      disabled={!selectedReportId || isLoadingGraph}
                      className="h-12 self-end rounded-2xl bg-[#087a3a] px-5 text-sm font-semibold text-white transition hover:bg-[#066b33] disabled:cursor-not-allowed disabled:opacity-60"
                    >
                      {isLoadingGraph ? 'Loading…' : 'Refresh Graph'}
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </header>

          {selectedReport ? (
            <section className="mt-4 rounded-[24px] border border-[#dceee3] bg-white/92 p-4 shadow-[0_16px_45px_rgba(15,43,29,0.045)]">
              <div className="flex flex-wrap items-center gap-3">
                <Pill>{selectedReport.id}</Pill>
                <Pill>{selectedReport.type ?? 'Report'}</Pill>
                <Pill>{selectedReport.status ?? 'Ready'}</Pill>
                {selectedReport.findings !== undefined ? <Pill>{selectedReport.findings} findings</Pill> : null}
              </div>
              <h2 className="mt-3 text-xl font-semibold text-[#0d2217]">{selectedReport.name}</h2>
              {selectedReport.summary ? (
                <p className="mt-2 max-w-6xl text-sm leading-7 text-[#5a7668]">{selectedReport.summary}</p>
              ) : null}
            </section>
          ) : null}

          <section className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-5">
            <MetricCard label="Graph nodes" value={String(stats.nodes)} helper={`${stats.edges} edges`} />
            <MetricCard label="Findings" value={String(stats.findings)} helper={`${stats.assets} assets`} />
            <MetricCard label="CVEs" value={String(stats.cves)} helper="Report-linked CVE nodes" />
            <MetricCard label="MITRE / Impact" value={`${stats.mitre}/${stats.impacts}`} helper="Enrichment coverage" />
            <MetricCard label="Attack paths" value={String(stats.attackPaths)} helper={`${stats.highSignalPaths} high-signal`} />
          </section>

          <section className="mt-4 grid gap-4 xl:grid-cols-[minmax(0,1fr)_390px]">
            <div className="overflow-hidden rounded-[28px] border border-[#dceee3] bg-white/96 shadow-[0_22px_70px_rgba(15,43,29,0.07)]">
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#e4f2e9] bg-[#f8fffa] px-4 py-3">
                <div>
                  <p className="text-xs font-semibold uppercase tracking-[0.18em] text-[#087a3a]">
                    Live graph canvas
                  </p>
                  <p className="mt-1 text-sm text-[#5a7668]">
                    Click any node to inspect real properties and graph relationships.
                  </p>
                </div>

                <div className="flex flex-wrap gap-2">
                  {['cose', 'breadthfirst', 'concentric', 'circle', 'grid'].map((item) => (
                    <button
                      key={item}
                      type="button"
                      onClick={() => applyLayout(item)}
                      className={`rounded-xl px-3 py-1.5 text-xs font-semibold capitalize transition ${
                        layout === item
                          ? 'bg-[#087a3a] text-white'
                          : 'border border-[#c4e3cf] bg-white text-[#173128] hover:bg-[#edfdf3]'
                      }`}
                    >
                      {item}
                    </button>
                  ))}
                  <button
                    type="button"
                    onClick={() => zoomBy(1.2)}
                    className="rounded-xl border border-[#c4e3cf] bg-white px-3 py-1.5 text-xs font-semibold text-[#173128] hover:bg-[#edfdf3]"
                  >
                    Zoom +
                  </button>
                  <button
                    type="button"
                    onClick={fitGraph}
                    className="rounded-xl border border-[#c4e3cf] bg-white px-3 py-1.5 text-xs font-semibold text-[#173128] hover:bg-[#edfdf3]"
                  >
                    Fit
                  </button>
                  <button
                    type="button"
                    onClick={openFullscreenGraph}
                    className="rounded-xl border border-[#c4e3cf] bg-white px-3 py-1.5 text-xs font-semibold text-[#173128] hover:bg-[#edfdf3]"
                  >
                    Fullscreen
                  </button>
                  <button
                    type="button"
                    onClick={() => zoomBy(0.82)}
                    className="rounded-xl border border-[#c4e3cf] bg-white px-3 py-1.5 text-xs font-semibold text-[#173128] hover:bg-[#edfdf3]"
                  >
                    Zoom -
                  </button>
                </div>
              </div>

              <div className="relative h-[calc(100vh-330px)] min-h-[620px] bg-[#fbfffc]">
                {isLoadingGraph ? (
                  <div className="absolute inset-0 z-10 grid place-items-center bg-white/80 backdrop-blur-sm">
                    <div className="text-center">
                      <div className="mx-auto grid h-20 w-20 place-items-center rounded-full border border-[#c4e3cf] bg-[#f6fff9] shadow-[0_18px_55px_rgba(8,122,58,0.12)]">
                        <div className="h-10 w-10 animate-spin rounded-full border-4 border-[#087a3a] border-t-transparent" />
                      </div>
                      <p className="mt-4 text-sm font-semibold text-[#087a3a]">Building real knowledge graph…</p>
                      <p className="mt-1 text-xs text-[#5a7668]">Fetching secured report-scoped nodes and relationships.</p>
                    </div>
                  </div>
                ) : null}

                {error ? (
                  <div className="absolute inset-0 z-20 grid place-items-center bg-white">
                    <div className="max-w-lg rounded-[28px] border border-red-200 bg-red-50 p-7 text-center">
                      <p className="text-lg font-semibold text-red-700">Graph error</p>
                      <p className="mt-2 text-sm leading-6 text-red-600">{error}</p>
                    </div>
                  </div>
                ) : null}

                {isEmpty ? (
                  <div className="absolute inset-0 z-10 grid place-items-center bg-white">
                    <div className="max-w-xl rounded-[30px] border border-dashed border-[#c4e3cf] bg-[#f8fffa] p-8 text-center">
                      <p className="text-xl font-semibold text-[#0d2217]">No real graph data yet</p>
                      <p className="mt-3 text-sm leading-7 text-[#5a7668]">
                        The secured Neo4j query returned no nodes for this report. Analyze or re-analyze the report so the user-scoped graph builder can persist report, finding, asset, CVE, and enrichment nodes.
                      </p>
                      <div className="mt-5 flex flex-wrap justify-center gap-3">
                        <ActionLink href="/analyzer" primary>Analyze Report</ActionLink>
                        {encodedReportId ? <ActionLink href={`/reports/${encodedReportId}`}>Open Report</ActionLink> : null}
                      </div>
                    </div>
                  </div>
                ) : null}

                <div ref={containerRef} className="h-full w-full" />
              </div>
            </div>

            <aside className="max-h-[calc(100vh-170px)] space-y-4 overflow-y-auto pr-1 xl:sticky xl:top-24">
              <Panel title="Selected node">
                {selectedNode ? (
                  <div className="space-y-3">
                    <InfoLine label="Label" value={selectedNode.label} />
                    <InfoLine label="Type" value={nodeTypeLabel(selectedNode.type)} />
                    {selectedNode.domainId ? <InfoLine label="ID" value={selectedNode.domainId} /> : null}
                    {selectedNode.severity ? <InfoLine label="Severity" value={selectedNode.severity} /> : null}
                    {selectedNode.score ? <InfoLine label="Score" value={`${selectedNode.score}/100`} /> : null}
                    {selectedNode.cve ? <InfoLine label="CVE" value={selectedNode.cve} /> : null}
                    {selectedNode.summary ? <TextBlock label="Summary" value={selectedNode.summary} /> : null}
                    {selectedNode.mitigation ? <TextBlock label="Mitigation" value={selectedNode.mitigation} /> : null}
                    {selectedNode.text ? <TextBlock label="Text" value={selectedNode.text} /> : null}

                    <div className="grid gap-2 pt-1">
                      {(selectedNode.reportId || selectedReportId) ? (
                        <>
                          <ActionLink href={`/reports/${encodeURIComponent(stringValue(selectedNode.reportId, selectedReportId))}`}>Open Report</ActionLink>
                          <ActionLink href={`/results?reportId=${encodeURIComponent(stringValue(selectedNode.reportId, selectedReportId))}`}>Report Findings</ActionLink>
                          <ActionLink href={`/risk-scoring?reportId=${encodeURIComponent(stringValue(selectedNode.reportId, selectedReportId))}`}>Risk Scoring</ActionLink>
                        </>
                      ) : null}
                      {selectedNode.findingId ? (
                        <ActionLink href={`/results/${encodeURIComponent(selectedNode.findingId)}`}>Open Finding</ActionLink>
                      ) : null}
                    </div>
                  </div>
                ) : (
                  <p className="text-sm leading-7 text-[#5a7668]">
                    Click a node to highlight its neighborhood and inspect report-scoped properties.
                  </p>
                )}
              </Panel>

              <Panel title="Attack path preview">
                {attackPathError ? (
                  <p className="rounded-2xl border border-yellow-200 bg-yellow-50 p-3 text-xs leading-5 text-yellow-700">
                    {attackPathError}
                  </p>
                ) : null}

                {attackPaths.length === 0 ? (
                  <p className="text-sm leading-7 text-[#5a7668]">
                    No attack path predictions returned for this report.
                  </p>
                ) : (
                  <div className="space-y-3">
                    {attackPaths.slice(0, 4).map((path) => (
                      <article key={path.findingId} className="rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] p-4">
                        <div className="flex items-start justify-between gap-3">
                          <h3 className="text-sm font-semibold leading-6 text-[#0d2217]">{path.findingTitle}</h3>
                          <span className={`shrink-0 rounded-full border px-2.5 py-1 text-[10px] font-bold ${riskTone(path.exploitLikelihood)}`}>
                            {path.exploitLikelihood ?? 'Unknown'}
                          </span>
                        </div>
                        <div className="mt-3 grid grid-cols-3 gap-2">
                          <MiniBox label="Risk" value={String(path.riskScore ?? 0)} />
                          <MiniBox label="Path" value={String(path.attackPathScore ?? 0)} />
                          <MiniBox label="Conf." value={`${path.confidence ?? 0}%`} />
                        </div>
                        {path.predictedOutcome ? (
                          <p className="mt-3 text-xs leading-5 text-[#5a7668]">{path.predictedOutcome}</p>
                        ) : null}
                      </article>
                    ))}
                    {encodedReportId ? (
                      <ActionLink href={`/attack-paths?reportId=${encodedReportId}`} primary>
                        Open Attack Paths
                      </ActionLink>
                    ) : null}
                  </div>
                )}
              </Panel>
              <Panel title="AI graph explanation">
                <div className="space-y-3">
                  {explanation.map((line, index) => (
                    <p
                      key={`${line}-${index}`}
                      className="rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] p-4 text-sm leading-7 text-[#173128]"
                    >
                      {line}
                    </p>
                  ))}
                </div>
              </Panel>

              <Panel title="Node filters">
                {nodeTypes.length === 0 ? (
                  <p className="text-sm leading-6 text-[#5a7668]">No node types loaded yet.</p>
                ) : (
                  <div className="grid gap-2">
                    <button
                      type="button"
                      onClick={() => setVisibleTypes(Object.fromEntries(nodeTypes.map((type) => [type, true])))}
                      className="mb-1 rounded-2xl border border-[#c4e3cf] bg-white px-3 py-2 text-xs font-semibold text-[#173128] hover:bg-[#edfdf3]"
                    >
                      Reset filters
                    </button>
                    {nodeTypes.map((type) => (
                      <button
                        key={type}
                        type="button"
                        onClick={() =>
                          setVisibleTypes((current) => ({
                            ...current,
                            [type]: !current[type],
                          }))
                        }
                        className={`flex items-center justify-between rounded-2xl border px-3 py-2 text-xs font-semibold transition ${
                          visibleTypes[type]
                            ? 'border-[#bbf7d0] bg-[#f0fdf4] text-[#087a3a]'
                            : 'border-[#e4f2e9] bg-[#f8fffa] text-[#6b8477]'
                        }`}
                      >
                        <span className="flex items-center gap-2">
                          <span
                            className="h-2.5 w-2.5 rounded-full"
                            style={{ backgroundColor: TYPE_COLORS[type] ?? TYPE_COLORS.unknown }}
                          />
                          {nodeTypeLabel(type)}
                        </span>
                        <span>{visibleTypes[type] ? 'On' : 'Off'}</span>
                      </button>
                    ))}
                  </div>
                )}
              </Panel>


            </aside>
          </section>
        </section>

        <style>{`
          @keyframes graph-core-float {
            0%, 100% { transform: translateY(0) rotate(0deg); }
            50% { transform: translateY(-12px) rotate(3deg); }
          }

          @keyframes graph-core-pulse {
            0%, 100% { box-shadow: 0 30px 70px rgba(8,122,58,0.18), inset 0 0 24px rgba(255,255,255,0.8); }
            50% { box-shadow: 0 34px 90px rgba(8,122,58,0.28), inset 0 0 34px rgba(255,255,255,0.95); }
          }

          .graph-ai-core {
            animation: graph-core-float 6.4s ease-in-out infinite, graph-core-pulse 4.8s ease-in-out infinite;
          }

          .graph-platform {
            transform: perspective(860px) rotateX(58deg);
          }

          @media (prefers-reduced-motion: reduce) {
            .graph-ai-core { animation: none; }
          }
        `}</style>
      </main>
    )
  }

  function ActionLink({ href, children, primary }: { href: string; children: ReactNode; primary?: boolean }) {
    return (
      <Link
        href={href}
        className={
          primary
            ? 'inline-flex items-center justify-center rounded-xl bg-[#087a3a] px-3 py-2 text-xs font-semibold text-white shadow-[0_12px_24px_rgba(8,122,58,0.16)] transition hover:-translate-y-0.5 hover:bg-[#066b33]'
            : 'inline-flex items-center justify-center rounded-xl border border-[#c4e3cf] bg-white px-3 py-2 text-xs font-semibold text-[#173128] transition hover:-translate-y-0.5 hover:bg-[#f4fff7]'
        }
      >
        {children}
      </Link>
    )
  }

  function Pill({ children }: { children: ReactNode }) {
    return (
      <span className="rounded-full border border-[#c4e3cf] bg-[#f6fff9] px-3 py-1 text-xs font-semibold text-[#173128]">
        {children}
      </span>
    )
  }

  function MetricCard({ label, value, helper }: { label: string; value: string; helper: string }) {
    return (
      <div className="rounded-[22px] border border-[#dceee3] bg-white p-4 shadow-[0_16px_45px_rgba(15,43,29,0.045)] transition hover:-translate-y-0.5 hover:shadow-[0_24px_65px_rgba(15,43,29,0.08)]">
        <p className="text-sm font-medium text-[#5a7668]">{label}</p>
        <p className="mt-2 text-2xl font-semibold tracking-tight text-[#0d2217]">{value}</p>
        <p className="mt-1 text-xs leading-5 text-[#5a7668]">{helper}</p>
      </div>
    )
  }

  function Panel({ title, children }: { title: string; children: ReactNode }) {
    return (
      <section className="rounded-[24px] border border-[#dceee3] bg-white/95 p-4 shadow-[0_16px_45px_rgba(15,43,29,0.055)] backdrop-blur">
        <h2 className="mb-3 text-base font-semibold text-[#0d2217]">{title}</h2>
        {children}
      </section>
    )
  }

  function InfoLine({ label, value }: { label: string; value: string | number }) {
    return (
      <div className="rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] p-3">
        <p className="text-[10px] font-semibold uppercase tracking-wide text-[#5a7668]">{label}</p>
        <p className="mt-1 break-words text-sm font-semibold text-[#173128]">{value}</p>
      </div>
    )
  }

  function TextBlock({ label, value }: { label: string; value: string }) {
    return (
      <div className="rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] p-3">
        <p className="text-[10px] font-semibold uppercase tracking-wide text-[#5a7668]">{label}</p>
        <p className="mt-1 break-words text-xs leading-5 text-[#173128]">{value}</p>
      </div>
    )
  }

  function MiniBox({ label, value }: { label: string; value: string }) {
    return (
      <div className="rounded-xl border border-[#e4f2e9] bg-white px-3 py-2">
        <p className="text-[9px] font-semibold uppercase tracking-wide text-[#5a7668]">{label}</p>
        <p className="mt-1 text-sm font-bold text-[#173128]">{value}</p>
      </div>
    )
  }
