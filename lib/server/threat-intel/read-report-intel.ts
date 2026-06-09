import { runCypher } from '@/lib/server/knowledge-graph/neo4j'
import type { ThreatIntelSourceStatus } from './source-status'

function props(node: any) {
  return node?.properties ?? null
}

function toPlainNumber(value: any) {
  if (value && typeof value.toNumber === 'function') return value.toNumber()

  const parsed = Number(value)
  return Number.isFinite(parsed) ? parsed : null
}

function normalizeCves(values: string[] = []) {
  return Array.from(
    new Set(
      values
        .map((value) => String(value ?? '').trim().toUpperCase())
        .filter((value) => /^CVE-\d{4}-\d{4,}$/i.test(value))
    )
  ).sort()
}

type ReadOptions = {
  userId?: string
  fallbackCves?: string[]
}

export async function getReportThreatIntel(reportId: string, options: ReadOptions = {}) {
  const records = await runCypher(
    options.userId
      ? `
        MATCH (:Report {id: $reportId, userId: $userId})-[:CONTAINS]->(:Finding)-[:HAS_CVE]->(c:CVE)

        OPTIONAL MATCH (c)-[:HAS_CVSS]->(cvss:CVSS)
        OPTIONAL MATCH (c)-[:DESCRIBED_BY]->(advisory:Advisory)
        OPTIONAL MATCH (c)-[:KNOWN_EXPLOITED]->(kev:KnownExploitedVulnerability)
        OPTIONAL MATCH (c)-[:HAS_REFERENCE]->(ref:Reference)
        OPTIONAL MATCH (c)-[:HAS_MISP_INTEL]->(misp:MISPAttribute)

        RETURN
          c AS cve,
          cvss AS cvss,
          advisory AS advisory,
          kev AS kev,
          collect(DISTINCT ref) AS references,
          collect(DISTINCT misp) AS mispItems

        ORDER BY c.id
        `
      : `
        MATCH (:Report {id: $reportId})-[:CONTAINS]->(:Finding)-[:HAS_CVE]->(c:CVE)

        OPTIONAL MATCH (c)-[:HAS_CVSS]->(cvss:CVSS)
        OPTIONAL MATCH (c)-[:DESCRIBED_BY]->(advisory:Advisory)
        OPTIONAL MATCH (c)-[:KNOWN_EXPLOITED]->(kev:KnownExploitedVulnerability)
        OPTIONAL MATCH (c)-[:HAS_REFERENCE]->(ref:Reference)
        OPTIONAL MATCH (c)-[:HAS_MISP_INTEL]->(misp:MISPAttribute)

        RETURN
          c AS cve,
          cvss AS cvss,
          advisory AS advisory,
          kev AS kev,
          collect(DISTINCT ref) AS references,
          collect(DISTINCT misp) AS mispItems

        ORDER BY c.id
        `,
    options.userId ? { reportId, userId: options.userId } : { reportId }
  )

  const sourceStatuses: ThreatIntelSourceStatus[] = []
  const warnings: string[] = []
  const notes: string[] = []

  let cves = records.map((record) => {
    const cve = props(record.get('cve')) ?? {}
    const cvss = props(record.get('cvss'))
    const advisory = props(record.get('advisory'))
    const kev = props(record.get('kev'))

    const references = (record.get('references') ?? [])
      .map(props)
      .filter(Boolean)
      .map((item: any) => item.url ?? item.id)
      .filter(Boolean)

    const mispItems = (record.get('mispItems') ?? [])
      .map(props)
      .filter(Boolean)
      .map((item: any) => ({
        value: item.value,
        category: item.category,
        type: item.type,
        eventId: item.eventId,
        eventInfo: item.eventInfo,
        tags: item.tags ?? [],
      }))

    const cvssScore =
      cvss?.score !== undefined
        ? toPlainNumber(cvss.score)
        : toPlainNumber(cve.cvssScore)

    const cveId = String(cve.id ?? '')
    const hasNvd = Boolean(cve.nvdDescription || cve.cvssScore || advisory)
    const hasKev = Boolean(cve.knownExploited || kev)

    return {
      cveId,
      description: cve.nvdDescription ?? '',
      nvd: hasNvd,
      cisaKev: hasKev,
      cvssScore,
      cvssSeverity: cvss?.severity ?? cve.cvssSeverity ?? null,
      cvssVector: cvss?.vector ?? cve.cvssVector ?? null,
      knownExploited: hasKev,
      advisory,
      kev,
      references,
      misp: {
        enabled: null,
        matches: mispItems.length,
        note: mispItems.length > 0 ? null : 'No MISP attributes are linked to this CVE in the graph.',
      },
      mispItems,
      sourceStatuses: [
        {
          source: 'NVD' as const,
          status: hasNvd ? ('ok' as const) : ('not_found' as const),
          cveId,
          message: hasNvd
            ? 'NVD enrichment is present in the graph.'
            : 'No NVD enrichment is present in the graph for this CVE.',
        },
        {
          source: 'CISA_KEV' as const,
          status: hasKev ? ('ok' as const) : ('not_found' as const),
          cveId,
          message: hasKev
            ? 'CISA KEV enrichment is present in the graph.'
            : 'No CISA KEV enrichment is present in the graph for this CVE.',
        },
      ],
    }
  })

  if (cves.length === 0) {
    const fallbackCves = normalizeCves(options.fallbackCves ?? [])

    if (fallbackCves.length > 0) {
      const message = 'No report-scoped CVE nodes were found in Neo4j; returning CVEs extracted from the owned report record without fabricated enrichment.'
      warnings.push(message)
      sourceStatuses.push({
        source: 'GRAPH',
        status: 'not_found',
        message,
      })

      cves = fallbackCves.map((cveId) => ({
        cveId,
        description: '',
        nvd: false,
        cisaKev: false,
        cvssScore: null,
        cvssSeverity: null,
        cvssVector: null,
        knownExploited: false,
        advisory: null,
        kev: null,
        references: [],
        misp: {
          enabled: null,
          matches: 0,
          note: 'No MISP enrichment is linked because no graph CVE node was found.',
        },
        mispItems: [],
        sourceStatuses: [
          {
            source: 'NVD' as const,
            status: 'not_found' as const,
            cveId,
            message: 'No NVD enrichment was found in the graph. Run threat-intel enrichment to query NVD.',
          },
          {
            source: 'CISA_KEV' as const,
            status: 'not_found' as const,
            cveId,
            message: 'No CISA KEV enrichment was found in the graph. Run threat-intel enrichment to query CISA KEV.',
          },
        ],
      }))
    } else {
      notes.push('No CVEs were found in the report graph or owned report record.')
    }
  }

  for (const cve of cves) {
    sourceStatuses.push(...(cve.sourceStatuses ?? []))
  }

  return {
    reportId,
    cveCount: cves.length,
    cves,
    sourceStatuses,
    warnings,
    notes,
  }
}
