import { runCypher } from '@/lib/server/knowledge-graph/neo4j'

function props(node: any) {
  return node?.properties ?? null
}

function toPlainNumber(value: any) {
  if (value && typeof value.toNumber === 'function') return value.toNumber()

  const parsed = Number(value)
  return Number.isFinite(parsed) ? parsed : null
}

export async function getReportThreatIntel(reportId: string) {
  const records = await runCypher(
    `
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
    { reportId }
  )

  const cves = records.map((record) => {
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

    return {
      cveId: String(cve.id ?? ''),
      description: cve.nvdDescription ?? '',
      cvssScore:
        cvss?.score !== undefined
          ? toPlainNumber(cvss.score)
          : toPlainNumber(cve.cvssScore),
      cvssSeverity: cvss?.severity ?? cve.cvssSeverity ?? null,
      cvssVector: cvss?.vector ?? cve.cvssVector ?? null,
      knownExploited: Boolean(cve.knownExploited || kev),
      advisory,
      kev,
      references,
      mispItems,
    }
  })

  return {
    reportId,
    cveCount: cves.length,
    cves,
  }
}