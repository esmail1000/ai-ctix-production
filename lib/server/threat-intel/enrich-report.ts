import { runCypher } from '@/lib/server/knowledge-graph/neo4j'
import { findCisaKev } from './cisa-kev'
import { searchMispByCveDetailed } from './misp'
import { fetchNvdCve } from './nvd'
import type { ThreatIntelSourceStatus } from './source-status'
import { sourceErrorToStatus } from './source-status'

function unique(values: string[]) {
  return Array.from(new Set(values.filter(Boolean)))
}

function normalizeCves(values: string[] = []) {
  return unique(
    values
      .map((value) => String(value ?? '').trim().toUpperCase())
      .filter((value) => /^CVE-\d{4}-\d{4,}$/i.test(value))
  ).sort()
}

async function getReportCves(reportId: string, userId?: string) {
  const records = await runCypher(
    userId
      ? `
        MATCH (:Report {id: $reportId, userId: $userId})-[:CONTAINS]->(:Finding)-[:HAS_CVE]->(c:CVE)
        RETURN DISTINCT c.id AS cveId
        ORDER BY cveId
        `
      : `
        MATCH (:Report {id: $reportId})-[:CONTAINS]->(:Finding)-[:HAS_CVE]->(c:CVE)
        RETURN DISTINCT c.id AS cveId
        ORDER BY cveId
        `,
    userId ? { reportId, userId } : { reportId }
  )

  return normalizeCves(records.map((record) => String(record.get('cveId'))))
}

async function storeNvdIntel(cveId: string, intel: Awaited<ReturnType<typeof fetchNvdCve>>) {
  if (!intel) return

  await runCypher(
    `
    MERGE (c:CVE {id: $cveId})
    SET c.nvdDescription = $description,
        c.nvdPublished = $published,
        c.nvdLastModified = $lastModified,
        c.cvssScore = $cvssScore,
        c.cvssSeverity = $cvssSeverity,
        c.cvssVector = $cvssVector,
        c.enrichedAt = datetime()

    MERGE (a:Advisory {id: $advisoryId})
    SET a.source = "NVD",
        a.title = $title,
        a.description = $description,
        a.published = $published,
        a.lastModified = $lastModified

    MERGE (c)-[:DESCRIBED_BY]->(a)

    FOREACH (_ IN CASE WHEN $cvssScore IS NULL THEN [] ELSE [1] END |
      MERGE (s:CVSS {id: $cvssId})
      SET s.score = $cvssScore,
          s.severity = $cvssSeverity,
          s.vector = $cvssVector
      MERGE (c)-[:HAS_CVSS]->(s)
    )
    `,
    {
      cveId,
      advisoryId: `NVD:${cveId}`,
      title: `NVD advisory for ${cveId}`,
      description: intel.description ?? '',
      published: intel.published ?? null,
      lastModified: intel.lastModified ?? null,
      cvssScore: typeof intel.cvssScore === 'number' ? intel.cvssScore : null,
      cvssSeverity: intel.cvssSeverity ?? null,
      cvssVector: intel.cvssVector ?? null,
      cvssId: `CVSS:${cveId}`,
    }
  )

  for (const ref of unique(intel.references ?? []).slice(0, 10)) {
    await runCypher(
      `
      MATCH (c:CVE {id: $cveId})
      MERGE (r:Reference {id: $ref})
      SET r.url = $ref
      MERGE (c)-[:HAS_REFERENCE]->(r)
      `,
      { cveId, ref }
    )
  }
}

async function storeKevIntel(cveId: string, kev: Awaited<ReturnType<typeof findCisaKev>>) {
  if (!kev) return

  await runCypher(
    `
    MERGE (c:CVE {id: $cveId})
    SET c.knownExploited = true,
        c.kevDateAdded = $dateAdded,
        c.kevDueDate = $dueDate,
        c.kevRansomwareUse = $knownRansomwareCampaignUse

    MERGE (k:KnownExploitedVulnerability {id: $kevId})
    SET k.source = "CISA_KEV",
        k.vendorProject = $vendorProject,
        k.product = $product,
        k.vulnerabilityName = $vulnerabilityName,
        k.dateAdded = $dateAdded,
        k.dueDate = $dueDate,
        k.requiredAction = $requiredAction,
        k.knownRansomwareCampaignUse = $knownRansomwareCampaignUse,
        k.notes = $notes

    MERGE (c)-[:KNOWN_EXPLOITED]->(k)
    `,
    {
      cveId,
      kevId: `CISA_KEV:${cveId}`,
      vendorProject: kev.vendorProject ?? '',
      product: kev.product ?? '',
      vulnerabilityName: kev.vulnerabilityName ?? '',
      dateAdded: kev.dateAdded ?? null,
      dueDate: kev.dueDate ?? null,
      requiredAction: kev.requiredAction ?? '',
      knownRansomwareCampaignUse: kev.knownRansomwareCampaignUse ?? '',
      notes: kev.notes ?? '',
    }
  )
}

async function storeMispIntel(cveId: string, mispItems: Awaited<ReturnType<typeof searchMispByCveDetailed>>['matches']) {
  for (let index = 0; index < mispItems.length; index += 1) {
    const item = mispItems[index]

    await runCypher(
      `
      MERGE (c:CVE {id: $cveId})

      MERGE (m:MISPAttribute {id: $mispId})
      SET m.source = "MISP",
          m.value = $value,
          m.category = $category,
          m.type = $type,
          m.eventId = $eventId,
          m.eventInfo = $eventInfo,
          m.tags = $tags

      MERGE (c)-[:HAS_MISP_INTEL]->(m)
      `,
      {
        cveId,
        mispId: `MISP:${cveId}:${item.eventId ?? index}`,
        value: item.value,
        category: item.category ?? '',
        type: item.type ?? '',
        eventId: item.eventId ?? '',
        eventInfo: item.eventInfo ?? '',
        tags: item.tags ?? [],
      }
    )
  }
}

type EnrichOptions = {
  userId?: string
  fallbackCves?: string[]
}

export async function enrichReportThreatIntel(reportId: string, options: EnrichOptions = {}) {
  const graphCves = await getReportCves(reportId, options.userId)
  const fallbackCves = normalizeCves(options.fallbackCves ?? [])
  const cves = graphCves.length > 0 ? graphCves : fallbackCves
  const results = []
  const errors: Array<{ cveId: string; source: string; error: string }> = []
  const sourceStatuses: ThreatIntelSourceStatus[] = []
  const notes: string[] = []

  if (graphCves.length === 0 && fallbackCves.length > 0) {
    const message = 'No report-scoped CVE nodes were found in Neo4j; using CVEs extracted from the owned report record for read-only threat-intel lookup.'
    notes.push(message)
    sourceStatuses.push({
      source: 'GRAPH',
      status: 'not_found',
      message,
    })
  }

  if (cves.length === 0) {
    notes.push('No CVEs were found in the report graph or owned report record; threat intelligence enrichment was not attempted.')
  }

  for (const cveId of cves) {
    let nvd: Awaited<ReturnType<typeof fetchNvdCve>> | null = null
    let kev: Awaited<ReturnType<typeof findCisaKev>> | null = null
    let mispMatches: Awaited<ReturnType<typeof searchMispByCveDetailed>>['matches'] = []
    let mispEnabled = false
    let mispNote: string | undefined
    const cveSourceStatuses: ThreatIntelSourceStatus[] = []

    try {
      nvd = await fetchNvdCve(cveId)
      await storeNvdIntel(cveId, nvd)
      cveSourceStatuses.push({
        source: 'NVD',
        status: nvd ? 'ok' : 'not_found',
        cveId,
        message: nvd ? 'NVD returned a CVE record.' : 'NVD returned no CVE record for this identifier.',
      })
    } catch (error) {
      const status = sourceErrorToStatus('NVD', cveId, error)
      cveSourceStatuses.push(status)
      errors.push({
        cveId,
        source: 'NVD',
        error: status.error ?? status.message ?? 'NVD lookup failed.',
      })
    }

    try {
      kev = await findCisaKev(cveId)
      await storeKevIntel(cveId, kev)
      cveSourceStatuses.push({
        source: 'CISA_KEV',
        status: kev ? 'ok' : 'not_found',
        cveId,
        message: kev ? 'CISA KEV listed this CVE as known exploited.' : 'CISA KEV did not list this CVE.',
      })
    } catch (error) {
      const status = sourceErrorToStatus('CISA_KEV', cveId, error)
      cveSourceStatuses.push(status)
      errors.push({
        cveId,
        source: 'CISA_KEV',
        error: status.error ?? status.message ?? 'CISA KEV lookup failed.',
      })
    }

    try {
      const misp = await searchMispByCveDetailed(cveId)
      mispMatches = misp.matches
      mispEnabled = misp.enabled
      mispNote = misp.note
      cveSourceStatuses.push(misp.sourceStatus)
      await storeMispIntel(cveId, mispMatches)
    } catch (error) {
      const status = sourceErrorToStatus('MISP', cveId, error)
      cveSourceStatuses.push(status)
      errors.push({
        cveId,
        source: 'MISP',
        error: status.error ?? status.message ?? 'MISP lookup failed.',
      })
    }

    sourceStatuses.push(...cveSourceStatuses)

    results.push({
      cveId,
      nvd: Boolean(nvd),
      cisaKev: Boolean(kev),
      mispMatches: mispMatches.length,
      misp: {
        enabled: mispEnabled,
        matches: mispMatches.length,
        note: mispNote ?? null,
      },
      cvssScore: nvd?.cvssScore ?? null,
      cvssSeverity: nvd?.cvssSeverity ?? null,
      cvssVector: nvd?.cvssVector ?? null,
      knownExploited: Boolean(kev),
      sourceStatuses: cveSourceStatuses,
      errors: errors.filter((item) => item.cveId === cveId),
    })
  }

  return {
    ok: errors.length === 0,
    reportId,
    cveCount: cves.length,
    graphCveCount: graphCves.length,
    fallbackCveCount: graphCves.length === 0 ? fallbackCves.length : 0,
    results,
    sourceStatuses,
    notes,
    errors,
  }
}
