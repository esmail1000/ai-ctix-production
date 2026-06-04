import { runCypher } from "@/lib/server/knowledge-graph/neo4j";
import { findCisaKev } from "./cisa-kev";
import { searchMispByCve } from "./misp";
import { fetchNvdCve } from "./nvd";

function unique(values: string[]) {
  return Array.from(new Set(values.filter(Boolean)));
}

async function getReportCves(reportId: string) {
  const records = await runCypher(
    `
    MATCH (:Report {id: $reportId})-[:CONTAINS]->(:Finding)-[:HAS_CVE]->(c:CVE)
    RETURN DISTINCT c.id AS cveId
    ORDER BY cveId
    `,
    { reportId }
  );

  return records.map((record) => String(record.get("cveId")).toUpperCase());
}

async function storeNvdIntel(cveId: string, intel: Awaited<ReturnType<typeof fetchNvdCve>>) {
  if (!intel) return;

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
      description: intel.description ?? "",
      published: intel.published ?? null,
      lastModified: intel.lastModified ?? null,
      cvssScore:
        typeof intel.cvssScore === "number" ? intel.cvssScore : null,
      cvssSeverity: intel.cvssSeverity ?? null,
      cvssVector: intel.cvssVector ?? null,
      cvssId: `CVSS:${cveId}`,
    }
  );

  for (const ref of unique(intel.references ?? []).slice(0, 10)) {
    await runCypher(
      `
      MATCH (c:CVE {id: $cveId})
      MERGE (r:Reference {id: $ref})
      SET r.url = $ref
      MERGE (c)-[:HAS_REFERENCE]->(r)
      `,
      { cveId, ref }
    );
  }
}

async function storeKevIntel(cveId: string, kev: Awaited<ReturnType<typeof findCisaKev>>) {
  if (!kev) return;

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
      vendorProject: kev.vendorProject ?? "",
      product: kev.product ?? "",
      vulnerabilityName: kev.vulnerabilityName ?? "",
      dateAdded: kev.dateAdded ?? null,
      dueDate: kev.dueDate ?? null,
      requiredAction: kev.requiredAction ?? "",
      knownRansomwareCampaignUse: kev.knownRansomwareCampaignUse ?? "",
      notes: kev.notes ?? "",
    }
  );
}

async function storeMispIntel(cveId: string, mispItems: Awaited<ReturnType<typeof searchMispByCve>>) {
for (let index = 0; index < mispItems.length; index += 1) {
  const item = mispItems[index];    await runCypher(
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
        category: item.category ?? "",
        type: item.type ?? "",
        eventId: item.eventId ?? "",
        eventInfo: item.eventInfo ?? "",
        tags: item.tags ?? [],
      }
    );
  }
}

export async function enrichReportThreatIntel(reportId: string) {
  const cves = await getReportCves(reportId);
  const results = [];

  for (const cveId of cves) {
    const nvd = await fetchNvdCve(cveId);
    await storeNvdIntel(cveId, nvd);

    const kev = await findCisaKev(cveId);
    await storeKevIntel(cveId, kev);

    const misp = await searchMispByCve(cveId);
    await storeMispIntel(cveId, misp);

    results.push({
      cveId,
      nvd: Boolean(nvd),
      cisaKev: Boolean(kev),
      mispMatches: misp.length,
      cvssScore: nvd?.cvssScore ?? null,
      cvssSeverity: nvd?.cvssSeverity ?? null,
      knownExploited: Boolean(kev),
    });
  }

  return {
    reportId,
    cveCount: cves.length,
    results,
  };
}