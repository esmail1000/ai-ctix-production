// lib/server/knowledge-graph/build-graph.ts

import crypto from "crypto";
import { enrichFinding } from "./mappings";
import { ensureKnowledgeGraphSchema, runCypher } from "./neo4j";
import type { BuildGraphInput, GraphFindingInput } from "./types";

function hash(value: string): string {
  return crypto.createHash("sha1").update(value).digest("hex").slice(0, 16);
}

function unique(values: Array<string | undefined | null>): string[] {
  return Array.from(
    new Set(
      values
        .filter(Boolean)
        .map((v) => String(v).trim())
    )
  ).filter(Boolean);
}

function normalizeOwasp(items: GraphFindingInput["owasp"] = []) {
  return items.map((item) =>
    typeof item === "string" ? { id: item, name: item } : item
  );
}

function normalizeFindingId(
  reportId: string,
  finding: GraphFindingInput,
  index: number
) {
  if (finding.id) return finding.id;

  return `${reportId}:finding:${index + 1}:${hash(
    `${finding.title}:${finding.description ?? ""}`
  )}`;
}

export async function buildKnowledgeGraphFromAnalysis(input: BuildGraphInput) {
  await ensureKnowledgeGraphSchema();

  await runCypher(
    `
    MERGE (r:Report {id: $reportId})
    SET r.name = $reportName,
        r.sourceFileName = $sourceFileName,
        r.updatedAt = datetime(),
        r.createdAt = coalesce(r.createdAt, datetime())
    `,
    {
      reportId: input.reportId,
      reportName: input.reportName ?? input.reportId,
      sourceFileName: input.sourceFileName ?? null,
    }
  );

  for (let index = 0; index < input.findings.length; index++) {
    const finding = enrichFinding(input.findings[index]);
    const findingId = normalizeFindingId(input.reportId, finding, index);

    const assets = unique([
      finding.asset,
      ...(finding.assets ?? []),
    ]);

    const cves = unique(finding.cves ?? []).map((cve) => cve.toUpperCase());
    const cwes = unique(finding.cwes ?? []);
    const owasp = normalizeOwasp(finding.owasp ?? []);
    const mitreTechniques = finding.mitreTechniques ?? [];

    const impacts = unique(finding.impacts ?? []).map((text) => ({
      id: `impact:${hash(text)}`,
      text,
    }));

    const remediations = unique(finding.remediations ?? []).map((text) => ({
      id: `remediation:${hash(text)}`,
      text,
    }));

    const exploits = unique(finding.exploits ?? []).map((text) => ({
      id: `exploit:${hash(text)}`,
      text,
    }));

    await runCypher(
      `
      MATCH (r:Report {id: $reportId})
      MERGE (f:Finding {id: $findingId})
      SET f.title = $title,
          f.description = $description,
          f.severity = $severity,
          f.riskScore = $riskScore,
          f.updatedAt = datetime(),
          f.createdAt = coalesce(f.createdAt, datetime())
      MERGE (r)-[:CONTAINS]->(f)
      `,
      {
        reportId: input.reportId,
        findingId,
        title: finding.title,
        description: finding.description ?? "",
        severity: finding.severity ?? "Unknown",
        riskScore: finding.riskScore ?? 0,
      }
    );

    await runCypher(
      `
      MATCH (f:Finding {id: $findingId})
      UNWIND $assets AS assetName
      MERGE (a:Asset {id: assetName})
      SET a.name = assetName
      MERGE (f)-[:AFFECTS]->(a)
      `,
      { findingId, assets }
    );

    await runCypher(
      `
      MATCH (f:Finding {id: $findingId})
      UNWIND $cves AS cveId
      MERGE (c:CVE {id: cveId})
      SET c.name = cveId
      MERGE (f)-[:HAS_CVE]->(c)
      `,
      { findingId, cves }
    );

    await runCypher(
      `
      MATCH (f:Finding {id: $findingId})
      UNWIND $cwes AS cweId
      MERGE (w:CWE {id: cweId})
      SET w.name = cweId
      MERGE (f)-[:HAS_CWE]->(w)
      `,
      { findingId, cwes }
    );

    await runCypher(
      `
      UNWIND $cves AS cveId
      MATCH (c:CVE {id: cveId})
      UNWIND $cwes AS cweId
      MATCH (w:CWE {id: cweId})
      MERGE (c)-[:HAS_WEAKNESS]->(w)
      `,
      { cves, cwes }
    );

    await runCypher(
      `
      MATCH (f:Finding {id: $findingId})
      UNWIND $owasp AS item
      MERGE (o:OWASP {id: item.id})
      SET o.name = coalesce(item.name, item.id)
      MERGE (f)-[:MAPS_TO]->(o)
      `,
      { findingId, owasp }
    );

    await runCypher(
      `
      UNWIND $cwes AS cweId
      MATCH (w:CWE {id: cweId})
      UNWIND $owasp AS item
      MATCH (o:OWASP {id: item.id})
      MERGE (w)-[:MAPS_TO]->(o)
      `,
      { cwes, owasp }
    );

    await runCypher(
      `
      MATCH (f:Finding {id: $findingId})
      UNWIND $mitreTechniques AS item
      MERGE (t:MITRETechnique {id: item.id})
      SET t.name = coalesce(item.name, item.id),
          t.tactic = item.tactic
      MERGE (f)-[:USES_TECHNIQUE]->(t)
      `,
      { findingId, mitreTechniques }
    );

    await runCypher(
      `
      UNWIND $cves AS cveId
      MATCH (c:CVE {id: cveId})
      UNWIND $mitreTechniques AS item
      MATCH (t:MITRETechnique {id: item.id})
      MERGE (c)-[:ENABLES]->(t)
      `,
      { cves, mitreTechniques }
    );

    await runCypher(
      `
      MATCH (f:Finding {id: $findingId})
      UNWIND $impacts AS item
      MERGE (i:Impact {id: item.id})
      SET i.name = item.text
      MERGE (f)-[:HAS_IMPACT]->(i)
      `,
      { findingId, impacts }
    );

    await runCypher(
      `
      UNWIND $mitreTechniques AS technique
      MATCH (t:MITRETechnique {id: technique.id})
      UNWIND $impacts AS impact
      MATCH (i:Impact {id: impact.id})
      MERGE (t)-[:LEADS_TO]->(i)
      `,
      { mitreTechniques, impacts }
    );

    await runCypher(
      `
      MATCH (f:Finding {id: $findingId})
      UNWIND $remediations AS item
      MERGE (m:Remediation {id: item.id})
      SET m.text = item.text
      MERGE (f)-[:MITIGATED_BY]->(m)
      `,
      { findingId, remediations }
    );

    await runCypher(
      `
      MATCH (f:Finding {id: $findingId})
      UNWIND $exploits AS item
      MERGE (e:Exploit {id: item.id})
      SET e.name = item.text
      MERGE (f)-[:HAS_EXPLOIT]->(e)
      `,
      { findingId, exploits }
    );

    await runCypher(
      `
      UNWIND $cves AS cveId
      MATCH (c:CVE {id: cveId})
      UNWIND $exploits AS item
      MATCH (e:Exploit {id: item.id})
      MERGE (c)-[:EXPLOITED_BY]->(e)
      `,
      { cves, exploits }
    );
  }

  return {
    reportId: input.reportId,
    findingsInserted: input.findings.length,
  };
}