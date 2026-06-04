// lib/server/knowledge-graph/attack-path.ts

import neo4j from "neo4j-driver";
import { runCypher } from "./neo4j";

type PathNode = {
  type: string;
  id: string;
  name: string;
};

type PathJson = {
  nodes: PathNode[];
  relationships: Array<{ type: string }>;
};

function toNumber(value: any): number {
  if (neo4j.isInt(value)) return value.toNumber();

  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function nodeSummary(node: any): PathNode {
  const props = node.properties ?? {};
  const label = node.labels?.[0] ?? "Node";

  return {
    type: label,
    id: String(props.id ?? ""),
    name: String(props.name ?? props.title ?? props.text ?? props.id ?? label),
  };
}

function pathToJson(path: any): PathJson {
  const nodes: PathNode[] = [];
  const relationships: Array<{ type: string }> = [];

  if (!path?.segments?.length) {
    return { nodes, relationships };
  }

  for (let index = 0; index < path.segments.length; index++) {
    const segment = path.segments[index];

    if (index === 0) {
      nodes.push(nodeSummary(segment.start));
    }

    relationships.push({
      type: segment.relationship.type,
    });

    nodes.push(nodeSummary(segment.end));
  }

  return { nodes, relationships };
}

function severityWeight(severity?: string) {
  const value = String(severity ?? "").toLowerCase();

  if (value.includes("critical")) return 30;
  if (value.includes("high")) return 22;
  if (value.includes("medium")) return 14;
  if (value.includes("low")) return 7;

  return 3;
}

function nodeBonus(path: PathJson) {
  const types = new Set(path.nodes.map((node) => node.type));
  const names = path.nodes.map((node) => `${node.id} ${node.name}`).join(" ");

  let bonus = 0;

  if (types.has("CVE")) bonus += 15;
  if (types.has("CWE")) bonus += 8;
  if (types.has("OWASP")) bonus += 8;
  if (types.has("MITRETechnique")) bonus += 12;
  if (types.has("Exploit")) bonus += 15;
  if (types.has("Impact")) bonus += 10;

  if (/T1190|Exploit Public-Facing Application/i.test(names)) bonus += 10;
  if (/remote code execution|rce|system compromise/i.test(names)) bonus += 12;
  if (/authentication bypass|credential|secret/i.test(names)) bonus += 8;
  if (/denial of service|dos/i.test(names)) bonus += 5;

  return bonus;
}

function predictOutcome(path: PathJson) {
  const impact = path.nodes.find((node) => node.type === "Impact");
  if (impact) return impact.name;

  const mitre = path.nodes.find((node) => node.type === "MITRETechnique");
  if (mitre) return `Likely attack technique: ${mitre.name}`;

  const owasp = path.nodes.find((node) => node.type === "OWASP");
  if (owasp) return `Likely weakness category: ${owasp.name}`;

  const cwe = path.nodes.find((node) => node.type === "CWE");
  if (cwe) return `Likely weakness: ${cwe.name}`;

  return "Potential exploitation path requires further enrichment.";
}

function likelihoodLabel(score: number, severity?: string) {
  const sev = String(severity ?? "").toLowerCase();

  if (score >= 85) {
    if (sev.includes("critical")) return "Critical";
    if (sev.includes("high")) return "High";
    return "Medium";
  }

  if (score >= 70) {
    if (sev.includes("low")) return "Medium";
    return "High";
  }

  if (score >= 45) return "Medium";

  return "Low";
}

function confidenceScore(path: PathJson) {
  const types = new Set(path.nodes.map((node) => node.type));

  let confidence = 35;

  if (types.has("Finding")) confidence += 10;
  if (types.has("CWE")) confidence += 10;
  if (types.has("OWASP")) confidence += 10;
  if (types.has("MITRETechnique")) confidence += 15;
  if (types.has("CVE")) confidence += 15;
  if (types.has("Impact")) confidence += 10;

  return Math.min(confidence, 95);
}

function scorePath(path: PathJson, riskScore: number, severity: string) {
  const rawScore = riskScore + severityWeight(severity) + nodeBonus(path);

  return Math.max(0, Math.min(Math.round(rawScore), 100));
}

function pickBestPath(paths: any[]) {
  if (!paths.length) return null;

  const scored = paths.map((path) => {
    const json = pathToJson(path);
    const richness = new Set(json.nodes.map((node) => node.type)).size;
    const length = json.relationships.length;

    return {
      raw: path,
      score: richness * 10 + length,
    };
  });

  scored.sort((a, b) => b.score - a.score);

  return scored[0].raw;
}

export async function getAttackPathsForReport(reportId: string, limit = 10) {
  const safeLimit = Math.max(1, Math.min(Math.floor(limit), 50));

  const records = await runCypher(
    `
    MATCH (r:Report {id: $reportId})-[:CONTAINS]->(f:Finding)

    OPTIONAL MATCH path =
      (r)-[:CONTAINS]->(f)
      -[:HAS_CVE|HAS_CWE|HAS_WEAKNESS|MAPS_TO|USES_TECHNIQUE|ENABLES|LEADS_TO|HAS_IMPACT*1..6]->
      (target)

    WHERE
      target:Impact
      OR target:MITRETechnique
      OR target:OWASP
      OR target:CWE
      OR target:CVE
      OR target:Exploit

    WITH
      f,
      [p IN collect(DISTINCT path) WHERE p IS NOT NULL] AS paths

    RETURN
      f.id AS findingId,
      f.title AS findingTitle,
      f.severity AS severity,
      f.riskScore AS riskScore,
      paths

    ORDER BY coalesce(f.riskScore, 0) DESC
    LIMIT $limit
    `,
    {
      reportId,
      limit: neo4j.int(safeLimit),
    }
  );

  return records.map((record) => {
    const findingId = String(record.get("findingId"));
    const findingTitle = String(record.get("findingTitle"));
    const severity = String(record.get("severity") ?? "Unknown");
    
    const riskScore = toNumber(record.get("riskScore"));
    const paths = record.get("paths") ?? [];

    const bestPath = pickBestPath(paths);
    const pathJson = bestPath ? pathToJson(bestPath) : {
      nodes: [
        {
          type: "Finding",
          id: findingId,
          name: findingTitle,
        },
      ],
      relationships: [],
    };

    const attackPathScore = scorePath(pathJson, riskScore, severity);
    const confidence = confidenceScore(pathJson);
    const exploitLikelihood = likelihoodLabel(attackPathScore);
    const predictedOutcome = predictOutcome(pathJson);

    return {
      findingId,
      findingTitle,
      severity,
      riskScore,
      attackPathScore,
      exploitLikelihood,
      confidence,
      predictedOutcome,
      reasoning: [
        `Severity is ${severity}.`,
        `Base risk score is ${riskScore}.`,
        `Graph evidence includes ${Array.from(
          new Set(pathJson.nodes.map((node) => node.type))
        ).join(", ")}.`,
        `Predicted outcome: ${predictedOutcome}`,
      ],
      path: pathJson,
    };
  });
}