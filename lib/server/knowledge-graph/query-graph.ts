// lib/server/knowledge-graph/query-graph.ts

import neo4j from "neo4j-driver";
import { runCypher } from "./neo4j";

function toJs(value: any): any {
  if (neo4j.isInt(value)) return value.toNumber();

  if (Array.isArray(value)) {
    return value.map(toJs);
  }

  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, val]) => [key, toJs(val)])
    );
  }

  return value;
}

function getNodeKey(node: any): string {
  return node.elementId ?? node.identity?.toString?.() ?? String(node.identity);
}

function getRelKey(rel: any): string {
  return rel.elementId ?? rel.identity?.toString?.() ?? String(rel.identity);
}

function getRelStartKey(rel: any): string {
  return (
    rel.startNodeElementId ??
    rel.start?.toString?.() ??
    rel.startNodeIdentity?.toString?.() ??
    String(rel.start)
  );
}

function getRelEndKey(rel: any): string {
  return (
    rel.endNodeElementId ??
    rel.end?.toString?.() ??
    rel.endNodeIdentity?.toString?.() ??
    String(rel.end)
  );
}

export async function getKnowledgeGraphForReport(reportId: string, depth = 4) {
  const safeDepth = Math.max(1, Math.min(depth, 6));

  const records = await runCypher(
    `
    MATCH (r:Report {id: $reportId})
    OPTIONAL MATCH p=(r)-[*1..${safeDepth}]-(n)
    WITH collect(DISTINCT r) + collect(DISTINCT n) AS rawNodes,
         reduce(
           acc = [],
           rels IN collect(CASE WHEN p IS NULL THEN [] ELSE relationships(p) END)
           | acc + rels
         ) AS rawRels
    UNWIND rawNodes AS node
    WITH collect(DISTINCT node) AS nodes, rawRels
    UNWIND CASE WHEN size(rawRels) = 0 THEN [null] ELSE rawRels END AS rel
    RETURN nodes, [x IN collect(DISTINCT rel) WHERE x IS NOT NULL] AS rels
    `,
    { reportId }
  );

  if (!records.length) {
    return { nodes: [], edges: [] };
  }

  const record = records[0];
  const rawNodes = record.get("nodes") ?? [];
  const rawRels = record.get("rels") ?? [];

  const elementToGraphId = new Map<string, string>();

const nodes = rawNodes
  .filter(Boolean)
  .map((node: any) => {
    const labels = node.labels ?? ["Node"];
    const primaryLabel = labels[0];
    const props = toJs(node.properties ?? {});
    const domainId = String(props.id ?? getNodeKey(node));
    const graphId = `${primaryLabel}:${domainId}`;

    elementToGraphId.set(getNodeKey(node), graphId);

    if (node.identity) {
      elementToGraphId.set(node.identity.toString(), graphId);
    }

    return {
      data: {
        ...props,
        id: graphId,
        domainId,
        type: primaryLabel,
        label: primaryLabel,
        name:
          props.name ??
          props.title ??
          props.text ??
          props.id ??
          primaryLabel,
      },
    };
  });
  const edges = rawRels
    .filter(Boolean)
    .map((rel: any) => {
      const source =
        elementToGraphId.get(getRelStartKey(rel)) ?? getRelStartKey(rel);
      const target =
        elementToGraphId.get(getRelEndKey(rel)) ?? getRelEndKey(rel);

      return {
        data: {
          id: `${rel.type}:${source}->${target}:${getRelKey(rel)}`,
          source,
          target,
          label: rel.type,
          type: rel.type,
          ...toJs(rel.properties ?? {}),
        },
      };
    });

  return { nodes, edges };
}