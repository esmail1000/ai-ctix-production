// lib/server/knowledge-graph/query-graph.ts

import neo4j from 'neo4j-driver'
import { runCypher } from './neo4j'

function toJs(value: any): any {
  if (neo4j.isInt(value)) return value.toNumber()

  if (Array.isArray(value)) {
    return value.map(toJs)
  }

  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value).map(([key, val]) => [key, toJs(val)])
    )
  }

  return value
}

function getNodeKey(node: any): string {
  return node.elementId ?? node.identity?.toString?.() ?? String(node.identity)
}

function getRelKey(rel: any): string {
  return rel.elementId ?? rel.identity?.toString?.() ?? String(rel.identity)
}

function getRelStartKey(rel: any): string {
  return (
    rel.startNodeElementId ??
    rel.start?.toString?.() ??
    rel.startNodeIdentity?.toString?.() ??
    String(rel.start)
  )
}

function getRelEndKey(rel: any): string {
  return (
    rel.endNodeElementId ??
    rel.end?.toString?.() ??
    rel.endNodeIdentity?.toString?.() ??
    String(rel.end)
  )
}

function normalizeId(value: string | undefined | null) {
  return String(value ?? '').trim()
}

export async function getKnowledgeGraphForReport(
  userId: string,
  reportId: string,
  depth = 4
) {
  const normalizedUserId = normalizeId(userId)
  const normalizedReportId = normalizeId(reportId)
  const safeDepth = Math.max(1, Math.min(Math.floor(depth), 6))

  if (!normalizedUserId || !normalizedReportId) {
    return { nodes: [], edges: [] }
  }

 const records = await runCypher(
  `
  MATCH (r:Report {id: $reportId, userId: $userId})

  OPTIONAL MATCH (r)-[:CONTAINS]->(directFinding:Finding {userId: $userId})

  WITH
    r,
    collect(DISTINCT directFinding) AS directFindings

  OPTIONAL MATCH p=(r)-[*1..${safeDepth}]-(n)

  WHERE
    n IS NULL
    OR (
      (n:Report AND n.userId = $userId)
      OR (n:Finding AND n.userId = $userId)
      OR (n:Asset AND n.userId = $userId)
      OR (n:Impact AND n.userId = $userId)
      OR (n:Remediation AND n.userId = $userId)
      OR (n:Exploit AND n.userId = $userId)
      OR n:CVE
      OR n:CWE
      OR n:OWASP
      OR n:MITRETechnique
      OR n:Advisory
      OR n:CVSS
      OR n:KnownExploitedVulnerability
      OR n:Reference
      OR n:MISPAttribute
    )

  WITH
    r,
    directFindings,
    collect(DISTINCT n) AS traversedNodes,
    reduce(
      acc = [],
      rels IN collect(CASE WHEN p IS NULL THEN [] ELSE relationships(p) END)
      | acc + rels
    ) AS rawRels

  WITH
    [r]
    + [f IN directFindings WHERE f IS NOT NULL]
    + [n IN traversedNodes WHERE n IS NOT NULL] AS rawNodes,
    rawRels

  UNWIND rawNodes AS node

  WITH
    collect(DISTINCT node) AS nodes,
    rawRels

  UNWIND CASE WHEN size(rawRels) = 0 THEN [null] ELSE rawRels END AS rel

  WITH
    nodes,
    collect(DISTINCT rel) AS collectedRels

  RETURN
    nodes,
    [x IN collectedRels WHERE x IS NOT NULL] AS rels
  `,
  {
    userId,
    reportId,
  }
)
  if (!records.length) {
    return { nodes: [], edges: [] }
  }

  const record = records[0]
  const rawNodes = record.get('nodes') ?? []
  const rawRels = record.get('rels') ?? []

  const elementToGraphId = new Map<string, string>()

  const nodes = rawNodes
    .filter(Boolean)
    .map((node: any) => {
      const labels = node.labels ?? ['Node']
      const primaryLabel = labels[0]
      const props = toJs(node.properties ?? {})
      const domainId = String(props.id ?? getNodeKey(node))
      const graphId = `${primaryLabel}:${domainId}`

      elementToGraphId.set(getNodeKey(node), graphId)

      if (node.identity) {
        elementToGraphId.set(node.identity.toString(), graphId)
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
      }
    })

  const edges = rawRels
    .filter(Boolean)
    .map((rel: any) => {
      const source =
        elementToGraphId.get(getRelStartKey(rel)) ?? getRelStartKey(rel)
      const target =
        elementToGraphId.get(getRelEndKey(rel)) ?? getRelEndKey(rel)

      return {
        data: {
          id: `${rel.type}:${source}->${target}:${getRelKey(rel)}`,
          source,
          target,
          label: rel.type,
          type: rel.type,
          ...toJs(rel.properties ?? {}),
        },
      }
    })

  return { nodes, edges }
}

export async function deleteKnowledgeGraphReportForUser(
  userId: string,
  reportId: string
) {
  const normalizedUserId = normalizeId(userId)
  const normalizedReportId = normalizeId(reportId)

  if (!normalizedUserId || !normalizedReportId) {
    return { deleted: 0 }
  }

  const records = await runCypher(
    `
    MATCH (r:Report {id: $reportId, userId: $userId})
    OPTIONAL MATCH (r)-[:CONTAINS]->(f:Finding {userId: $userId})
    OPTIONAL MATCH (f)-[:AFFECTS]->(a:Asset {userId: $userId})
    OPTIONAL MATCH (f)-[:HAS_IMPACT]->(i:Impact {userId: $userId})
    OPTIONAL MATCH (f)-[:HAS_REMEDIATION]->(m:Remediation {userId: $userId})
    OPTIONAL MATCH (f)-[:HAS_EXPLOIT]->(e:Exploit {userId: $userId})
    WITH
      collect(DISTINCT r)
      + collect(DISTINCT f)
      + collect(DISTINCT a)
      + collect(DISTINCT i)
      + collect(DISTINCT m)
      + collect(DISTINCT e) AS nodes
    UNWIND nodes AS node
    WITH DISTINCT node
    WHERE node IS NOT NULL
    DETACH DELETE node
    RETURN count(node) AS deleted
    `,
    { userId: normalizedUserId, reportId: normalizedReportId }
  )

  return { deleted: records[0]?.get('deleted')?.toNumber?.() ?? 0 }
}
