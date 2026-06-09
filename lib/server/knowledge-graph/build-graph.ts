// lib/server/knowledge-graph/build-graph.ts

import crypto from 'crypto'
import { enrichFinding } from './mappings'
import { ensureKnowledgeGraphSchema, runCypher } from './neo4j'
import type {
  BuildGraphInput,
  GraphEvidenceSource,
  GraphFindingInput,
  GraphIndicatorInput,
  GraphMappingProvenance,
} from './types'

function hash(value: string): string {
  return crypto.createHash('sha1').update(value).digest('hex').slice(0, 16)
}

function unique(values: Array<string | undefined | null>): string[] {
  return Array.from(
    new Set(
      values
        .filter(Boolean)
        .map((value) => String(value).trim())
    )
  ).filter(Boolean)
}

function normalizeOwasp(items: GraphFindingInput['owasp'] = []) {
  return items
    .map((item) => (typeof item === 'string' ? { id: item, name: item } : item))
    .filter((item) => item?.id)
}

function normalizeFindingId(
  reportId: string,
  finding: GraphFindingInput,
  index: number
) {
  if (finding.id) return finding.id

  return `${reportId}:finding:${index + 1}:${hash(
    `${finding.title}:${finding.description ?? ''}`
  )}`
}

function scopedId(userId: string, type: string, value: string) {
  return `${type}:${hash(`${userId}:${value}`)}`
}

function normalizeUserId(value: string | undefined | null) {
  return String(value ?? '').trim()
}

function sourcePriority(source: GraphEvidenceSource) {
  switch (source) {
    case 'report-extracted':
      return 5
    case 'threat-intel':
      return 4
    case 'known-cve-rule':
      return 3
    case 'deterministic-keyword-rule':
      return 2
    case 'risk-engine':
      return 1
    default:
      return 0
  }
}

function provenanceFor(
  finding: GraphFindingInput,
  kind: GraphMappingProvenance['kind'],
  id: string,
  fallback: Partial<GraphMappingProvenance> = {}
): GraphMappingProvenance {
  const normalizedId = String(id ?? '').trim()
  const candidates = (finding.mappingProvenance ?? []).filter(
    (item) => item.kind === kind && item.id === normalizedId
  )

  candidates.sort((a, b) => {
    const priorityDelta = sourcePriority(b.source) - sourcePriority(a.source)
    if (priorityDelta !== 0) return priorityDelta
    return b.confidence - a.confidence
  })

  const selected = candidates[0]

  return {
    kind,
    id: normalizedId,
    source: selected?.source ?? fallback.source ?? 'unknown',
    rule: selected?.rule ?? fallback.rule,
    confidence: selected?.confidence ?? fallback.confidence ?? 50,
    inferred: selected?.inferred ?? fallback.inferred ?? true,
  }
}

function relationshipProps(provenance: GraphMappingProvenance) {
  return {
    source: provenance.source,
    rule: provenance.rule ?? null,
    confidence: provenance.confidence,
    inferred: Boolean(provenance.inferred),
  }
}

function normalizeIndicators(
  userId: string,
  reportId: string,
  findingId: string,
  indicators: GraphIndicatorInput[] = []
) {
  const map = new Map<string, {
    id: string
    type: GraphIndicatorInput['type']
    value: string
    source: GraphEvidenceSource
    confidence: number
    reportId: string
    findingId: string
  }>()

  for (const indicator of indicators) {
    const type = indicator.type
    const value = String(indicator.value ?? '').trim()
    if (!type || !value) continue

    const key = `${type}:${value.toLowerCase()}`
    const current = map.get(key)
    const next = {
      id: scopedId(userId, `indicator:${type.toLowerCase()}`, value),
      type,
      value,
      source: indicator.source ?? 'report-extracted',
      confidence: indicator.confidence ?? 85,
      reportId,
      findingId,
    }

    if (!current || next.confidence > current.confidence) {
      map.set(key, next)
    }
  }

  return Array.from(map.values())
}

async function cleanupExistingReportGraph(userId: string, reportId: string) {
  // Delete only user/report scoped finding graph content. Global CTI nodes such as
  // CVE/CWE/OWASP/MITRE are intentionally preserved, but all old Finding links are
  // removed so a re-analysis cannot keep stale report-specific paths alive.
  await runCypher(
    `
    MATCH (:Report {id: $reportId, userId: $userId})-[:CONTAINS]->(f:Finding {userId: $userId, reportId: $reportId})
    DETACH DELETE f
    `,
    { userId, reportId }
  )

  for (const label of ['Impact', 'Remediation', 'Exploit', 'Indicator']) {
    await runCypher(
      `
      MATCH (n:${label} {userId: $userId, reportId: $reportId})
      DETACH DELETE n
      `,
      { userId, reportId }
    )
  }
}

export async function buildKnowledgeGraphFromAnalysis(input: BuildGraphInput) {
  const userId = normalizeUserId(input.userId)

  if (!userId) {
    throw new Error('Knowledge graph build requires a userId for data isolation.')
  }

  await ensureKnowledgeGraphSchema()
  await cleanupExistingReportGraph(userId, input.reportId)

  await runCypher(
    `
    MERGE (r:Report {id: $reportId})
    SET r.userId = $userId,
        r.name = $reportName,
        r.sourceFileName = $sourceFileName,
        r.updatedAt = datetime(),
        r.createdAt = coalesce(r.createdAt, datetime())
    `,
    {
      userId,
      reportId: input.reportId,
      reportName: input.reportName ?? input.reportId,
      sourceFileName: input.sourceFileName ?? null,
    }
  )

  for (let index = 0; index < input.findings.length; index++) {
    const finding = enrichFinding(input.findings[index])
    const findingId = normalizeFindingId(input.reportId, finding, index)

    const assets = unique([finding.asset, ...(finding.assets ?? [])]).map(
      (assetName) => ({
        id: scopedId(userId, 'asset', assetName),
        name: assetName,
        source: 'report-extracted',
        confidence: 90,
      })
    )

    const cves = unique(finding.cves ?? [])
      .map((cve) => cve.toUpperCase())
      .map((id) => ({ id, source: 'report-extracted', confidence: 95 }))

    const cwes = unique(finding.cwes ?? []).map((id) => ({
      id,
      ...relationshipProps(provenanceFor(finding, 'cwe', id, {
        source: 'report-extracted',
        confidence: 90,
        inferred: false,
      })),
    }))

    const owasp = normalizeOwasp(finding.owasp ?? []).map((item) => ({
      id: item.id,
      name: item.name ?? item.id,
      ...relationshipProps(provenanceFor(finding, 'owasp', item.id, {
        source: item.source ?? 'unknown',
        confidence: item.confidence ?? 70,
        inferred: item.inferred ?? true,
      })),
    }))

    const mitreTechniques = (finding.mitreTechniques ?? []).map((item) => ({
      id: item.id,
      name: item.name ?? item.id,
      tactic: item.tactic ?? null,
      ...relationshipProps(provenanceFor(finding, 'mitre', item.id, {
        source: item.source ?? 'unknown',
        confidence: item.confidence ?? 70,
        inferred: item.inferred ?? true,
      })),
    }))

    const impacts = unique(finding.impacts ?? []).map((text) => ({
      id: scopedId(userId, 'impact', `${findingId}:${text}`),
      text,
      reportId: input.reportId,
      findingId,
      ...relationshipProps(provenanceFor(finding, 'impact', text, {
        source: 'report-extracted',
        confidence: 85,
        inferred: false,
      })),
    }))

    const remediations = unique(finding.remediations ?? []).map((text) => ({
      id: scopedId(userId, 'remediation', `${findingId}:${text}`),
      text,
      reportId: input.reportId,
      findingId,
      source: 'report-extracted',
      confidence: 88,
      inferred: false,
    }))

    const exploits = unique(finding.exploits ?? []).map((text) => ({
      id: scopedId(userId, 'exploit', `${findingId}:${text}`),
      text,
      reportId: input.reportId,
      findingId,
      source: 'report-extracted',
      confidence: 88,
      inferred: false,
    }))

    const indicators = normalizeIndicators(
      userId,
      input.reportId,
      findingId,
      finding.indicators ?? []
    )

    await runCypher(
      `
      MATCH (r:Report {id: $reportId, userId: $userId})
      MERGE (f:Finding {id: $findingId})
      SET f.userId = $userId,
          f.reportId = $reportId,
          f.title = $title,
          f.description = $description,
          f.severity = $severity,
          f.riskScore = $riskScore,
          f.updatedAt = datetime(),
          f.createdAt = coalesce(f.createdAt, datetime())
      MERGE (r)-[:CONTAINS]->(f)
      `,
      {
        userId,
        reportId: input.reportId,
        findingId,
        title: finding.title,
        description: finding.description ?? '',
        severity: finding.severity ?? 'Unknown',
        riskScore: finding.riskScore ?? 0,
      }
    )

    await runCypher(
      `
      MATCH (f:Finding {id: $findingId, userId: $userId, reportId: $reportId})
      UNWIND $assets AS item
      MERGE (a:Asset {id: item.id})
      SET a.userId = $userId,
          a.name = item.name,
          a.lastSeenReportId = $reportId,
          a.source = item.source,
          a.confidence = item.confidence
      MERGE (f)-[rel:AFFECTS]->(a)
      SET rel.source = item.source,
          rel.confidence = item.confidence,
          rel.inferred = false,
          rel.userId = $userId,
          rel.reportId = $reportId,
          rel.findingId = $findingId
      `,
      { userId, reportId: input.reportId, findingId, assets }
    )

    await runCypher(
      `
      MATCH (f:Finding {id: $findingId, userId: $userId, reportId: $reportId})
      UNWIND $cves AS item
      MERGE (c:CVE {id: item.id})
      SET c.name = item.id
      MERGE (f)-[rel:HAS_CVE]->(c)
      SET rel.source = item.source,
          rel.confidence = item.confidence,
          rel.inferred = false,
          rel.userId = $userId,
          rel.reportId = $reportId,
          rel.findingId = $findingId
      `,
      { userId, reportId: input.reportId, findingId, cves }
    )

    await runCypher(
      `
      MATCH (f:Finding {id: $findingId, userId: $userId, reportId: $reportId})
      UNWIND $cwes AS item
      MERGE (w:CWE {id: item.id})
      SET w.name = item.id
      MERGE (f)-[rel:HAS_CWE]->(w)
      SET rel.source = item.source,
          rel.rule = item.rule,
          rel.confidence = item.confidence,
          rel.inferred = item.inferred,
          rel.userId = $userId,
          rel.reportId = $reportId,
          rel.findingId = $findingId
      `,
      { userId, reportId: input.reportId, findingId, cwes }
    )

    await runCypher(
      `
      UNWIND $cves AS cve
      MATCH (c:CVE {id: cve.id})
      UNWIND $cwes AS weakness
      MATCH (w:CWE {id: weakness.id})
      MERGE (c)-[rel:HAS_WEAKNESS]->(w)
      SET rel.source = weakness.source,
          rel.rule = weakness.rule,
          rel.confidence = weakness.confidence,
          rel.inferred = weakness.inferred,
          rel.lastSeenReportId = $reportId
      `,
      { reportId: input.reportId, cves, cwes }
    )

    await runCypher(
      `
      MATCH (f:Finding {id: $findingId, userId: $userId, reportId: $reportId})
      UNWIND $owasp AS item
      MERGE (o:OWASP {id: item.id})
      SET o.name = coalesce(item.name, item.id)
      MERGE (f)-[rel:MAPS_TO]->(o)
      SET rel.source = item.source,
          rel.rule = item.rule,
          rel.confidence = item.confidence,
          rel.inferred = item.inferred,
          rel.userId = $userId,
          rel.reportId = $reportId,
          rel.findingId = $findingId
      `,
      { userId, reportId: input.reportId, findingId, owasp }
    )

    await runCypher(
      `
      UNWIND $cwes AS weakness
      MATCH (w:CWE {id: weakness.id})
      UNWIND $owasp AS item
      MATCH (o:OWASP {id: item.id})
      MERGE (w)-[rel:MAPS_TO]->(o)
      SET rel.source = item.source,
          rel.rule = item.rule,
          rel.confidence = item.confidence,
          rel.inferred = item.inferred,
          rel.lastSeenReportId = $reportId
      `,
      { reportId: input.reportId, cwes, owasp }
    )

    await runCypher(
      `
      MATCH (f:Finding {id: $findingId, userId: $userId, reportId: $reportId})
      UNWIND $mitreTechniques AS item
      MERGE (t:MITRETechnique {id: item.id})
      SET t.name = coalesce(item.name, item.id),
          t.tactic = item.tactic
      MERGE (f)-[rel:USES_TECHNIQUE]->(t)
      SET rel.source = item.source,
          rel.rule = item.rule,
          rel.confidence = item.confidence,
          rel.inferred = item.inferred,
          rel.userId = $userId,
          rel.reportId = $reportId,
          rel.findingId = $findingId
      `,
      { userId, reportId: input.reportId, findingId, mitreTechniques }
    )

    await runCypher(
      `
      UNWIND $cves AS cve
      MATCH (c:CVE {id: cve.id})
      UNWIND $mitreTechniques AS item
      MATCH (t:MITRETechnique {id: item.id})
      MERGE (c)-[rel:ENABLES]->(t)
      SET rel.source = item.source,
          rel.rule = item.rule,
          rel.confidence = item.confidence,
          rel.inferred = item.inferred,
          rel.lastSeenReportId = $reportId
      `,
      { reportId: input.reportId, cves, mitreTechniques }
    )

    await runCypher(
      `
      MATCH (f:Finding {id: $findingId, userId: $userId, reportId: $reportId})
      UNWIND $impacts AS item
      MERGE (i:Impact {id: item.id})
      SET i.userId = $userId,
          i.reportId = item.reportId,
          i.findingId = item.findingId,
          i.name = item.text,
          i.source = item.source,
          i.rule = item.rule,
          i.confidence = item.confidence,
          i.inferred = item.inferred
      MERGE (f)-[rel:HAS_IMPACT]->(i)
      SET rel.source = item.source,
          rel.rule = item.rule,
          rel.confidence = item.confidence,
          rel.inferred = item.inferred,
          rel.userId = $userId,
          rel.reportId = $reportId,
          rel.findingId = $findingId
      `,
      { userId, reportId: input.reportId, findingId, impacts }
    )

    await runCypher(
      `
      UNWIND $mitreTechniques AS technique
      MATCH (t:MITRETechnique {id: technique.id})
      UNWIND $impacts AS impact
      MATCH (i:Impact {id: impact.id, userId: $userId, reportId: $reportId})
      MERGE (t)-[rel:LEADS_TO]->(i)
      SET rel.source = impact.source,
          rel.rule = impact.rule,
          rel.confidence = impact.confidence,
          rel.inferred = impact.inferred,
          rel.userId = $userId,
          rel.reportId = $reportId
      `,
      { userId, reportId: input.reportId, mitreTechniques, impacts }
    )

    await runCypher(
      `
      MATCH (f:Finding {id: $findingId, userId: $userId, reportId: $reportId})
      UNWIND $remediations AS item
      MERGE (m:Remediation {id: item.id})
      SET m.userId = $userId,
          m.reportId = item.reportId,
          m.findingId = item.findingId,
          m.text = item.text,
          m.source = item.source,
          m.confidence = item.confidence,
          m.inferred = item.inferred
      MERGE (f)-[rel:MITIGATED_BY]->(m)
      SET rel.source = item.source,
          rel.confidence = item.confidence,
          rel.inferred = item.inferred,
          rel.userId = $userId,
          rel.reportId = $reportId,
          rel.findingId = $findingId
      `,
      { userId, reportId: input.reportId, findingId, remediations }
    )

    await runCypher(
      `
      MATCH (f:Finding {id: $findingId, userId: $userId, reportId: $reportId})
      UNWIND $exploits AS item
      MERGE (e:Exploit {id: item.id})
      SET e.userId = $userId,
          e.reportId = item.reportId,
          e.findingId = item.findingId,
          e.name = item.text,
          e.source = item.source,
          e.confidence = item.confidence,
          e.inferred = item.inferred
      MERGE (f)-[rel:HAS_EXPLOIT]->(e)
      SET rel.source = item.source,
          rel.confidence = item.confidence,
          rel.inferred = item.inferred,
          rel.userId = $userId,
          rel.reportId = $reportId,
          rel.findingId = $findingId
      `,
      { userId, reportId: input.reportId, findingId, exploits }
    )

    await runCypher(
      `
      UNWIND $cves AS cve
      MATCH (c:CVE {id: cve.id})
      UNWIND $exploits AS item
      MATCH (e:Exploit {id: item.id, userId: $userId, reportId: $reportId})
      MERGE (c)-[rel:EXPLOITED_BY]->(e)
      SET rel.source = item.source,
          rel.confidence = item.confidence,
          rel.inferred = item.inferred,
          rel.userId = $userId,
          rel.reportId = $reportId
      `,
      { userId, reportId: input.reportId, cves, exploits }
    )

    await runCypher(
      `
      MATCH (f:Finding {id: $findingId, userId: $userId, reportId: $reportId})
      UNWIND $indicators AS item
      MERGE (i:Indicator {id: item.id})
      SET i.userId = $userId,
          i.reportId = item.reportId,
          i.findingId = item.findingId,
          i.type = item.type,
          i.value = item.value,
          i.name = item.value,
          i.source = item.source,
          i.confidence = item.confidence
      MERGE (f)-[rel:HAS_INDICATOR]->(i)
      SET rel.source = item.source,
          rel.confidence = item.confidence,
          rel.inferred = false,
          rel.userId = $userId,
          rel.reportId = $reportId,
          rel.findingId = $findingId
      `,
      { userId, reportId: input.reportId, findingId, indicators }
    )
  }

  return {
    ok: true,
    reportId: input.reportId,
    findingsInserted: input.findings.length,
  }
}
