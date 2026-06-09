// lib/server/knowledge-graph/attack-path.ts

import neo4j from 'neo4j-driver'
import { runCypher } from './neo4j'

type PathNode = {
  type: string
  id: string
  name: string
  source?: string | null
  confidence?: number | null
  inferred?: boolean | null
}

type PathJson = {
  nodes: PathNode[]
  relationships: Array<{ type: string }>
}

type EvidenceItem = {
  rel: string
  node: PathNode
}

function toNumber(value: any): number {
  if (neo4j.isInt(value)) return value.toNumber()

  const parsed = Number(value)
  return Number.isFinite(parsed) ? parsed : 0
}

function toBoolean(value: any): boolean {
  if (typeof value === 'boolean') return value
  if (typeof value === 'string') return value.toLowerCase() === 'true'
  return Boolean(value)
}

function toStringArray(value: any): string[] {
  if (!Array.isArray(value)) return []
  return value.filter(Boolean).map(String)
}

function nodeSummary(node: any): PathNode | null {
  if (!node) return null

  const props = node.properties ?? {}
  const label = node.labels?.[0] ?? 'Node'

  return {
    type: label,
    id: String(props.id ?? ''),
    name: String(props.name ?? props.title ?? props.text ?? props.value ?? props.id ?? label),
    source: props.source ? String(props.source) : null,
    confidence: props.confidence == null ? null : toNumber(props.confidence),
    inferred: props.inferred == null ? null : toBoolean(props.inferred),
  }
}

function uniqueEvidence(items: EvidenceItem[]) {
  const seen = new Set<string>()
  const output: EvidenceItem[] = []

  for (const item of items) {
    const key = `${item.node.type}:${item.node.id || item.node.name}`
    if (seen.has(key)) continue
    seen.add(key)
    output.push(item)
  }

  return output
}

function isGenericImpact(value: string) {
  return /potential impact includes exploitation|unauthorized access|data exposure|service compromise if this issue remains unaddressed/i.test(value)
}

function evidenceRank(item: EvidenceItem) {
  const node = item.node
  let score = 0

  if (node.source === 'report-extracted') score += 40
  if (node.source === 'threat-intel') score += 35
  if (node.source === 'known-cve-rule') score += 25
  if (node.source === 'deterministic-keyword-rule') score += 15
  if (node.inferred === false) score += 25
  if (node.inferred === true) score -= 8
  if (node.confidence) score += Math.min(node.confidence, 100) / 10

  if (node.type === 'Impact' && isGenericImpact(node.name)) score -= 30
  if (/remote code execution|system compromise|authentication bypass|sensitive user data|database records/i.test(node.name)) {
    score += 8
  }

  return score
}

function pickBest(items: EvidenceItem[], type: string): EvidenceItem | null {
  const matches = items.filter((item) => item.node.type === type)
  if (!matches.length) return null

  matches.sort((a, b) => evidenceRank(b) - evidenceRank(a))
  return matches[0]
}

function pickBestIndicator(items: EvidenceItem[]): EvidenceItem | null {
  const priority = ['URL', 'IP', 'Domain', 'Endpoint', 'Port', 'Service']
  const matches = items.filter((item) => item.node.type === 'Indicator')

  matches.sort((a, b) => {
    const ai = priority.indexOf(String(a.node.source ?? ''))
    const bi = priority.indexOf(String(b.node.source ?? ''))
    if (ai !== bi) return (ai < 0 ? 99 : ai) - (bi < 0 ? 99 : bi)
    return evidenceRank(b) - evidenceRank(a)
  })

  return matches[0] ?? null
}

function buildEvidencePath(reportId: string, findingId: string, findingTitle: string, evidence: EvidenceItem[]): PathJson {
  const nodes: PathNode[] = [
    {
      type: 'Report',
      id: reportId,
      name: 'Analyzed Report',
    },
    {
      type: 'Finding',
      id: findingId,
      name: findingTitle,
    },
  ]
  const relationships: Array<{ type: string }> = [{ type: 'CONTAINS' }]

  const selected = [
    pickBest(evidence, 'Asset'),
    pickBestIndicator(evidence),
    pickBest(evidence, 'CVE'),
    pickBest(evidence, 'CWE'),
    pickBest(evidence, 'OWASP'),
    pickBest(evidence, 'MITRETechnique'),
    pickBest(evidence, 'Exploit'),
    pickBest(evidence, 'Impact'),
    pickBest(evidence, 'Remediation'),
  ].filter(Boolean) as EvidenceItem[]

  for (const item of uniqueEvidence(selected)) {
    nodes.push(item.node)
    relationships.push({ type: item.rel })
  }

  return { nodes, relationships }
}

function severityWeight(severity?: string) {
  const value = String(severity ?? '').toLowerCase()

  if (value.includes('critical')) return 30
  if (value.includes('high')) return 22
  if (value.includes('medium')) return 14
  if (value.includes('low')) return 7

  return 3
}

function nodeBonus(path: PathJson) {
  const types = new Set(path.nodes.map((node) => node.type))
  const names = path.nodes.map((node) => `${node.id} ${node.name}`).join(' ')

  let bonus = 0

  if (types.has('Asset')) bonus += 8
  if (types.has('Indicator')) bonus += 6
  if (types.has('CVE')) bonus += 15
  if (types.has('CWE')) bonus += 8
  if (types.has('OWASP')) bonus += 8
  if (types.has('MITRETechnique')) bonus += 12
  if (types.has('Exploit')) bonus += 15
  if (types.has('Impact')) bonus += 10

  if (/T1190|Exploit Public-Facing Application/i.test(names)) bonus += 10
  if (/remote code execution|rce|system compromise/i.test(names)) bonus += 12
  if (/authentication bypass|credential|secret/i.test(names)) bonus += 8
  if (/denial of service|dos/i.test(names)) bonus += 5

  return bonus
}

function predictOutcome(path: PathJson) {
  const impact = [...path.nodes]
    .filter((node) => node.type === 'Impact')
    .sort((a, b) => {
      const aScore = (a.source === 'report-extracted' ? 50 : 0) + (a.inferred === false ? 25 : 0) - (isGenericImpact(a.name) ? 40 : 0)
      const bScore = (b.source === 'report-extracted' ? 50 : 0) + (b.inferred === false ? 25 : 0) - (isGenericImpact(b.name) ? 40 : 0)
      return bScore - aScore
    })[0]
  if (impact) return impact.name

  const exploit = path.nodes.find((node) => node.type === 'Exploit')
  if (exploit) return `Graph-linked exploit evidence: ${exploit.name}`

  const asset = path.nodes.find((node) => node.type === 'Asset')
  if (asset) return `Graph-linked affected asset: ${asset.name}`

  const mitre = path.nodes.find((node) => node.type === 'MITRETechnique')
  if (mitre) return `Graph-linked technique: ${mitre.name}`

  const owasp = path.nodes.find((node) => node.type === 'OWASP')
  if (owasp) return `Graph-linked weakness category: ${owasp.name}`

  const cwe = path.nodes.find((node) => node.type === 'CWE')
  if (cwe) return `Graph-linked weakness: ${cwe.name}`

  return 'No enriched path beyond the source finding was found.'
}

function likelihoodLabel(score: number, severity?: string) {
  const sev = String(severity ?? '').toLowerCase()

  if (score >= 85) {
    if (sev.includes('critical')) return 'Critical'
    if (sev.includes('high')) return 'High'
    return 'Medium'
  }

  if (score >= 70) {
    if (sev.includes('low')) return 'Medium'
    return 'High'
  }

  if (score >= 45) return 'Medium'

  return 'Low'
}

function confidenceScore(path: PathJson, graphDerived: boolean) {
  if (!graphDerived) return 25

  const types = new Set(path.nodes.map((node) => node.type))

  let confidence = 35

  if (types.has('Finding')) confidence += 10
  if (types.has('Asset')) confidence += 8
  if (types.has('Indicator')) confidence += 6
  if (types.has('CWE')) confidence += 10
  if (types.has('OWASP')) confidence += 10
  if (types.has('MITRETechnique')) confidence += 15
  if (types.has('CVE')) confidence += 15
  if (types.has('Exploit')) confidence += 10
  if (types.has('Impact')) confidence += 10

  return Math.min(confidence, 95)
}

function scorePath(path: PathJson, riskScore: number, severity: string, graphDerived: boolean) {
  if (!graphDerived) return Math.max(0, Math.min(Math.round(riskScore), 100))

  const rawScore = riskScore + severityWeight(severity) + nodeBonus(path)

  return Math.max(0, Math.min(Math.round(rawScore), 100))
}

function normalizeId(value: string | undefined | null) {
  return String(value ?? '').trim()
}

function buildReasoning(input: {
  severity: string
  riskScore: number
  evidenceTypes: string
  predictedOutcome: string
  graphDerived: boolean
  pathStatus: string
  knownExploited: boolean
  cisaKev: boolean
  exploitAvailable: boolean
  attackVector: string | null
  riskFactors: string[]
}) {
  const reasoning = [
    `Severity is ${input.severity}.`,
    `Final threat-aware risk score is ${input.riskScore}.`,
  ]

  if (input.graphDerived) {
    reasoning.push(`Graph evidence includes ${input.evidenceTypes}.`)
  } else {
    reasoning.push(
      'No enriched graph path was found; this result is marked as finding-only and should not be treated as a full attack path.'
    )
  }

  if (input.knownExploited || input.cisaKev) {
    reasoning.push('CISA KEV or threat intelligence confirms known exploitation.')
  }

  if (input.exploitAvailable) {
    reasoning.push('Exploit or proof-of-concept evidence is present in the report graph.')
  }

  if (input.attackVector) {
    reasoning.push(`Attack vector is ${input.attackVector}.`)
  }

  reasoning.push(`Path status is ${input.pathStatus}.`)
  reasoning.push(`Outcome is derived from report-scoped graph evidence: ${input.predictedOutcome}`)

  return Array.from(new Set([...reasoning, ...input.riskFactors.slice(0, 4)]))
}

export async function getAttackPathsForReport(
  userId: string,
  reportId: string,
  limit = 10
) {
  const normalizedUserId = normalizeId(userId)
  const normalizedReportId = normalizeId(reportId)
  const safeLimit = Math.max(1, Math.min(Math.floor(limit), 50))

  if (!normalizedUserId || !normalizedReportId) {
    return []
  }

  const records = await runCypher(
    `
    MATCH (r:Report {id: $reportId, userId: $userId})-[:CONTAINS]->(f:Finding {userId: $userId, reportId: $reportId})

    OPTIONAL MATCH (f)-[assetRel:AFFECTS]->(asset:Asset {userId: $userId})
    OPTIONAL MATCH (f)-[indicatorRel:HAS_INDICATOR]->(indicator:Indicator {userId: $userId, reportId: $reportId})
    OPTIONAL MATCH (f)-[cveRel:HAS_CVE]->(cve:CVE)
    OPTIONAL MATCH (f)-[cweRel:HAS_CWE]->(cwe:CWE)
    OPTIONAL MATCH (f)-[owaspRel:MAPS_TO]->(owasp:OWASP)
    OPTIONAL MATCH (f)-[mitreRel:USES_TECHNIQUE]->(mitre:MITRETechnique)
    OPTIONAL MATCH (f)-[exploitRel:HAS_EXPLOIT]->(exploit:Exploit {userId: $userId, reportId: $reportId})
    OPTIONAL MATCH (f)-[impactRel:HAS_IMPACT]->(impact:Impact {userId: $userId, reportId: $reportId})
    OPTIONAL MATCH (f)-[remRel:MITIGATED_BY]->(remediation:Remediation {userId: $userId, reportId: $reportId})

    WITH
      r,
      f,
      collect(DISTINCT {rel: 'AFFECTS', node: asset}) +
      collect(DISTINCT {rel: 'HAS_INDICATOR', node: indicator}) +
      collect(DISTINCT {rel: 'HAS_CVE', node: cve}) +
      collect(DISTINCT {rel: 'HAS_CWE', node: cwe}) +
      collect(DISTINCT {rel: 'MAPS_TO', node: owasp}) +
      collect(DISTINCT {rel: 'USES_TECHNIQUE', node: mitre}) +
      collect(DISTINCT {rel: 'HAS_EXPLOIT', node: exploit}) +
      collect(DISTINCT {rel: 'HAS_IMPACT', node: impact}) +
      collect(DISTINCT {rel: 'MITIGATED_BY', node: remediation}) AS evidence

    RETURN
      f.id AS findingId,
      f.title AS findingTitle,
      f.severity AS severity,
      coalesce(f.finalRiskScore, f.riskScore, 0) AS riskScore,
      f.knownExploited AS knownExploited,
      f.cisaKev AS cisaKev,
      f.exploitAvailable AS exploitAvailable,
      f.attackVector AS attackVector,
      f.riskFactors AS riskFactors,
      [item IN evidence WHERE item.node IS NOT NULL] AS evidence

    ORDER BY coalesce(f.finalRiskScore, f.riskScore, 0) DESC
    LIMIT $limit
    `,
    {
      userId: normalizedUserId,
      reportId: normalizedReportId,
      limit: neo4j.int(safeLimit),
    }
  )

  return records.map((record) => {
    const findingId = String(record.get('findingId'))
    const findingTitle = String(record.get('findingTitle'))
    const severity = String(record.get('severity') ?? 'Unknown')

    const riskScore = toNumber(record.get('riskScore'))
    const rawEvidence = record.get('evidence') ?? []
    const knownExploited = toBoolean(record.get('knownExploited'))
    const cisaKev = toBoolean(record.get('cisaKev'))
    const exploitAvailable = toBoolean(record.get('exploitAvailable'))
    const attackVector = record.get('attackVector')
      ? String(record.get('attackVector'))
      : null
    const riskFactors = toStringArray(record.get('riskFactors'))

    const evidence = uniqueEvidence(
      rawEvidence
        .map((item: any) => ({ rel: String(item.rel), node: nodeSummary(item.node) }))
        .filter((item: { rel: string; node: PathNode | null }): item is EvidenceItem => Boolean(item.node))
    )

    const pathJson = buildEvidencePath(normalizedReportId, findingId, findingTitle, evidence)
    const graphDerived = pathJson.nodes.length > 2
    const pathStatus = graphDerived ? 'graph-derived' : 'finding-only'
    const attackPathScore = scorePath(pathJson, riskScore, severity, graphDerived)
    const confidence = confidenceScore(pathJson, graphDerived)
    const exploitLikelihood = likelihoodLabel(attackPathScore, severity)
    const predictedOutcome = predictOutcome(pathJson)
    const evidenceTypes = Array.from(
      new Set(pathJson.nodes.map((node) => node.type))
    ).join(', ')

    return {
      findingId,
      findingTitle,
      severity,
      riskScore,
      attackPathScore,
      exploitLikelihood,
      confidence,
      predictedOutcome,
      pathStatus,
      graphDerived,
      knownExploited,
      cisaKev,
      exploitAvailable,
      attackVector,
      reasoning: buildReasoning({
        severity,
        riskScore,
        evidenceTypes,
        predictedOutcome,
        graphDerived,
        pathStatus,
        knownExploited,
        cisaKev,
        exploitAvailable,
        attackVector,
        riskFactors,
      }),
      path: pathJson,
    }
  })
}
