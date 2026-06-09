// lib/server/llm-analysis/threat-scenarios.ts

import { getAttackPathsForReport } from '@/lib/server/knowledge-graph/attack-path'
import { runCypher } from '@/lib/server/knowledge-graph/neo4j'

type ScenarioFinding = {
  findingId: string
  title: string
  severity: string
  riskScore: number
  cves: string[]
  cwes: string[]
  owasp: string[]
  mitre: string[]
  impacts: string[]
  remediations: string[]
}

function normalizeId(value: string | undefined | null): string {
  return String(value ?? '').trim()
}

function normalizeText(value: string | undefined | null): string {
  return String(value ?? '')
    .replace(/\s+/g, ' ')
    .replace(/[\s,;.:]+$/, '')
    .trim()
}

function semanticKey(value: string): string {
  return normalizeText(value)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, ' ')
    .replace(/\b(the|a|an|and|or|to|of|for|with|after|before)\b/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
}

function isNearDuplicate(a: string, b: string): boolean {
  const left = semanticKey(a)
  const right = semanticKey(b)
  if (!left || !right) return false
  if (left === right) return true

  const [shorter, longer] = left.length <= right.length ? [left, right] : [right, left]
  return shorter.length >= 18 && longer.includes(shorter)
}

function unique(values: string[]): string[] {
  const output: string[] = []

  for (const value of values.map(normalizeText).filter(Boolean)) {
    const duplicateIndex = output.findIndex((item) => isNearDuplicate(item, value))
    if (duplicateIndex >= 0) {
      if (value.length > output[duplicateIndex].length + 20) {
        output[duplicateIndex] = value
      }
      continue
    }

    output.push(value)
  }

  return output
}

function toPlain(value: any): any {
  if (value && typeof value.toNumber === 'function') return value.toNumber()
  return value
}

function likelihoodFromSeverity(severity: string, riskScore: number) {
  const sev = severity.toLowerCase()

  if (sev.includes('critical')) return 'Very High'
  if (sev.includes('high')) return 'High'
  if (sev.includes('medium') && riskScore >= 60) return 'Medium to High'
  if (sev.includes('medium')) return 'Medium'
  if (sev.includes('low')) return 'Low'

  return 'Unknown'
}

function attackerGoalFromEvidence(finding: ScenarioFinding) {
  const text = [
    finding.title,
    ...finding.cves,
    ...finding.cwes,
    ...finding.owasp,
    ...finding.mitre,
    ...finding.impacts,
  ]
    .join(' ')
    .toLowerCase()

  if (text.includes('remote code execution') || text.includes('rce')) {
    return 'execute arbitrary code and gain control of the affected service'
  }

  if (text.includes('path traversal') || text.includes('cwe-22')) {
    return 'read unauthorized files and potentially expose sensitive server data'
  }

  if (
    text.includes('injection') ||
    text.includes('cwe-89') ||
    text.includes('cwe-78')
  ) {
    return 'manipulate application input to change backend behavior'
  }

  if (text.includes('authentication bypass')) {
    return 'bypass authentication and access protected functionality'
  }

  if (text.includes('denial of service') || text.includes('dos')) {
    return 'disrupt service availability'
  }

  if (text.includes('secret') || text.includes('credential')) {
    return 'obtain credentials or secrets for follow-on access'
  }

  return 'increase attacker opportunity and move closer to system compromise'
}

function makeScenario(finding: ScenarioFinding, attackPath: any) {
  const attackerGoal = attackerGoalFromEvidence(finding)
  const likelihood = likelihoodFromSeverity(finding.severity, finding.riskScore)

  const pathText =
    attackPath?.path?.nodes?.map((node: any) => node.name).join(' → ') ??
    'No enriched graph path beyond the source finding'

  const firstCve = finding.cves[0]
  const cveText = firstCve ? ` The scenario is supported by ${firstCve}.` : ''

  return {
    findingId: finding.findingId,
    title: `Threat scenario for ${finding.title}`,
    likelihood,
    confidence: attackPath?.confidence ?? 50,
    attackerGoal,
    killChain: [
      {
        phase: 'Reconnaissance',
        description:
          'The attacker identifies the affected asset and confirms that the reported vulnerable behavior is reachable.',
      },
      {
        phase: 'Initial Access',
        description: firstCve
          ? `The attacker attempts to exploit ${firstCve} or a related weakness present in the report graph.`
          : 'The attacker attempts to trigger the weakness through crafted input or misuse of exposed functionality.',
      },
      {
        phase: 'Execution / Abuse',
        description: `The attacker uses the weakness to ${attackerGoal}.`,
      },
      {
        phase: 'Impact',
        description:
          finding.impacts[0] ??
          attackPath?.predictedOutcome ??
          'The impact requires further validation because no enriched graph outcome was found.',
      },
    ],
    graphEvidence: {
      path: pathText,
      cves: finding.cves,
      cwes: finding.cwes,
      owasp: finding.owasp,
      mitre: finding.mitre,
      impacts: finding.impacts,
    },
    recommendedDefenses:
      finding.remediations.length > 0
        ? finding.remediations
        : [
            'Patch or upgrade the affected component.',
            'Add strict input validation and normalization.',
            'Monitor exploitation attempts in application and web server logs.',
            'Add detection rules for suspicious request patterns.',
          ],
    narrative:
      `An attacker could target "${finding.title}" to ${attackerGoal}.${cveText} ` +
      `The graph-derived path is ${pathText}. The expected likelihood is ${likelihood}, ` +
      `based on severity ${finding.severity}, risk score ${finding.riskScore}, and user-scoped graph evidence.`,
  }
}

async function getScenarioFindings(
  userId: string,
  reportId: string
): Promise<ScenarioFinding[]> {
  const normalizedUserId = normalizeId(userId)
  const normalizedReportId = normalizeId(reportId)

  if (!normalizedUserId || !normalizedReportId) return []

  const records = await runCypher(
    `
    MATCH (:Report {id: $reportId, userId: $userId})-[:CONTAINS]->(f:Finding {userId: $userId, reportId: $reportId})

    OPTIONAL MATCH (f)-[:HAS_CVE]->(cve:CVE)
    OPTIONAL MATCH (f)-[:HAS_CWE]->(cwe:CWE)
    OPTIONAL MATCH (f)-[:MAPS_TO]->(owasp:OWASP)
    OPTIONAL MATCH (f)-[:USES_TECHNIQUE]->(mitre:MITRETechnique)
    OPTIONAL MATCH (f)-[:HAS_IMPACT]->(impact:Impact {userId: $userId})
    OPTIONAL MATCH (f)-[:MITIGATED_BY]->(remediation:Remediation {userId: $userId})

    RETURN
      f.id AS findingId,
      f.title AS title,
      f.severity AS severity,
      f.riskScore AS riskScore,
      collect(DISTINCT cve.id) AS cves,
      collect(DISTINCT cwe.id) AS cwes,
      collect(DISTINCT coalesce(owasp.name, owasp.id)) AS owasp,
      collect(DISTINCT coalesce(mitre.name, mitre.id)) AS mitre,
      collect(DISTINCT coalesce(impact.name, impact.text, impact.id)) AS impacts,
      collect(DISTINCT coalesce(remediation.text, remediation.name, remediation.id)) AS remediations,
      f.recommendations AS riskRecommendations

    ORDER BY coalesce(f.riskScore, 0) DESC
    `,
    {
      userId: normalizedUserId,
      reportId: normalizedReportId,
    }
  )

  return records.map((record) => ({
    findingId: String(record.get('findingId')),
    title: String(record.get('title')),
    severity: String(record.get('severity') ?? 'Unknown'),
    riskScore: Number(toPlain(record.get('riskScore')) ?? 0),
    cves: (record.get('cves') ?? []).filter(Boolean).map(String),
    cwes: (record.get('cwes') ?? []).filter(Boolean).map(String),
    owasp: (record.get('owasp') ?? []).filter(Boolean).map(String),
    mitre: (record.get('mitre') ?? []).filter(Boolean).map(String),
    impacts: (record.get('impacts') ?? []).filter(Boolean).map(String),
    remediations: (() => {
      const riskRecommendations = (record.get('riskRecommendations') ?? [])
        .filter(Boolean)
        .map(String)
      const graphRemediations = (record.get('remediations') ?? [])
        .filter(Boolean)
        .map(String)

      // Threat scenarios should use the phase-3 risk/defense-engine output when
      // it exists. Graph remediation nodes are a fallback only; mixing both causes
      // duplicated and sometimes older generic defenses in the scenario narrative.
      return unique(
        riskRecommendations.length > 0 ? riskRecommendations : graphRemediations
      )
    })(),
  }))
}

export async function generateThreatScenarios(
  userId: string,
  reportId: string
) {
  const normalizedUserId = normalizeId(userId)
  const normalizedReportId = normalizeId(reportId)

  const findings = await getScenarioFindings(normalizedUserId, normalizedReportId)
  const attackPaths = await getAttackPathsForReport(
    normalizedUserId,
    normalizedReportId,
    10
  )

  const scenarios = findings.map((finding) => {
    const attackPath = attackPaths.find(
      (path: any) => path.findingId === finding.findingId
    )

    return makeScenario(finding, attackPath)
  })

  return {
    reportId: normalizedReportId,
    scenarioCount: scenarios.length,
    model: 'graph-grounded-threat-scenario-generator',
    method:
      'Scenarios are generated from user-scoped Neo4j graph evidence, attack path prediction, CVE/CWE/OWASP/MITRE mappings, severity, and risk score.',
    scenarios,
  }
}
