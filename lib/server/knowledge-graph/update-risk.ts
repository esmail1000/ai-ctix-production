import type { ReportRiskResult } from '@/lib/server/risk-scoring'
import { runCypher } from './neo4j'

function normalizeId(value: string | undefined | null): string {
  return String(value ?? '').trim()
}

export async function updateKnowledgeGraphRiskScores(input: {
  userId: string
  reportId: string
  risk: ReportRiskResult
}) {
  const userId = normalizeId(input.userId)
  const reportId = normalizeId(input.reportId)

  if (!userId || !reportId) {
    return {
      ok: false,
      reportId,
      updated: 0,
      error: 'Missing userId or reportId.',
    }
  }

  const findings = input.risk.allFindings.map((finding) => ({
    findingId: finding.findingId,
    originalScore: finding.originalScore,
    finalRiskScore: finding.finalRiskScore ?? finding.riskScore,
    riskBand: finding.riskBand,
    reportCvss: finding.reportCvss ?? null,
    intelCvss: finding.intelCvss ?? null,
    intelCvssSeverity: finding.intelCvssSeverity ?? null,
    knownExploited: Boolean(finding.knownExploited),
    cisaKev: Boolean(finding.cisaKev),
    exploitAvailable: Boolean(finding.exploitAvailable),
    attackVector: finding.attackVector ?? null,
    riskFactors: finding.riskFactors ?? finding.rationale ?? [],
    recommendations: finding.recommendations ?? [],
    riskModelVersion: finding.riskModelVersion ?? null,
  }))

  if (findings.length === 0) {
    return { ok: true, reportId, updated: 0 }
  }

  const records = await runCypher(
    `
    UNWIND $findings AS item
    MATCH (f:Finding {id: item.findingId, userId: $userId, reportId: $reportId})
    SET f.baseRiskScore = item.originalScore,
        f.riskScore = item.finalRiskScore,
        f.finalRiskScore = item.finalRiskScore,
        f.riskBand = item.riskBand,
        f.reportCvss = item.reportCvss,
        f.intelCvss = item.intelCvss,
        f.intelCvssSeverity = item.intelCvssSeverity,
        f.knownExploited = item.knownExploited,
        f.cisaKev = item.cisaKev,
        f.exploitAvailable = item.exploitAvailable,
        f.attackVector = item.attackVector,
        f.riskFactors = item.riskFactors,
        f.recommendations = item.recommendations,
        f.riskModelVersion = item.riskModelVersion,
        f.riskUpdatedAt = datetime()
    RETURN count(f) AS updated
    `,
    {
      userId,
      reportId,
      findings,
    }
  )

  const updatedValue = records[0]?.get('updated')
  const updated =
    updatedValue && typeof updatedValue.toNumber === 'function'
      ? updatedValue.toNumber()
      : Number(updatedValue ?? 0)

  return {
    ok: true,
    reportId,
    updated: Number.isFinite(updated) ? updated : 0,
  }
}
