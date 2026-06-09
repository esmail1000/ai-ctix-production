// lib/server/pipeline/post-analysis.ts

import { generateReportRisk } from '@/lib/server/ai-risk-scoring'
import { generateReportSummary } from '@/lib/server/ai-summarization'
import {
  saveAnalysisRiskScoreForUser,
  saveAnalysisSummaryForUser,
} from '@/lib/server/analysis-repository'
import { getAttackPathsForReport } from '@/lib/server/knowledge-graph/attack-path'
import { buildKnowledgeGraphFromAnalysis } from '@/lib/server/knowledge-graph/build-graph'
import { updateKnowledgeGraphRiskScores } from '@/lib/server/knowledge-graph/update-risk'
import { generateThreatScenarios } from '@/lib/server/llm-analysis/threat-scenarios'
import { applyRiskToFindings } from '@/lib/server/threat-aware-risk'
import { enrichReportThreatIntel } from '@/lib/server/threat-intel/enrich-report'

function unique(values: Array<string | undefined | null>) {
  return Array.from(
    new Set(
      values
        .filter(Boolean)
        .map((value) => String(value).trim())
        .filter(Boolean)
    )
  )
}

function splitDelimitedValues(value: unknown): string[] {
  if (Array.isArray(value)) {
    return unique(value.map((item) => String(item)))
  }

  return String(value ?? '')
    .split(/[;,|]/g)
    .map((item) => item.trim())
    .filter(Boolean)
}

function extractCves(text: string) {
  return unique(text.match(/\bCVE-\d{4}-\d{4,7}\b/gi) ?? []).map((cve) =>
    cve.toUpperCase()
  )
}

function extractUrls(text: string): string[] {
  return unique(text.match(/https?:\/\/[^\s|,;"'<>]+/gi) ?? [])
}

function extractIps(text: string): string[] {
  return unique(
    text.match(/\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/g) ?? []
  )
}

function extractDomains(text: string): string[] {
  const urls = extractUrls(text)
  const fromUrls = urls
    .map((url) => {
      try {
        return new URL(url).hostname
      } catch {
        return ''
      }
    })
    .filter(Boolean)

  const labelled = extractLabelledValues(text, ['Domains', 'Domain'])

  return unique([...fromUrls, ...labelled]).filter(
    (domain) => !/^\d+\.\d+\.\d+\.\d+$/.test(domain)
  )
}

function extractPorts(text: string): string[] {
  const labelled = extractLabelledValues(text, ['Ports', 'Port'])
  const inline = text.match(/\bport\s*:?\s*(\d{1,5})\b/gi) ?? []

  return unique([
    ...labelled,
    ...inline.map((value) => value.replace(/\D+/g, '')),
  ]).filter((port) => {
    const parsed = Number(port)
    return Number.isInteger(parsed) && parsed > 0 && parsed <= 65535
  })
}

function extractLabelledValues(text: string, labels: string[]): string[] {
  const output: string[] = []

  for (const label of labels) {
    const pattern = new RegExp(`${label}\\s*:\\s*([^|\\n\\r]+)`, 'gi')
    let match: RegExpExecArray | null

    while ((match = pattern.exec(text))) {
      output.push(
        ...String(match[1] ?? '')
          .split(/[,;]/g)
          .map((item) => item.trim())
          .filter(Boolean)
      )
    }
  }

  return unique(output)
}

function extractIndicatorsFromFinding(finding: any, fullText: string) {
  const indicators: Array<{
    type: 'URL' | 'Domain' | 'IP' | 'Port' | 'Service' | 'Endpoint'
    value: string
    source: 'report-extracted'
    confidence: number
  }> = []

  for (const value of extractUrls(fullText)) {
    indicators.push({ type: 'URL', value, source: 'report-extracted', confidence: 90 })
  }

  for (const value of extractDomains(fullText)) {
    indicators.push({ type: 'Domain', value, source: 'report-extracted', confidence: 86 })
  }

  for (const value of extractIps(fullText)) {
    indicators.push({ type: 'IP', value, source: 'report-extracted', confidence: 90 })
  }

  for (const value of extractPorts(fullText)) {
    indicators.push({ type: 'Port', value, source: 'report-extracted', confidence: 84 })
  }

  for (const value of extractLabelledValues(fullText, ['Services', 'Service'])) {
    indicators.push({ type: 'Service', value, source: 'report-extracted', confidence: 82 })
  }

  for (const value of extractLabelledValues(fullText, ['Endpoints', 'Endpoint'])) {
    indicators.push({ type: 'Endpoint', value, source: 'report-extracted', confidence: 82 })
  }

  if (String(finding.asset ?? '').startsWith('/')) {
    indicators.push({
      type: 'Endpoint',
      value: String(finding.asset),
      source: 'report-extracted',
      confidence: 82,
    })
  }

  return indicators
}

function buildSummaryMeta(summary: any) {
  return {
    generatedAtIso: summary.generatedAtIso,
    confidence: summary.confidence,
    grounding: summary.grounding,
    totalFindings: summary.stats?.totalFindings,
    openFindings: summary.stats?.openCount,
    distinctAssets: summary.stats?.distinctAssets,
  }
}

function buildRiskMeta(risk: any) {
  return {
    generatedAtIso: risk.generatedAtIso,
    overallRiskScore: risk.overallRiskScore,
    overallRiskBand: risk.overallRiskBand,
    totalFindings: risk.stats?.totalFindings,
    openFindings: risk.stats?.openFindings,
    findingsWithCve: risk.stats?.findingsWithCve,
    distinctAssets: risk.stats?.distinctAssets,
    riskModelVersion: risk.allFindings?.[0]?.riskModelVersion ?? null,
  }
}

function toGraphFinding(finding: any) {
  const title = String(finding.title ?? finding.id ?? 'Untitled finding')
  const description = String(
    finding.description ?? finding.summary ?? finding.evidence ?? ''
  )

  const exploitationSteps = Array.isArray(finding.exploitationSteps)
    ? finding.exploitationSteps
    : Array.isArray(finding.reported?.exploitationSteps)
      ? finding.reported.exploitationSteps
      : []

  const fullText = [
    title,
    description,
    finding.cve,
    finding.cwe,
    finding.impact,
    finding.evidence,
    finding.remediation,
    exploitationSteps.join(' '),
    Array.isArray(finding.recommendations) ? finding.recommendations.join(' ') : '',
  ]
    .filter(Boolean)
    .join(' ')

  const score =
    typeof finding.finalRiskScore === 'number'
      ? finding.finalRiskScore
      : typeof finding.score === 'number'
        ? finding.score
        : Number(finding.riskScore ?? 0)

  return {
    id: finding.id,
    title,
    description,
    severity: finding.severity,
    riskScore: Number.isFinite(score) ? score : 0,
    asset: finding.asset,
    assets: unique([
      finding.asset,
      ...(Array.isArray(finding.assets) ? finding.assets : []),
    ]),
    cves: unique([
      ...splitDelimitedValues(finding.cve),
      ...(Array.isArray(finding.cves) ? finding.cves : []),
      ...extractCves(fullText),
    ]).map((cve) => cve.toUpperCase()),
    cwes: unique([
      ...splitDelimitedValues(finding.cwe),
      ...(Array.isArray(finding.cwes) ? finding.cwes : []),
    ]),
    owasp: Array.isArray(finding.owasp) ? finding.owasp : [],
    mitreTechniques: Array.isArray(finding.mitreTechniques)
      ? finding.mitreTechniques
      : [],
    impacts: unique([
      ...splitDelimitedValues(finding.impact),
      ...(Array.isArray(finding.impacts) ? finding.impacts : []),
    ]),
    remediations: unique([
      finding.remediation,
      ...(Array.isArray(finding.remediations) ? finding.remediations : []),
      ...(Array.isArray(finding.recommendations) ? finding.recommendations : []),
    ]),
    exploits: unique([
      ...(Array.isArray(finding.exploits) ? finding.exploits : []),
      ...exploitationSteps,
    ]),
    indicators: extractIndicatorsFromFinding(finding, fullText),
  }
}

export async function runPostAnalysisPipeline(result: any, userId: string) {
  const reportId = result.report.id

  const status: any = {
    reportId,
    graph: null,
    threatIntel: null,
    riskScoring: null,
    graphRiskUpdate: null,
    attackPaths: null,
    threatScenarios: null,
  }

  try {
    status.graph = await buildKnowledgeGraphFromAnalysis({
      userId,
      reportId: result.report.id,
      reportName: result.report.name,
      sourceFileName: result.report.sourceFileName,
      findings: result.findings.map(toGraphFinding),
    })
  } catch (error) {
    status.graph = {
      ok: false,
      error: error instanceof Error ? error.message : String(error),
    }
  }

  try {
    status.threatIntel = await enrichReportThreatIntel(reportId, {
      userId,
      fallbackCves: result.findings
        .flatMap((finding: any) => {
          const text = JSON.stringify(finding ?? '') ?? ''
          return text.match(/CVE-\d{4}-\d{4,}/gi) ?? []
        })
        .map((cve: string) => cve.toUpperCase()),
    })
  } catch (error) {
    status.threatIntel = {
      ok: false,
      error: error instanceof Error ? error.message : String(error),
    }
  }

  try {
    const summary = await generateReportSummary(result.report, result.findings)
    const risk = await generateReportRisk(result.report, result.findings, summary, {
      threatIntel: Array.isArray(status.threatIntel?.results) ? status.threatIntel : null,
    })

    result.findings = applyRiskToFindings(result.findings, risk)

    await saveAnalysisSummaryForUser({
      userId,
      reportId,
      summary,
      summaryMeta: buildSummaryMeta(summary),
    })

    await saveAnalysisRiskScoreForUser({
      userId,
      reportId,
      risk,
      riskMeta: buildRiskMeta(risk),
    })

    status.riskScoring = {
      ok: true,
      reportId,
      overallRiskScore: risk.overallRiskScore,
      overallRiskBand: risk.overallRiskBand,
      riskModelVersion: risk.allFindings[0]?.riskModelVersion ?? null,
      allFindings: risk.allFindings,
    }

    status.graphRiskUpdate = await updateKnowledgeGraphRiskScores({
      userId,
      reportId,
      risk,
    })
  } catch (error) {
    status.riskScoring = {
      ok: false,
      error: error instanceof Error ? error.message : String(error),
    }
  }

  try {
    const paths = await getAttackPathsForReport(userId, reportId, 10)

    status.attackPaths = {
      ok: true,
      count: paths.length,
      paths,
    }
  } catch (error) {
    status.attackPaths = {
      ok: false,
      error: error instanceof Error ? error.message : String(error),
    }
  }

  try {
    const scenarios = await generateThreatScenarios(userId, reportId)

    status.threatScenarios = {
      ok: true,
      count: scenarios.scenarioCount,
      scenarios: scenarios.scenarios,
    }
  } catch (error) {
    status.threatScenarios = {
      ok: false,
      error: error instanceof Error ? error.message : String(error),
    }
  }

  return status
}
