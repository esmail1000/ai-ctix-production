import { getAttackPathsForReport } from '@/lib/server/knowledge-graph/attack-path'
import { buildKnowledgeGraphFromAnalysis } from '@/lib/server/knowledge-graph/build-graph'
import { generateThreatScenarios } from '@/lib/server/llm-analysis/threat-scenarios'
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
  return unique(text.match(/CVE-\d{4}-\d{4,7}/gi) ?? []).map((cve) =>
    cve.toUpperCase()
  )
}

function toGraphFinding(finding: any) {
  const title = String(finding.title ?? finding.id ?? 'Untitled finding')
  const description = String(
    finding.description ?? finding.summary ?? finding.evidence ?? ''
  )

  const fullText = [
    title,
    description,
    finding.cve,
    finding.impact,
    finding.evidence,
    finding.remediation,
  ]
    .filter(Boolean)
    .join(' ')

  const score =
    typeof finding.score === 'number'
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
      ...splitDelimitedValues(finding.remediation),
      ...(Array.isArray(finding.remediations) ? finding.remediations : []),
    ]),
    exploits: Array.isArray(finding.exploits) ? finding.exploits : [],
  }
}

export async function runPostAnalysisPipeline(result: any) {
  const reportId = result.report.id

  const status: any = {
    reportId,
    graph: null,
    threatIntel: null,
    attackPaths: null,
    threatScenarios: null,
  }

  try {
    status.graph = await buildKnowledgeGraphFromAnalysis({
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
    status.threatIntel = await enrichReportThreatIntel(reportId)
  } catch (error) {
    status.threatIntel = {
      ok: false,
      error: error instanceof Error ? error.message : String(error),
    }
  }

  try {
    const paths = await getAttackPathsForReport(reportId, 10)

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
    const scenarios = await generateThreatScenarios(reportId)

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
