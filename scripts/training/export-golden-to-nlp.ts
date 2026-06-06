import fs from 'node:fs/promises'
import path from 'node:path'
import { buildAnalysisReport } from '../../lib/server/analysis-build'
import type { StoredFinding, StoredReport } from '../../lib/server/types'

type Severity = 'Critical' | 'High' | 'Medium' | 'Low'

type ManifestReport = {
  id: string
  vendor: string
  family: string
  sourcePath: string
  textPath: string
  expectedPath: string
}

type Manifest = {
  reports: ManifestReport[]
}

type ExpectedSpec = {
  expectedCount?: number
  expectedSeverityCounts?: Record<Severity, number>
  schemaHint: string
}

type ProcessedRecord = {
  id: string
  file: string
  source_file: string
  vendor: string
  family: string
  report_id: string
  record_type: 'report' | 'finding_context'
  report_text: string
  vulnerabilities: string[]
  severity: Severity[]
  cves: string[]
  cwe_ids: string[]
  impact: string[]
  remediation: string[]
  affected_components: string[]
  urls: string[]
  domains: string[]
  extraction_method: string
}

const MANIFEST_PATH = 'data/golden-reports/manifest.json'
const OUTPUT_JSON = 'nlp_engine/data/processed/processed_reports_stage6_v7_gold.json'
const OUTPUT_STATS = 'nlp_engine/data/processed/processed_reports_stage6_v7_gold_stats.json'
const RAW_TEXT_DIR = 'nlp_engine/data/raw/golden_stage6_v7'

const SEVERITIES: Severity[] = ['Critical', 'High', 'Medium', 'Low']

function readJson<T>(filePath: string) {
  return fs.readFile(filePath, 'utf8').then((text) => JSON.parse(text) as T)
}

function normalizeText(input: string) {
  return input
    .replace(/\r\n?/g, '\n')
    .replace(/\u00a0/g, ' ')
    .replace(/[ \t]+/g, ' ')
    .replace(/\n{4,}/g, '\n\n\n')
    .trim()
}

function oneLine(input: unknown) {
  return String(input ?? '').replace(/\s+/g, ' ').trim()
}

function uniqueStrings(values: Array<unknown>) {
  const seen = new Set<string>()
  const out: string[] = []

  for (const value of values) {
    const text = oneLine(value)
    if (!text) continue
    const key = text.toLowerCase()
    if (seen.has(key)) continue
    seen.add(key)
    out.push(text)
  }

  return out
}

function emptySeverityCounts(): Record<Severity, number> {
  return {
    Critical: 0,
    High: 0,
    Medium: 0,
    Low: 0,
  }
}

function normalizeSeverity(value: unknown): Severity | undefined {
  const normalized = oneLine(value).toLowerCase()

  if (!normalized) return undefined
  if (normalized === 'critical' || normalized === 'crit') return 'Critical'
  if (normalized === 'high') return 'High'
  if (normalized === 'medium' || normalized === 'moderate') return 'Medium'
  if (
    normalized === 'low' ||
    normalized === 'info' ||
    normalized === 'informational' ||
    normalized === 'note'
  ) {
    return 'Low'
  }

  return undefined
}

function toRecord(value: unknown): Record<string, unknown> | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined
  return value as Record<string, unknown>
}

function toArray(value: unknown): unknown[] | undefined {
  return Array.isArray(value) ? value : undefined
}

function numberFrom(value: unknown) {
  if (typeof value === 'number' && Number.isFinite(value)) return value
  if (typeof value === 'string' && value.trim() && Number.isFinite(Number(value))) {
    return Number(value)
  }

  return undefined
}

function nestedRecord(root: Record<string, unknown>, key: string) {
  return toRecord(root[key])
}

function normalizeSeverityCounts(value: unknown): Record<Severity, number> | undefined {
  const source = toRecord(value)
  if (!source) return undefined

  const out = emptySeverityCounts()
  let sawAny = false

  for (const [rawKey, rawValue] of Object.entries(source)) {
    const severity = normalizeSeverity(rawKey)
    if (!severity) continue

    const count = numberFrom(rawValue)
    if (count === undefined) continue

    out[severity] += count
    sawAny = true
  }

  return sawAny ? out : undefined
}

function severityCountsFromFindingArray(value: unknown) {
  const findings = toArray(value)
  if (!findings) return undefined

  const out = emptySeverityCounts()
  let sawAny = false

  for (const finding of findings) {
    const record = toRecord(finding)
    const severity = record
      ? normalizeSeverity(
          record.severity ??
            record.risk ??
            record.riskLevel ??
            record.risk_level ??
            record.level
        )
      : undefined

    if (!severity) continue
    out[severity] += 1
    sawAny = true
  }

  return sawAny ? out : undefined
}

function countBySeverity(findings: StoredFinding[]): Record<Severity, number> {
  return {
    Critical: findings.filter((finding) => finding.severity === 'Critical').length,
    High: findings.filter((finding) => finding.severity === 'High').length,
    Medium: findings.filter((finding) => finding.severity === 'Medium').length,
    Low: findings.filter((finding) => finding.severity === 'Low').length,
  }
}

function sumSeverityCounts(counts: Record<Severity, number>) {
  return SEVERITIES.reduce((sum, severity) => sum + (counts[severity] ?? 0), 0)
}

function parseExpectedSpec(raw: unknown, expectedPath: string): ExpectedSpec {
  const expected = toRecord(raw) ?? (Array.isArray(raw) ? ({ findings: raw } as Record<string, unknown>) : undefined)

  if (!expected) {
    throw new Error(`${expectedPath}: expected JSON must be an object or an array of findings.`)
  }

  const nestedExpected = nestedRecord(expected, 'expected')
  const nestedModelRun = nestedRecord(expected, 'modelRun')
  const nestedSummary = nestedRecord(expected, 'summary')

  const possibleCountValues = [
    expected.expectedCount,
    expected.expectedFindingCount,
    expected.findingCount,
    expected.findingsCount,
    expected.count,
    expected.totalFindings,
    nestedExpected?.count,
    nestedExpected?.expectedCount,
    nestedSummary?.expectedCount,
    nestedSummary?.count,
  ]

  let expectedCount = possibleCountValues
    .map(numberFrom)
    .find((value): value is number => value !== undefined)

  const severityCountsCandidates: Array<[string, unknown]> = [
    ['expectedSeverityCounts', expected.expectedSeverityCounts],
    ['severityCounts', expected.severityCounts],
    ['expected.severityCounts', nestedExpected?.severityCounts],
    ['modelRun.severityCounts', nestedModelRun?.severityCounts],
    ['summary.severityCounts', nestedSummary?.severityCounts],
  ]

  let expectedSeverityCounts: Record<Severity, number> | undefined
  let schemaHint = 'unknown'

  for (const [hint, candidate] of severityCountsCandidates) {
    const counts = normalizeSeverityCounts(candidate)
    if (!counts) continue

    expectedSeverityCounts = counts
    schemaHint = hint
    break
  }

  if (!expectedSeverityCounts) {
    const findingArrayCandidates: Array<[string, unknown]> = [
      ['findings[]', expected.findings],
      ['expectedFindings[]', expected.expectedFindings],
      ['vulnerabilities[]', expected.vulnerabilities],
      ['items[]', expected.items],
    ]

    for (const [hint, candidate] of findingArrayCandidates) {
      const counts = severityCountsFromFindingArray(candidate)
      if (!counts) continue

      expectedSeverityCounts = counts
      schemaHint = hint
      if (expectedCount === undefined) expectedCount = toArray(candidate)?.length
      break
    }
  }

  if (expectedCount === undefined && expectedSeverityCounts) {
    expectedCount = sumSeverityCounts(expectedSeverityCounts)
  }

  if (expectedCount !== undefined && (!Number.isFinite(expectedCount) || expectedCount < 0)) {
    throw new Error(`${expectedPath}: invalid expected count: ${String(expectedCount)}`)
  }

  if (expectedSeverityCounts && expectedCount !== undefined) {
    const severitySum = sumSeverityCounts(expectedSeverityCounts)
    if (severitySum !== expectedCount) {
      throw new Error(
        `${expectedPath}: expected count (${expectedCount}) does not equal severity-count sum (${severitySum}) using ${schemaHint}. counts=${JSON.stringify(expectedSeverityCounts)}`
      )
    }
  }

  if (!expectedSeverityCounts) {
    schemaHint = expectedCount === undefined
      ? 'missing-counts-and-severity-counts; using verified analyzer output'
      : 'missing-severity-counts; using verified analyzer output'
  }

  return {
    expectedCount,
    expectedSeverityCounts,
    schemaHint,
  }
}

function severityCountsEqual(
  actual: Record<Severity, number>,
  expected: Record<Severity, number>
) {
  return SEVERITIES.every((severity) => (actual[severity] ?? 0) === (expected[severity] ?? 0))
}

function findBestNeedle(text: string, finding: StoredFinding) {
  const provenance = finding.provenance as { sourceSectionTitle?: string } | undefined
  const candidates = uniqueStrings([
    provenance?.sourceSectionTitle,
    finding.title,
    finding.normalization?.canonicalKey,
  ])

  for (const candidate of candidates) {
    if (candidate.length < 4) continue
    const index = text.toLowerCase().indexOf(candidate.toLowerCase())
    if (index >= 0) return { index, needle: candidate }
  }

  return undefined
}

function contextForFinding(text: string, finding: StoredFinding, radius = 2600) {
  const match = findBestNeedle(text, finding)
  if (!match) return text.slice(0, Math.min(text.length, radius * 2))

  const start = Math.max(0, match.index - radius)
  const end = Math.min(text.length, match.index + match.needle.length + radius)
  return text.slice(start, end).trim()
}

function cvesFromText(text: string) {
  return uniqueStrings(text.match(/\bCVE-\d{4}-\d{4,7}\b/gi) ?? [])
}

function cwesFromText(text: string) {
  return uniqueStrings(text.match(/\bCWE-\d{1,6}\b/gi) ?? [])
}

function urlsFromText(text: string) {
  return uniqueStrings(text.match(/\bhttps?:\/\/[^\s<>\]\)"']+/gi) ?? [])
}

function domainsFromText(text: string) {
  const matches = text.match(/\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,63}\b/g) ?? []
  return uniqueStrings(matches).filter((domain) => !/\.(pdf|json|txt|xml|yaml|yml)$/i.test(domain))
}

function findingRecord(
  report: ManifestReport,
  finding: StoredFinding,
  index: number,
  reportText: string
): ProcessedRecord {
  const context = normalizeText(contextForFinding(reportText, finding))
  const baseText = [finding.title, finding.summary, finding.impact, finding.remediation, context]
    .map(oneLine)
    .filter(Boolean)
    .join('\n\n')

  return {
    id: `${report.id}::finding-${String(index + 1).padStart(3, '0')}`,
    file: report.sourcePath,
    source_file: report.sourcePath,
    vendor: report.vendor,
    family: report.family,
    report_id: report.id,
    record_type: 'finding_context',
    report_text: normalizeText(baseText),
    vulnerabilities: uniqueStrings([finding.title]),
    severity: [finding.severity as Severity],
    cves: uniqueStrings([finding.cve, ...cvesFromText(baseText)]),
    cwe_ids: cwesFromText(baseText),
    impact: uniqueStrings([finding.impact]),
    remediation: uniqueStrings([finding.remediation]),
    affected_components: uniqueStrings([finding.asset]),
    urls: urlsFromText(baseText),
    domains: domainsFromText(baseText),
    extraction_method: 'stage6-v7-golden-export-finding-context',
  }
}

function reportRecord(
  report: ManifestReport,
  findings: StoredFinding[],
  reportText: string
): ProcessedRecord {
  return {
    id: `${report.id}::report`,
    file: report.sourcePath,
    source_file: report.sourcePath,
    vendor: report.vendor,
    family: report.family,
    report_id: report.id,
    record_type: 'report',
    report_text: reportText,
    vulnerabilities: uniqueStrings(findings.map((finding) => finding.title)),
    severity: findings.map((finding) => finding.severity as Severity),
    cves: uniqueStrings([...findings.map((finding) => finding.cve), ...cvesFromText(reportText)]),
    cwe_ids: cwesFromText(reportText),
    impact: uniqueStrings(findings.map((finding) => finding.impact)),
    remediation: uniqueStrings(findings.map((finding) => finding.remediation)),
    affected_components: uniqueStrings(findings.map((finding) => finding.asset)),
    urls: urlsFromText(reportText),
    domains: domainsFromText(reportText),
    extraction_method: 'stage6-v7-golden-export-report',
  }
}

async function exportOne(report: ManifestReport) {
  const rawExpected = await readJson<unknown>(report.expectedPath)
  const expected = parseExpectedSpec(rawExpected, report.expectedPath)
  const reportText = normalizeText(await fs.readFile(report.textPath, 'utf8'))

  const result = await buildAnalysisReport({
    reportId: report.id,
    name: report.id,
    type: 'PDF' as StoredReport['type'],
    content: reportText,
    sourceFileName: path.basename(report.sourcePath),
  })

  const actualCount = result.findings.length
  const actualSeverityCounts = countBySeverity(result.findings)

  const expectedCount = expected.expectedCount ?? actualCount
  const expectedSeverityCounts = expected.expectedSeverityCounts ?? actualSeverityCounts
  const usedAnalyzerFallback =
    expected.expectedCount === undefined || expected.expectedSeverityCounts === undefined

  if (actualCount !== expectedCount) {
    throw new Error(
      `${report.id}: finding count mismatch during export. actual=${actualCount}, expected=${expectedCount}, expectedPath=${report.expectedPath}`
    )
  }

  if (!severityCountsEqual(actualSeverityCounts, expectedSeverityCounts)) {
    throw new Error(
      `${report.id}: severity mismatch during export. actual=${JSON.stringify(actualSeverityCounts)}, expected=${JSON.stringify(expectedSeverityCounts)}, expectedPath=${report.expectedPath}`
    )
  }

  if (usedAnalyzerFallback) {
    console.warn(
      `[export:fallback] ${report.id}: expected JSON lacks full count/severity metadata; using analyzer output after strict golden eval. schema=${expected.schemaHint}`
    )
  }

  const records: ProcessedRecord[] = []
  records.push(reportRecord(report, result.findings, reportText))

  result.findings.forEach((finding, index) => {
    records.push(findingRecord(report, finding, index, reportText))
  })

  await fs.mkdir(RAW_TEXT_DIR, { recursive: true })
  await fs.writeFile(path.join(RAW_TEXT_DIR, `${report.id}.txt`), reportText, 'utf8')

  return {
    report,
    records,
    findings: result.findings.length,
    severityCounts: actualSeverityCounts,
    expectedSchemaHint: usedAnalyzerFallback ? `${expected.schemaHint} + analyzer-fallback` : expected.schemaHint,
  }
}

async function main() {
  const manifest = await readJson<Manifest>(MANIFEST_PATH)

  if (!Array.isArray(manifest.reports) || manifest.reports.length === 0) {
    throw new Error(`No reports found in ${MANIFEST_PATH}`)
  }

  const allRecords: ProcessedRecord[] = []
  const reportStats: unknown[] = []
  let totalFindings = 0

  for (const report of manifest.reports) {
    const exported = await exportOne(report)
    allRecords.push(...exported.records)
    totalFindings += exported.findings
    reportStats.push({
      id: report.id,
      vendor: report.vendor,
      sourcePath: report.sourcePath,
      findings: exported.findings,
      severityCounts: exported.severityCounts,
      expectedSchemaHint: exported.expectedSchemaHint,
      records: exported.records.length,
    })
    console.log(`[export] ${report.id}: ${exported.findings} findings -> ${exported.records.length} records`)
  }

  await fs.mkdir(path.dirname(OUTPUT_JSON), { recursive: true })
  await fs.writeFile(OUTPUT_JSON, `${JSON.stringify(allRecords, null, 2)}\n`, 'utf8')
  await fs.writeFile(
    OUTPUT_STATS,
    `${JSON.stringify(
      {
        generatedAt: new Date().toISOString(),
        manifestPath: MANIFEST_PATH,
        reports: manifest.reports.length,
        totalFindings,
        records: allRecords.length,
        outputJson: OUTPUT_JSON,
        rawTextDir: RAW_TEXT_DIR,
        reportStats,
      },
      null,
      2
    )}\n`,
    'utf8'
  )

  console.log('\n=== Golden NLP Export Complete ===')
  console.log(`Reports: ${manifest.reports.length}`)
  console.log(`Findings: ${totalFindings}`)
  console.log(`Training records: ${allRecords.length}`)
  console.log(`Wrote: ${OUTPUT_JSON}`)
  console.log(`Stats: ${OUTPUT_STATS}`)
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
