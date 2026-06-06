import { buildAnalysisReport } from '@/lib/server/analysis-build'
import type { StoredFinding, StoredReport } from '@/lib/server/types'
import fs from 'node:fs/promises'
import path from 'node:path'

type Severity = 'Critical' | 'High' | 'Medium' | 'Low'

type Manifest = {
  reports: Array<{
    id: string
    vendor: string
    family: string
    sourcePath: string
    textPath: string
    expectedPath: string
  }>
}

type ExpectedReport = {
  id: string
  expectedCount: number
  expectedSeverityCounts?: Partial<Record<Severity, number>>
  negativeSections?: string[]
  notes?: string[]
}

function normalize(value: unknown) {
  return String(value ?? '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
}

function countBySeverity(findings: StoredFinding[]): Record<Severity, number> {
  return {
    Critical: findings.filter((finding) => finding.severity === 'Critical').length,
    High: findings.filter((finding) => finding.severity === 'High').length,
    Medium: findings.filter((finding) => finding.severity === 'Medium').length,
    Low: findings.filter((finding) => finding.severity === 'Low').length,
  }
}

function duplicateKey(finding: StoredFinding) {
  return normalize(
    finding.normalization?.canonicalKey ||
      `${finding.title}:${finding.asset}:${finding.cve}:${finding.severity}`
  )
}

function duplicateCount(findings: StoredFinding[]) {
  const seen = new Set<string>()
  let duplicates = 0

  for (const finding of findings) {
    const key = duplicateKey(finding)
    if (!key) continue

    if (seen.has(key)) {
      duplicates += 1
      continue
    }

    seen.add(key)
  }

  return duplicates
}
function compact(value: unknown) {
  return String(value ?? '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
}

function isNegativeHeading(value: unknown, negativeSections: string[]) {
  const text = compact(value)
  if (!text) return false

  return negativeSections.some((section) => {
    const term = compact(section)
    if (!term) return false

    // Exact heading match.
    if (text === term) return true

    // Common heading variants.
    if (text === `${term} section`) return true
    if (text === `${term} details`) return true

    // Avoid matching broad terms inside valid evidence.
    // Example: "scope was reviewed" should not fail.
    return false
  })
}

function negativeHitsForFinding(
  finding: StoredFinding,
  negativeSections: string[]
) {
  const hits: string[] = []

  const directFields = [
    finding.title,
    finding.provenance?.sourceSectionTitle,
  ]

  for (const field of directFields) {
    for (const section of negativeSections) {
      if (isNegativeHeading(field, [section])) {
        hits.push(section)
      }
    }
  }

  return hits
}




function severityCountsMatch(
  actual: Record<Severity, number>,
  expected?: Partial<Record<Severity, number>>
) {
  if (!expected) return true

  for (const severity of ['Critical', 'High', 'Medium', 'Low'] as const) {
    const expectedValue = expected[severity]
    if (expectedValue === undefined) continue
    if (actual[severity] !== expectedValue) return false
  }

  return true
}

function compactFinding(finding: StoredFinding, index: number) {
  return {
    n: index + 1,
    id: finding.id,
    severity: finding.severity,
    title: finding.title,
    asset: finding.asset,
    cve: finding.cve,
    score: finding.score,
    sourceTitle: finding.provenance?.sourceSectionTitle,
    method: finding.provenance?.extractionMethod,
    canonicalKey: finding.normalization?.canonicalKey,
  }
}

function printFailedFindings(id: string, findings: StoredFinding[]) {
  console.log(`\n--- ${id}: actual findings ---`)
  console.table(findings.map(compactFinding))
}

async function main() {
  const failMode = process.argv.includes('--fail')
  const enableNlp = process.env.ENABLE_NLP === 'true'

  const manifest = JSON.parse(
    await fs.readFile('data/golden-reports/manifest.json', 'utf8')
  ) as Manifest

  await fs.mkdir('data/golden-reports/actual', { recursive: true })

  const rows: Array<{
    id: string
    vendor: string
    expected: number
    actual: number
    countOk: boolean
    severityOk: boolean
    duplicates: number
    negativeHits: number
    pass: boolean
  }> = []

  for (const item of manifest.reports) {
    const content = await fs.readFile(item.textPath, 'utf8')
    const expected = JSON.parse(
      await fs.readFile(item.expectedPath, 'utf8')
    ) as ExpectedReport

    const result = await buildAnalysisReport({
      reportId: `G-${item.id}`,
      name: item.id,
      type: 'PDF' as StoredReport['type'],
      content,
      sourceFileName: path.basename(item.sourcePath),
      enableNlp,
    })

    const actualSeverityCounts = countBySeverity(result.findings)
    const duplicates = duplicateCount(result.findings)
    const negativeHits = result.findings.reduce((total, finding) => {
      return (
        total +
        negativeHitsForFinding(
          finding,
          expected.negativeSections ?? []
        ).length
      )
    }, 0)

    const countOk = result.findings.length === expected.expectedCount
    const severityOk = severityCountsMatch(
      actualSeverityCounts,
      expected.expectedSeverityCounts
    )

    const pass = countOk && severityOk && duplicates === 0 && negativeHits === 0

    rows.push({
      id: item.id,
      vendor: item.vendor,
      expected: expected.expectedCount,
      actual: result.findings.length,
      countOk,
      severityOk,
      duplicates,
      negativeHits,
      pass,
    })

    await fs.writeFile(
      `data/golden-reports/actual/${item.id}.json`,
      JSON.stringify(
        {
          manifest: item,
          expected,
          report: result.report,
          findings: result.findings,
          eval: {
            enableNlp,
            expectedCount: expected.expectedCount,
            actualCount: result.findings.length,
            expectedSeverityCounts: expected.expectedSeverityCounts,
            actualSeverityCounts,
            duplicates,
            negativeHits,
            pass,
          },
        },
        null,
        2
      ),
      'utf8'
    )

    if (!pass) {
      printFailedFindings(item.id, result.findings)
    }
  }

  console.log('\n=== Golden Evaluation ===')
  console.table(rows)

  const failed = rows.filter((row) => !row.pass)
  if (failed.length > 0) {
    console.log(`\nFailed reports: ${failed.length}`)
    for (const row of failed) {
      console.log(
        `- ${row.id}: expected=${row.expected}, actual=${row.actual}, duplicates=${row.duplicates}, negativeHits=${row.negativeHits}, severityOk=${row.severityOk}`
      )
    }
  } else {
    console.log('\nAll golden reports passed.')
  }

  if (failMode && failed.length > 0) {
    process.exit(1)
  }
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
