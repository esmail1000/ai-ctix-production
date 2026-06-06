import { spawnSync } from 'node:child_process'
import crypto from 'node:crypto'
import fs from 'node:fs/promises'
import { createRequire } from 'node:module'
import path from 'node:path'
import { buildAnalysisReport } from '../../lib/server/analysis-build'
import type { StoredFinding, StoredReport } from '../../lib/server/types'

const require = createRequire(import.meta.url)

const HELD_REVIEW_SOURCE_PATHS = [
  // Not vulnerability-finding reports.
  'Bishop Fox/Bishop-Fox-Research-Report-Efficacy-of-micro-segmentation-V01.pdf',
  'Bishop Fox/stj_expert_witness_report.pdf',

  // No severity-rated findings in the extracted text; keep for manual/OCR follow-up.
  'Consensys/Diligence/vyper-audit-2019-10.pdf',

  // Not a report.
  'CPTC/2019/letter to competitors.pdf',

  // CPTC reports are scanned/poor text extraction in the current pipeline.
  // Keep them out of normal batches until an OCR stage is added.
  'CPTC/2019/nationalsC-report-redacted.pdf',
  'CPTC/2019/nationalsD-report-redacted.pdf',
  'CPTC/2019/nationalsE-report-redacted.pdf',
  'CPTC/2019/nationalsF-report-redacted.pdf',
  'CPTC/2019/nationalsH-report-redacted.pdf',
  'CPTC/2019/nationalsI-report-redacted.pdf',
  'CPTC/2020/Finals-A-report-redacted.pdf',
  'CPTC/2020/Finals-B-report-redacted.pdf',
  'CPTC/2020/Finals-C-report-redacted.pdf',
  'CPTC/2020/Finals-D-report-redacted.pdf',
  'CPTC/2020/Finals-E-report-redacted.pdf',
  'CPTC/2020/Finals-F-report-redacted.pdf',
  'CPTC/2020/Finals-G-report-redacted.pdf',
] as const

const HELD_REVIEW_SOURCE_PREFIXES = [
  // CPTC PDFs in the public corpus are mostly scanned/image-only in the
  // current text-extraction pipeline. Keep them for a dedicated OCR stage.
  'CPTC/',

  // These are cryptographic white papers/statements, not vulnerability
  // finding reports. They can trigger low-confidence NLP-only false positives.
  'Cryptography Research/',
] as const

const KNOWN_GOLDEN_SOURCE_ALIASES = [
  // These PDFs are already represented by older golden manifest entries whose
  // sourcePath values do not exactly match the current public-corpus paths.
  // Keep them out of normal review batches to avoid duplicate golden reports.
  'Cure53/Cure53-1PW17-report.pdf',
  'Cure53/Cure53-1PW18-report.pdf',
  'Cure53/HLM-01-report.pdf',
] as const

function normalizeCorpusPath(input: string) {
  return input.replace(/\\/g, '/').toLowerCase()
}

const HELD_REVIEW_SOURCE_PATH_SET = new Set(
  HELD_REVIEW_SOURCE_PATHS.map(normalizeCorpusPath)
)

const HELD_REVIEW_SOURCE_PREFIXES_NORMALIZED = HELD_REVIEW_SOURCE_PREFIXES.map(
  normalizeCorpusPath
)

const KNOWN_GOLDEN_SOURCE_ALIAS_SET = new Set(
  KNOWN_GOLDEN_SOURCE_ALIASES.map(normalizeCorpusPath)
)

function isKnownGoldenSourceAlias(relativePath: string) {
  return KNOWN_GOLDEN_SOURCE_ALIAS_SET.has(normalizeCorpusPath(relativePath))
}

function isHeldReviewSourcePath(relativePath: string) {
  const normalizedRelativePath = normalizeCorpusPath(relativePath)

  return (
    HELD_REVIEW_SOURCE_PATH_SET.has(normalizedRelativePath) ||
    HELD_REVIEW_SOURCE_PREFIXES_NORMALIZED.some((prefix) =>
      normalizedRelativePath.startsWith(prefix)
    )
  )
}

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

type ReviewQueueItem = {
  id: string
  sourcePath: string
  absolutePath: string
  fileName: string
  vendorGuess: string
  textPath: string
  reviewPath: string
  status: 'ready_for_review' | 'needs_attention'
  textChars: number
  actualFindings: number
  severityCounts: Record<Severity, number>
  warnings: string[]
}

function parseArgs() {
  const args = process.argv.slice(2)

  const getValue = (name: string) => {
    const prefix = `--${name}=`
    const direct = args.find((arg) => arg.startsWith(prefix))
    if (direct) return direct.slice(prefix.length)

    const index = args.indexOf(`--${name}`)
    if (index >= 0) return args[index + 1]

    return undefined
  }

  const hasFlag = (name: string) => args.includes(`--${name}`)

  return {
    limit: Number(getValue('limit') ?? process.env.REVIEW_LIMIT ?? 10),
    vendor: getValue('vendor') ?? process.env.REVIEW_VENDOR,
    includeKnownGolden: hasFlag('include-known-golden'),
    includeHeld:
      hasFlag('include-held') || process.env.REVIEW_INCLUDE_HELD === 'true',
    maxMb: Number(getValue('max-mb') ?? process.env.REVIEW_MAX_MB ?? 25),
  }
}

function slugify(input: string) {
  const cleaned = input
    .replace(/\\/g, '/')
    .replace(/\.pdf$/i, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 90)

  const hash = crypto.createHash('sha1').update(input).digest('hex').slice(0, 8)
  return `${cleaned || 'report'}-${hash}`
}

function vendorGuessFromRelativePath(relativePath: string) {
  const firstPart = relativePath.replace(/\\/g, '/').split('/')[0]
  return firstPart || 'unknown'
}

async function pathExists(filePath: string) {
  try {
    await fs.access(filePath)
    return true
  } catch {
    return false
  }
}

async function walkPdfFiles(dir: string): Promise<string[]> {
  const entries = await fs.readdir(dir, { withFileTypes: true })
  const files: string[] = []

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name)

    if (entry.isDirectory()) {
      if (
        entry.name === '.git' ||
        entry.name === 'node_modules' ||
        entry.name === '__MACOSX'
      ) {
        continue
      }

      files.push(...(await walkPdfFiles(fullPath)))
      continue
    }

    if (entry.isFile() && entry.name.toLowerCase().endsWith('.pdf')) {
      files.push(fullPath)
    }
  }

  return files
}

function runPdfMiner(command: string, pdfPath: string) {
  const result = spawnSync(command, ['-m', 'pdfminer.high_level', pdfPath], {
    encoding: 'utf8',
    maxBuffer: 1024 * 1024 * 120,
    windowsHide: true,
  })

  if (result.status !== 0 || !result.stdout?.trim()) {
    return undefined
  }

  return result.stdout
}

async function extractWithPdfParse(pdfPath: string) {
  const pdfParseModule = require('pdf-parse')
  const buffer = await fs.readFile(pdfPath)

  const parser =
    typeof pdfParseModule === 'function'
      ? pdfParseModule
      : typeof pdfParseModule.default === 'function'
        ? pdfParseModule.default
        : typeof pdfParseModule.pdfParse === 'function'
          ? pdfParseModule.pdfParse
          : undefined

  if (parser) {
    const parsed = await parser(buffer)
    return String(parsed?.text ?? '')
  }

  const PdfParseClass =
    pdfParseModule.PDFParse ??
    pdfParseModule.default?.PDFParse

  if (typeof PdfParseClass === 'function') {
    const instance = new PdfParseClass({ data: buffer })

    try {
      const parsed = await instance.getText()
      return String(parsed?.text ?? parsed ?? '')
    } finally {
      await instance.destroy?.()
    }
  }

  throw new Error(
    'Unsupported pdf-parse export shape. Install pdf-parse v1 or keep pdfminer available.'
  )
}

async function extractPdfText(pdfPath: string) {
  let method: 'pdfminer' | 'pdf-parse' = 'pdfminer'
  let text =
    runPdfMiner('python', pdfPath) ??
    runPdfMiner('py', pdfPath) ??
    runPdfMiner('python3', pdfPath)

  if (!text) {
    method = 'pdf-parse'
    text = await extractWithPdfParse(pdfPath)
  }

  return {
    method,
    text: text
      .replace(/\r\n?/g, '\n')
      .replace(/\u00a0/g, ' ')
      .replace(/[ \t]+/g, ' ')
      .replace(/\n{4,}/g, '\n\n\n')
      .trim(),
  }
}

function countBySeverity(findings: StoredFinding[]): Record<Severity, number> {
  return {
    Critical: findings.filter((finding) => finding.severity === 'Critical').length,
    High: findings.filter((finding) => finding.severity === 'High').length,
    Medium: findings.filter((finding) => finding.severity === 'Medium').length,
    Low: findings.filter((finding) => finding.severity === 'Low').length,
  }
}

function simplifyFinding(finding: StoredFinding) {
  const provenance = finding.provenance as
    | {
        method?: string
        sourceSectionTitle?: string
      }
    | undefined

  return {
    id: finding.id,
    title: finding.title,
    severity: finding.severity,
    asset: finding.asset,
    cve: finding.cve,
    score: finding.score,
    status: finding.status,
    summary: finding.summary,
    impact: finding.impact,
    remediation: finding.remediation,
    method: provenance?.method ?? 'unknown',
    sourceSectionTitle: provenance?.sourceSectionTitle,
    canonicalKey: finding.normalization?.canonicalKey,
  }
}

function isLowConfidenceNlpOnlyFinding(finding: StoredFinding) {
  const provenance = finding.provenance as
    | {
        method?: string
        sourceSectionTitle?: string
      }
    | undefined

  return (
    finding.title === 'NLP Security Finding' &&
    !provenance?.sourceSectionTitle
  )
}

function hasLowConfidenceNlpOnlyOutput(
  findings: StoredFinding[],
  warnings: string[]
) {
  if (findings.length === 0) return false

  const parserFoundNoBlocks = warnings.some((warning) =>
    /structured parser found no blocks/i.test(warning)
  )

  return parserFoundNoBlocks && findings.every(isLowConfidenceNlpOnlyFinding)
}

async function readManifestKnownSources() {
  const manifestPath = 'data/golden-reports/manifest.json'

  if (!(await pathExists(manifestPath))) {
    return new Set<string>()
  }

  const manifest = JSON.parse(
    await fs.readFile(manifestPath, 'utf8')
  ) as Manifest

  return new Set(
    manifest.reports.map((report) =>
      report.sourcePath.replace(/\\/g, '/').toLowerCase()
    )
  )
}

async function main() {
  const args = parseArgs()

  if (!Number.isFinite(args.limit) || args.limit <= 0) {
    throw new Error('Invalid --limit value.')
  }

  if (!Number.isFinite(args.maxMb) || args.maxMb <= 0) {
    throw new Error('Invalid --max-mb value.')
  }

  const corpusRoot =
    process.env.PUBLIC_REPORT_CORPUS_DIR ??
    'data/public-report-corpus/public-pentesting-reports'

  const absoluteCorpusRoot = path.resolve(corpusRoot)

  if (!(await pathExists(absoluteCorpusRoot))) {
    throw new Error(
      `PUBLIC_REPORT_CORPUS_DIR does not exist: ${absoluteCorpusRoot}`
    )
  }

  const knownGoldenSources = await readManifestKnownSources()
  const allPdfFiles = await walkPdfFiles(absoluteCorpusRoot)
  let skippedHeldReports = 0

  const candidates: Array<{
    absolutePath: string
    relativePath: string
    fileName: string
    vendorGuess: string
    sizeMb: number
  }> = []

  for (const absolutePath of allPdfFiles) {
    const stat = await fs.stat(absolutePath)
    const sizeMb = stat.size / 1024 / 1024

    if (sizeMb > args.maxMb) continue

    const relativePath = path
      .relative(absoluteCorpusRoot, absolutePath)
      .replace(/\\/g, '/')

    const normalizedRelativePath = normalizeCorpusPath(relativePath)

    if (
      !args.includeKnownGolden &&
      (knownGoldenSources.has(normalizedRelativePath) ||
        isKnownGoldenSourceAlias(relativePath))
    ) {
      continue
    }

    if (!args.includeHeld && isHeldReviewSourcePath(relativePath)) {
      skippedHeldReports += 1
      continue
    }

    const vendorGuess = vendorGuessFromRelativePath(relativePath)

    if (
      args.vendor &&
      !relativePath.toLowerCase().includes(args.vendor.toLowerCase())
    ) {
      continue
    }

    candidates.push({
      absolutePath,
      relativePath,
      fileName: path.basename(absolutePath),
      vendorGuess,
      sizeMb,
    })
  }

  candidates.sort((a, b) => a.relativePath.localeCompare(b.relativePath))

  const selected = candidates.slice(0, args.limit)

  await fs.mkdir('data/golden-reports/review-queue', { recursive: true })
  await fs.mkdir('data/golden-reports/review-queue-text', { recursive: true })

  const indexItems: ReviewQueueItem[] = []

  for (const candidate of selected) {
    const id = slugify(candidate.relativePath)

    console.log(`\n[review] ${candidate.relativePath}`)

    const extracted = await extractPdfText(candidate.absolutePath)
    const textPath = `data/golden-reports/review-queue-text/${id}.txt`
    const reviewPath = `data/golden-reports/review-queue/${id}.json`

    await fs.writeFile(textPath, extracted.text, 'utf8')

    const result = await buildAnalysisReport({
      reportId: `Q-${id}`,
      name: id,
      type: 'PDF' as StoredReport['type'],
      content: extracted.text,
      sourceFileName: candidate.fileName,
    })

    const severityCounts = countBySeverity(result.findings)
    const warnings = (result.report.parsingNotes ?? [])
      .filter(Boolean)
      .map(String)

    const modelUnavailable = warnings.some((warning) =>
      /model unavailable|regex-only fallback/i.test(warning)
    )

    const lowConfidenceNlpOnly = hasLowConfidenceNlpOnlyOutput(
      result.findings,
      warnings
    )

    const status: ReviewQueueItem['status'] =
      modelUnavailable ||
      lowConfidenceNlpOnly ||
      result.findings.length === 0 ||
      extracted.text.length <= 1000
        ? 'needs_attention'
        : 'ready_for_review'

    const reviewFile = {
      id,
      status,
      source: {
        sourcePath: candidate.relativePath,
        absolutePath: candidate.absolutePath,
        fileName: candidate.fileName,
        vendorGuess: candidate.vendorGuess,
        sizeMb: Number(candidate.sizeMb.toFixed(2)),
        extractionMethod: extracted.method,
        textPath,
      },
      modelRun: {
        enableNlp: process.env.ENABLE_NLP === 'true',
        actualFindings: result.findings.length,
        severityCounts,
        warnings,
      },
      reviewChecklist: {
        expectedCount: null,
        expectedSeverityCounts: {
          Critical: null,
          High: null,
          Medium: null,
          Low: null,
        },
        reviewerNotes: [],
        promoteToGolden: false,
        promoteToTraining: false,
        rejectedReason: null,
      },
      findings: result.findings.map(simplifyFinding),
    }

    await fs.writeFile(reviewPath, JSON.stringify(reviewFile, null, 2), 'utf8')

    indexItems.push({
      id,
      sourcePath: candidate.relativePath,
      absolutePath: candidate.absolutePath,
      fileName: candidate.fileName,
      vendorGuess: candidate.vendorGuess,
      textPath,
      reviewPath,
      status,
      textChars: extracted.text.length,
      actualFindings: result.findings.length,
      severityCounts,
      warnings,
    })
  }

  const indexPath = 'data/golden-reports/review-queue/index.json'

  await fs.writeFile(
    indexPath,
    JSON.stringify(
      {
        generatedAt: new Date().toISOString(),
        corpusRoot: absoluteCorpusRoot,
        enableNlp: process.env.ENABLE_NLP === 'true',
        limit: args.limit,
        vendorFilter: args.vendor ?? null,
        maxMb: args.maxMb,
        includeHeld: args.includeHeld,
        skippedHeldReports,
        heldReviewSourcePaths: HELD_REVIEW_SOURCE_PATHS,
        heldReviewSourcePrefixes: HELD_REVIEW_SOURCE_PREFIXES,
        knownGoldenSourceAliases: KNOWN_GOLDEN_SOURCE_ALIASES,
        totalPdfFilesFound: allPdfFiles.length,
        candidatesAfterFiltering: candidates.length,
        selected: selected.length,
        items: indexItems,
      },
      null,
      2
    ),
    'utf8'
  )

  console.log('\n=== Review Queue ===')
  console.table(
    indexItems.map((item) => ({
      id: item.id,
      vendor: item.vendorGuess,
      findings: item.actualFindings,
      critical: item.severityCounts.Critical,
      high: item.severityCounts.High,
      medium: item.severityCounts.Medium,
      low: item.severityCounts.Low,
      status: item.status,
    }))
  )

  if (!args.includeHeld && skippedHeldReports > 0) {
    console.log(`\nSkipped held reports: ${skippedHeldReports}`)
    console.log('Use --include-held or REVIEW_INCLUDE_HELD=true to revisit them.')
  }

  console.log(`\nReview queue index written to: ${indexPath}`)
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})