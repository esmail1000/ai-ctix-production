import fs from 'node:fs/promises'
import path from 'node:path'

type Severity = 'Critical' | 'High' | 'Medium' | 'Low'

type ManifestReport = {
  id: string
  vendor: string
  family: string
  sourceRootEnv?: string
  sourcePath: string
  textPath: string
  expectedPath: string
}

type Manifest = {
  reports: ManifestReport[]
}

type ReviewQueueItem = {
  id: string
  status: string
  source: {
    sourcePath: string
    fileName: string
    vendorGuess?: string
    textPath: string
  }
  modelRun: {
    actualFindings: number
    severityCounts: Record<Severity, number>
    warnings?: string[]
  }
  findings: unknown[]
}

type PromoteTarget = {
  reviewId: string
  goldenId: string
  vendor: string
  family: string
  expectedCount: number
  expectedSeverityCounts: Record<Severity, number>
  notes?: string[]
}

const REVIEW_DIR = 'data/golden-reports/review-queue'
const REVIEW_TEXT_DIR = 'data/golden-reports/review-queue-text'
const GOLDEN_TEXT_DIR = 'data/golden-reports/extracted-text'
const GOLDEN_EXPECTED_DIR = 'data/golden-reports/expected'
const MANIFEST_PATH = 'data/golden-reports/manifest.json'

const PROMOTE_TARGETS: PromoteTarget[] = [
  {
    reviewId: 'cure53-analysis-report-pomerium-f9038a95',
    goldenId: 'cure53-analysis-report-pomerium',
    vendor: 'Cure53',
    family: 'cure53',
    expectedCount: 5,
    expectedSeverityCounts: {
      Critical: 0,
      High: 2,
      Medium: 1,
      Low: 2,
    },
  },
  {
    reviewId: 'cure53-cure53-b5-1pw-06-report-v2-6a6f5640',
    goldenId: 'cure53-b5-1pw-06-report-v2',
    vendor: 'Cure53',
    family: 'cure53',
    expectedCount: 10,
    expectedSeverityCounts: {
      Critical: 0,
      High: 1,
      Medium: 2,
      Low: 7,
    },
  },
  {
    reviewId: 'cure53-cure53-b5-automations-1pw-14-report-99945eb6',
    goldenId: 'cure53-b5-automations-1pw-14-report',
    vendor: 'Cure53',
    family: 'cure53',
    expectedCount: 7,
    expectedSeverityCounts: {
      Critical: 0,
      High: 0,
      Medium: 2,
      Low: 5,
    },
  },
  {
    reviewId: 'cure53-dnsmasq-report-15848bd4',
    goldenId: 'cure53-dnsmasq-report',
    vendor: 'Cure53',
    family: 'cure53',
    expectedCount: 6,
    expectedSeverityCounts: {
      Critical: 0,
      High: 0,
      Medium: 1,
      Low: 5,
    },
  },
  {
    reviewId: 'cure53-jaeger-cure53-20190504-5a1e085f',
    goldenId: 'cure53-jaeger-20190504',
    vendor: 'Cure53',
    family: 'cure53',
    expectedCount: 3,
    expectedSeverityCounts: {
      Critical: 0,
      High: 0,
      Medium: 0,
      Low: 3,
    },
  },
  {
    reviewId: 'cure53-pentest-report-accessmyinfo-5bc82d43',
    goldenId: 'cure53-pentest-report-accessmyinfo',
    vendor: 'Cure53',
    family: 'cure53',
    expectedCount: 9,
    expectedSeverityCounts: {
      Critical: 1,
      High: 1,
      Medium: 1,
      Low: 6,
    },
  },
  {
    reviewId: 'cure53-pentest-report-bitwarden-7e80ee51',
    goldenId: 'cure53-pentest-report-bitwarden',
    vendor: 'Cure53',
    family: 'cure53',
    expectedCount: 11,
    expectedSeverityCounts: {
      Critical: 3,
      High: 2,
      Medium: 1,
      Low: 5,
    },
  },
  {
    reviewId: 'cure53-pentest-report-briar-8f57b02f',
    goldenId: 'cure53-pentest-report-briar',
    vendor: 'Cure53',
    family: 'cure53',
    expectedCount: 12,
    expectedSeverityCounts: {
      Critical: 0,
      High: 1,
      Medium: 4,
      Low: 7,
    },
  },
  {
    reviewId: 'cure53-pentest-report-casebox-1-726fabf1',
    goldenId: 'cure53-pentest-report-casebox-1',
    vendor: 'Cure53',
    family: 'cure53',
    expectedCount: 30,
    expectedSeverityCounts: {
      Critical: 6,
      High: 10,
      Medium: 8,
      Low: 6,
    },
  },
  {
    reviewId: 'cure53-pentest-report-casebox-2-b8d04deb',
    goldenId: 'cure53-pentest-report-casebox-2',
    vendor: 'Cure53',
    family: 'cure53',
    expectedCount: 18,
    expectedSeverityCounts: {
      Critical: 0,
      High: 2,
      Medium: 11,
      Low: 5,
    },
  },
  {
    reviewId: 'cure53-pentest-report-clipperz-d4001db8',
    goldenId: 'cure53-pentest-report-clipperz',
    vendor: 'Cure53',
    family: 'cure53',
    expectedCount: 25,
    expectedSeverityCounts: {
      Critical: 4,
      High: 2,
      Medium: 5,
      Low: 14,
    },
  },
  {
    reviewId: 'cure53-pentest-report-coredns-846d3103',
    goldenId: 'cure53-pentest-report-coredns',
    vendor: 'Cure53',
    family: 'cure53',
    expectedCount: 4,
    expectedSeverityCounts: {
      Critical: 1,
      High: 0,
      Medium: 1,
      Low: 2,
    },
  },
  {
    reviewId: 'cure53-pentest-report-cryptech-d0b72da6',
    goldenId: 'cure53-pentest-report-cryptech',
    vendor: 'Cure53',
    family: 'cure53',
    expectedCount: 9,
    expectedSeverityCounts: {
      Critical: 3,
      High: 2,
      Medium: 0,
      Low: 4,
    },
  },
  {
    reviewId: 'cure53-pentest-report-curl-17f9c235',
    goldenId: 'cure53-pentest-report-curl',
    vendor: 'Cure53',
    family: 'cure53',
    expectedCount: 22,
    expectedSeverityCounts: {
      Critical: 0,
      High: 4,
      Medium: 5,
      Low: 13,
    },
  },
  {
    reviewId: 'cure53-pentest-report-cyph-0565d909',
    goldenId: 'cure53-pentest-report-cyph',
    vendor: 'Cure53',
    family: 'cure53',
    expectedCount: 13,
    expectedSeverityCounts: {
      Critical: 2,
      High: 2,
      Medium: 5,
      Low: 4,
    },
  },
  {
    reviewId: 'cure53-pentest-report-dompurify-55fa3848',
    goldenId: 'cure53-pentest-report-dompurify',
    vendor: 'Cure53',
    family: 'cure53',
    expectedCount: 5,
    expectedSeverityCounts: {
      Critical: 1,
      High: 1,
      Medium: 0,
      Low: 3,
    },
  },
  {
    reviewId: 'cure53-pentest-report-dovecot-f4dc918c',
    goldenId: 'cure53-pentest-report-dovecot',
    vendor: 'Cure53',
    family: 'cure53',
    expectedCount: 3,
    expectedSeverityCounts: {
      Critical: 0,
      High: 0,
      Medium: 0,
      Low: 3,
    },
  },
  {
    reviewId: 'cure53-pentest-report-envoy-6dd5377a',
    goldenId: 'cure53-pentest-report-envoy',
    vendor: 'Cure53',
    family: 'cure53',
    expectedCount: 8,
    expectedSeverityCounts: {
      Critical: 0,
      High: 1,
      Medium: 5,
      Low: 2,
    },
  },
  {
    reviewId: 'cure53-pentest-report-fdroid-9331fc15',
    goldenId: 'cure53-pentest-report-fdroid',
    vendor: 'Cure53',
    family: 'cure53',
    expectedCount: 17,
    expectedSeverityCounts: {
      Critical: 3,
      High: 3,
      Medium: 5,
      Low: 6,
    },
  },
  {
    reviewId: 'cure53-pentest-report-fluent-dc5dcbc0',
    goldenId: 'cure53-pentest-report-fluent',
    vendor: 'Cure53',
    family: 'cure53',
    expectedCount: 6,
    expectedSeverityCounts: {
      Critical: 3,
      High: 0,
      Medium: 1,
      Low: 2,
    },
  },
]

const EXCLUDED_REVIEW_IDS = [
  'cure53-1pw-23-cure53-report-1password-mobile-v2-8e4a91a4',
  'cure53-analysis-report-bxaq-a972d918',
  'cure53-analysis-report-ijop-011406e1',
  'cure53-analysis-report-sgn-843d6df8',
  'cure53-pentest-report-cryptocat-2-835aa9a1',
]

function safeTimestamp() {
  return new Date().toISOString().replace(/[:.]/g, '-')
}

async function pathExists(filePath: string) {
  try {
    await fs.access(filePath)
    return true
  } catch {
    return false
  }
}

async function backupIfExists(filePath: string) {
  if (!(await pathExists(filePath))) return undefined

  const backupPath = `${filePath}.bak-${safeTimestamp()}`
  await fs.copyFile(filePath, backupPath)
  return backupPath
}

function readJson<T>(filePath: string) {
  return fs.readFile(filePath, 'utf8').then((text) => JSON.parse(text) as T)
}

function prettyJson(value: unknown) {
  return `${JSON.stringify(value, null, 2)}\n`
}

function severityCountsMatch(
  actual: Record<Severity, number>,
  expected: Record<Severity, number>
) {
  for (const severity of ['Critical', 'High', 'Medium', 'Low'] as const) {
    if ((actual[severity] ?? 0) !== expected[severity]) return false
  }

  return true
}

function assertReviewMatchesExpected(
  review: ReviewQueueItem,
  target: PromoteTarget
) {
  const errors: string[] = []

  if (review.id !== target.reviewId) {
    errors.push(`review id is ${review.id}, expected ${target.reviewId}`)
  }

  if (review.status !== 'ready_for_review') {
    errors.push(`status is ${review.status}, expected ready_for_review`)
  }

  if (review.modelRun.actualFindings !== target.expectedCount) {
    errors.push(
      `actualFindings is ${review.modelRun.actualFindings}, expected ${target.expectedCount}`
    )
  }

  if (
    !severityCountsMatch(
      review.modelRun.severityCounts,
      target.expectedSeverityCounts
    )
  ) {
    errors.push(
      `severityCounts mismatch. actual=${JSON.stringify(
        review.modelRun.severityCounts
      )}, expected=${JSON.stringify(target.expectedSeverityCounts)}`
    )
  }

  if (review.findings.length !== target.expectedCount) {
    errors.push(
      `findings array length is ${review.findings.length}, expected ${target.expectedCount}`
    )
  }

  const hasModelUnavailable = (review.modelRun.warnings ?? []).some((warning) =>
    /model unavailable|regex-only fallback/i.test(warning)
  )

  if (hasModelUnavailable) {
    errors.push('review contains model unavailable / regex-only fallback warning')
  }

  if (errors.length > 0) {
    throw new Error(
      `Cannot promote ${target.reviewId} -> ${target.goldenId}:\n- ${errors.join(
        '\n- '
      )}`
    )
  }
}

function expectedJsonFor(target: PromoteTarget, review: ReviewQueueItem) {
  return {
    id: target.goldenId,
    expectedCount: target.expectedCount,
    expectedSeverityCounts: target.expectedSeverityCounts,
    notes: [
      'Promoted from verified Stage 6 V7 Cure53 review queue.',
      `Source review id: ${review.id}`,
      'Requires ENABLE_GENERIC_INDEX_ALIGNMENT=true for generic official index / Cure53 official ID recovery gates.',
      'Cure53 severity labels are normalized into Critical, High, Medium, and Low. Info/Informational/Note are normalized to Low only when they are official severity-rated entries.',
      ...(target.notes ?? []),
    ],
  }
}

function manifestEntryFor(
  target: PromoteTarget,
  review: ReviewQueueItem
): ManifestReport {
  return {
    id: target.goldenId,
    vendor: target.vendor,
    family: target.family,
    sourceRootEnv: 'PUBLIC_REPORT_CORPUS_DIR',
    sourcePath: review.source.sourcePath,
    textPath: `data/golden-reports/extracted-text/${target.goldenId}.txt`,
    expectedPath: `data/golden-reports/expected/${target.goldenId}.json`,
  }
}

async function promoteOne(target: PromoteTarget) {
  const reviewPath = path.join(REVIEW_DIR, `${target.reviewId}.json`)
  const reviewTextPath = path.join(REVIEW_TEXT_DIR, `${target.reviewId}.txt`)
  const goldenTextPath = path.join(GOLDEN_TEXT_DIR, `${target.goldenId}.txt`)
  const expectedPath = path.join(GOLDEN_EXPECTED_DIR, `${target.goldenId}.json`)

  if (!(await pathExists(reviewPath))) {
    throw new Error(`Missing review JSON: ${reviewPath}`)
  }

  if (!(await pathExists(reviewTextPath))) {
    throw new Error(`Missing review text: ${reviewTextPath}`)
  }

  const review = await readJson<ReviewQueueItem>(reviewPath)

  assertReviewMatchesExpected(review, target)

  await fs.mkdir(path.dirname(goldenTextPath), { recursive: true })
  await fs.mkdir(path.dirname(expectedPath), { recursive: true })

  await backupIfExists(goldenTextPath)
  await backupIfExists(expectedPath)

  await fs.copyFile(reviewTextPath, goldenTextPath)

  await fs.writeFile(
    expectedPath,
    prettyJson(expectedJsonFor(target, review)),
    'utf8'
  )

  return manifestEntryFor(target, review)
}

async function main() {
  if (!(await pathExists(MANIFEST_PATH))) {
    throw new Error(`Missing manifest: ${MANIFEST_PATH}`)
  }

  const manifest = await readJson<Manifest>(MANIFEST_PATH)

  await backupIfExists(MANIFEST_PATH)

  const promotedEntries: ManifestReport[] = []

  for (const target of PROMOTE_TARGETS) {
    const entry = await promoteOne(target)
    promotedEntries.push(entry)
  }

  const promotedIds = new Set(promotedEntries.map((entry) => entry.id))

  const preservedReports = manifest.reports.filter(
    (report) => !promotedIds.has(report.id)
  )

  const updatedManifest: Manifest = {
    reports: [...preservedReports, ...promotedEntries],
  }

  await fs.writeFile(MANIFEST_PATH, prettyJson(updatedManifest), 'utf8')

  console.log('\n=== Promoted Stage 6 V7 Cure53 Review Queue Items ===')
  console.table(
    promotedEntries.map((entry) => ({
      id: entry.id,
      vendor: entry.vendor,
      sourcePath: entry.sourcePath,
      textPath: entry.textPath,
      expectedPath: entry.expectedPath,
    }))
  )

  console.log('\nExcluded / needs_attention review IDs:')
  console.table(EXCLUDED_REVIEW_IDS.map((id) => ({ id })))

  console.log('\nManifest updated:', MANIFEST_PATH)
  console.log('Promoted:', promotedEntries.length)
  console.log('Expected total manifest size:', updatedManifest.reports.length)
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
