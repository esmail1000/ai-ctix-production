import type { Finding } from '@/lib/mock-data'
import type {
    ExtractionMethod,
    FindingNormalization,
    FindingProvenance,
    FindingSourceSpan,
    ParsedFindingFields,
} from '@/lib/server/types'

export type ParsedFindingCandidate = {
  title: string
  severity?: Finding['severity']
  asset?: string
  status?: Finding['status']
  summary?: string
  impact?: string
  evidence?: string
  remediation?: string
  cve?: string
  references: string[]
  reported: ParsedFindingFields
  normalization: FindingNormalization
  provenance: FindingProvenance
}

type LineEntry = {
  text: string
  start: number
  end: number
}

type FieldKey =
  | 'severity'
  | 'asset'
  | 'status'
  | 'summary'
  | 'impact'
  | 'evidence'
  | 'remediation'
  | 'reference'

type ParsedFieldBuffer = {
  key: FieldKey
  value: string
  start: number
  end: number
}

export type FindingBlock = {
  index: number
  heading: string
  title: string
  rawText: string
  start: number
  end: number
}

const BLOCK_HEADING_RE =
  /^(?:(?:finding|issue|vulnerability)\s*(?:#|\b)?\s*\d+|F-\d{2,})\s*[:\-–].*$/gim

const BLOCK_ONLY_HEADING_RE =
  /^(?:(?:finding|issue|vulnerability)\s*(?:#|\b)?\s*\d+|F-\d{2,})$/i

const CVE_RE = /\bCVE-\d{4}-\d{4,}\b/gi
const HOST_LIKE_RE = /\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+){1,}\b/gi

const LABEL_ALIASES: Record<FieldKey, string[]> = {
  severity: ['Severity', 'Risk', 'Risk Level'],
  asset: ['Affected Asset', 'Asset', 'Host', 'Target', 'Affected Host', 'System'],
  status: ['Status', 'Finding Status'],
  summary: ['Summary', 'Description', 'Overview'],
  impact: ['Impact', 'Business Impact'],
  evidence: ['Evidence', 'Observation', 'Proof', 'Details'],
  remediation: ['Remediation', 'Recommended Remediation', 'Recommendation', 'Recommendations', 'Mitigation', 'Fix'],
  reference: ['Reference', 'References', 'CVE', 'CVEs', 'CWE', 'CWEs', 'OWASP Mapping', 'MITRE ATT&CK Mapping'],
}

function normalizeWhitespace(value: string | null | undefined): string {
  return String(value ?? '')
    .replace(/\r/g, '')
    .replace(/[ \t]+/g, ' ')
    .replace(/\n{3,}/g, '\n\n')
    .trim()
}

function normalizeInlineValue(value: string): string {
  return normalizeWhitespace(value.replace(/^[\-\s:]+/, ''))
}

function toLineEntries(text: string, offset = 0): LineEntry[] {
  const lines = text.replace(/\r/g, '').split('\n')
  const entries: LineEntry[] = []
  let cursor = 0

  for (const line of lines) {
    const start = offset + cursor
    const end = start + line.length
    entries.push({ text: line, start, end })
    cursor += line.length + 1
  }

  return entries
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

function stripFindingPrefix(value: string): string {
  return normalizeWhitespace(
    value.replace(/^(?:(?:finding|issue|vulnerability)\s*(?:#|\b)?\s*\d+|F-\d{2,})\s*[:\-–]?\s*/i, '')
  )
}

function matchFieldLabel(line: string): { key: FieldKey; label: string; inlineValue: string } | null {
  const trimmed = line.trim()

  for (const [key, aliases] of Object.entries(LABEL_ALIASES) as Array<[FieldKey, string[]]>) {
    for (const alias of aliases) {
      const re = new RegExp(`^${escapeRegExp(alias)}\\s*:\\s*(.*)$`, 'i')
      const match = trimmed.match(re)

      if (match) {
        return {
          key,
          label: alias,
          inlineValue: normalizeInlineValue(match[1] ?? ''),
        }
      }
    }
  }

  return null
}
function isTerminalSectionHeading(line: string): boolean {
  const trimmed = line.trim()
  if (!trimmed) return false

  if (
    /^(?:OVERALL IMPACT|RECOMMENDED ACTION PLAN|APPENDIX|CONCLUSION|NOTES?)$/i.test(
      trimmed
    )
  ) {
    return true
  }

  if (/^[A-Z][A-Z\s/&-]{4,}$/.test(trimmed) && !matchFieldLabel(trimmed)) {
    return true
  }

  return false
}

function getEffectiveBlockEnd(
  block: FindingBlock,
  titleText: string,
  fields: Map<FieldKey, ParsedFieldBuffer>
): number {
  let end = block.start + titleText.length

  fields.forEach((field) => {
    if (field.end > end) end = field.end
  })

  return end
}

function flushField(
  store: Map<FieldKey, ParsedFieldBuffer>,
  current: ParsedFieldBuffer | null
): ParsedFieldBuffer | null {
  if (!current) return null

  const nextValue = normalizeWhitespace(current.value)
  if (!nextValue) return null

  const existing = store.get(current.key)

  if (!existing || nextValue.length > existing.value.length) {
    store.set(current.key, {
      ...current,
      value: nextValue,
    })
  }

  return null
}

function buildFieldSpans(
  blockStart: number,
  blockEnd: number,
  titleText: string,
  fields: Map<FieldKey, ParsedFieldBuffer>
): FindingSourceSpan[] {
  const spans: FindingSourceSpan[] = [
    {
      label: 'block',
      start: blockStart,
      end: blockEnd,
      text: '',
    },
    {
      label: 'title',
      start: blockStart,
      end: blockStart + titleText.length,
      text: titleText,
    },
  ]

  fields.forEach((field) => {
  const label: FindingSourceSpan['label'] =
    field.key === 'reference' ? 'reference' : field.key

  spans.push({
    label,
    start: field.start,
    end: field.end,
    text: field.value,
  })
})

  return spans
}

function extractBlockTitle(block: FindingBlock): string {
  const lines = toLineEntries(block.rawText, block.start)
    .map((line) => line.text.trim())
    .filter(Boolean)

  if (lines.length === 0) return `Finding ${block.index + 1}`

  const first = lines[0]

  if (BLOCK_ONLY_HEADING_RE.test(first) && lines.length > 1) {
    return normalizeWhitespace(lines[1])
  }

  const stripped = stripFindingPrefix(first)
  if (stripped) return stripped

  return normalizeWhitespace(first) || `Finding ${block.index + 1}`
}

function parseFields(block: FindingBlock): Map<FieldKey, ParsedFieldBuffer> {
  const lines = toLineEntries(block.rawText, block.start)
  const fields = new Map<FieldKey, ParsedFieldBuffer>()

  let current: ParsedFieldBuffer | null = null

  for (let i = 1; i < lines.length; i += 1) {
    const line = lines[i]
    const trimmed = line.text.trim()

    if (!trimmed) {
      if (current) current.value += '\n'
      continue
    }

   const labelMatch = matchFieldLabel(trimmed)

if (labelMatch) {
  current = flushField(fields, current)
  current = {
    key: labelMatch.key,
    value: labelMatch.inlineValue,
    start: line.start,
    end: line.end,
  }
  continue
}

if (current && isTerminalSectionHeading(trimmed)) {
  current = flushField(fields, current)
  break
}

    if (current) {
      current.value = normalizeWhitespace(`${current.value}\n${trimmed}`)
      current.end = line.end
    }
  }

  flushField(fields, current)

  return fields
}

export function normalizeSeverity(value: string | undefined): Finding['severity'] | undefined {
  const text = normalizeWhitespace(value).toLowerCase()
  if (!text) return undefined

  if (text.includes('critical')) return 'Critical'
  if (text.includes('high')) return 'High'
  if (text.includes('medium')) return 'Medium'
  if (text.includes('low')) return 'Low'

  return undefined
}

export function normalizeStatus(value: string | undefined): Finding['status'] | undefined {
  const text = normalizeWhitespace(value).toLowerCase()
  if (!text) return undefined

  if (text.includes('resolved') || text.includes('closed') || text.includes('fixed')) {
    return 'Resolved'
  }

  if (text.includes('review')) return 'In Review'
  if (text.includes('open') || text.includes('active') || text.includes('new')) return 'Open'

  return undefined
}

export function normalizeAsset(value: string | undefined): string | undefined {
  const cleaned = normalizeWhitespace(value)
    .replace(/^affected asset\s*:\s*/i, '')
    .replace(/^asset\s*:\s*/i, '')
    .replace(/^host\s*:\s*/i, '')
    .replace(/^target\s*:\s*/i, '')

  return cleaned || undefined
}

export function normalizeTitle(value: string | undefined): string | undefined {
  const cleaned = stripFindingPrefix(normalizeWhitespace(value))
  return cleaned || undefined
}

function extractFirstCve(text: string | undefined): string | undefined {
  const matches = normalizeWhitespace(text).match(CVE_RE)
  return matches?.[0]?.toUpperCase()
}

function extractReferences(text: string | undefined): string[] {
  const normalized = normalizeWhitespace(text)
  if (!normalized) return []

  const cves = (normalized.match(CVE_RE) ?? []).map((item) => item.toUpperCase())
  const extras = normalized
    .split(/[,;\n]/)
    .map((item) => normalizeWhitespace(item))
    .filter(Boolean)

  return Array.from(new Set([...cves, ...extras]))
}

function extractHostLike(text: string | undefined): string | undefined {
  const match = normalizeWhitespace(text).match(HOST_LIKE_RE)
  return match?.[0]
}

export function buildCanonicalFindingKey(params: {
  title?: string
  asset?: string
  cve?: string
}): string | undefined {
  const title = normalizeWhitespace(params.title).toLowerCase()
  const asset = normalizeWhitespace(params.asset).toLowerCase()
  const cve = normalizeWhitespace(params.cve).toLowerCase()

  const parts = [title, asset, cve].filter(Boolean)
  if (parts.length === 0) return undefined

  return parts.join('::')
}

function calculateParserConfidence(params: {
  title?: string
  severity?: Finding['severity']
  asset?: string
  status?: Finding['status']
  summary?: string
  impact?: string
  evidence?: string
  remediation?: string
  cve?: string
  extractionMethod: ExtractionMethod
}): number {
  let score = 45

  if (params.extractionMethod === 'structured-parser') score += 10
  if (params.title) score += 10
  if (params.severity) score += 8
  if (params.asset) score += 8
  if (params.status) score += 5
  if (params.summary) score += 6
  if (params.impact) score += 4
  if (params.evidence) score += 4
  if (params.remediation) score += 4
  if (params.cve) score += 3

  return Math.max(0, Math.min(100, score))
}

export function splitFindingBlocks(reportText: string): FindingBlock[] {
  const text = reportText.replace(/\r/g, '')
  const matches = Array.from(text.matchAll(BLOCK_HEADING_RE))

  if (matches.length === 0) return []

  return matches.map((match, index) => {
    const start = match.index ?? 0
    const end =
      index < matches.length - 1
        ? (matches[index + 1].index ?? text.length)
        : text.length

    const rawText = text.slice(start, end).trim()
    const heading = normalizeWhitespace(match[0])

    const block: FindingBlock = {
      index,
      heading,
      title: '',
      rawText,
      start,
      end,
    }

    return {
      ...block,
      title: extractBlockTitle(block),
    }
  })
}

export function hasStructuredFindingBlocks(reportText: string): boolean {
  return splitFindingBlocks(reportText).length > 0
}

export function parseFindingBlock(block: FindingBlock): ParsedFindingCandidate {
  const fields = parseFields(block)

  const title = normalizeTitle(block.title) ?? `Finding ${block.index + 1}`

  const severityField = fields.get('severity')?.value
  const assetField = fields.get('asset')?.value
  const statusField = fields.get('status')?.value
  const summaryField = fields.get('summary')?.value
  const impactField = fields.get('impact')?.value
  const evidenceField = fields.get('evidence')?.value
  const remediationField = fields.get('remediation')?.value
  const referenceField = fields.get('reference')?.value

  const severity = normalizeSeverity(severityField)
  const status = normalizeStatus(statusField)
  const summary = normalizeWhitespace(summaryField)
  const impact = normalizeWhitespace(impactField)
  const evidence = normalizeWhitespace(evidenceField)
  const remediation = normalizeWhitespace(remediationField)

 const effectiveBlockEnd = getEffectiveBlockEnd(block, title, fields)
const effectiveBlockText = block.rawText
  .slice(0, Math.max(0, effectiveBlockEnd - block.start))
  .trim()

const asset =
  normalizeAsset(assetField) ??
  extractHostLike(summaryField) ??
  extractHostLike(evidenceField) ??
  extractHostLike(effectiveBlockText)

const cve =
  extractFirstCve(referenceField) ??
  extractFirstCve(summaryField) ??
  extractFirstCve(evidenceField) ??
  extractFirstCve(title)

  const references = Array.from(
    new Set([
      ...extractReferences(referenceField),
      ...(cve ? [cve] : []),
    ])
  )

  const canonicalKey = buildCanonicalFindingKey({
    title,
    asset,
    cve,
  })

  const reported: ParsedFindingFields = {
    title,
    severity,
    asset,
    status,
    summary: summary || undefined,
    impact: impact || undefined,
    evidence: evidence || undefined,
    remediation: remediation || undefined,
    cve,
    references,
  }

  const normalization: FindingNormalization = {
    normalizedTitle: title.toLowerCase(),
    normalizedAsset: asset?.toLowerCase(),
    canonicalKey,
  }

  const provenance: FindingProvenance = {
    extractionMethod: 'structured-parser',
    parserConfidence: calculateParserConfidence({
      extractionMethod: 'structured-parser',
      title,
      severity,
      asset,
      status,
      summary,
      impact,
      evidence,
      remediation,
      cve,
    }),
   sourceSectionTitle: block.heading,
sourceBlockIndex: block.index,
sourceText: effectiveBlockText,
sourceSpans: buildFieldSpans(block.start, effectiveBlockEnd, title, fields),
    fieldSources: {
      title: 'reported',
      severity: severityField ? 'reported' : undefined,
      asset: assetField ? 'reported' : asset ? 'inferred' : undefined,
      status: statusField ? 'reported' : undefined,
      summary: summary ? 'reported' : undefined,
      impact: impact ? 'reported' : undefined,
      evidence: evidence ? 'reported' : undefined,
      remediation: remediation ? 'reported' : undefined,
      cve: referenceField ? 'reported' : cve ? 'inferred' : undefined,
    },
  }

  return {
    title,
    severity,
    asset,
    status,
    summary: summary || undefined,
    impact: impact || undefined,
    evidence: evidence || undefined,
    remediation: remediation || undefined,
    cve,
    references,
    reported,
    normalization,
    provenance,
  }
}

export function parseStructuredFindings(reportText: string): ParsedFindingCandidate[] {
  return splitFindingBlocks(reportText).map(parseFindingBlock)
}