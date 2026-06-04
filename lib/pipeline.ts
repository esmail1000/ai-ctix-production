export type AnalysisMode = 'quick' | 'deep'

export type Segment = {
  sentenceIndex: number
  sectionIndex?: number
  text: string
}

export type IndicatorType = 'IP' | 'Domain' | 'URL' | 'Hash' | 'Email'

export type Indicator = {
  id: string
  type: IndicatorType
  value: string
  confidence: number
  evidenceSentenceIndex: number
  evidenceText: string
}

export type PipelineRun = {
  version: 1
  createdAtIso: string
  mode: AnalysisMode
  strictness: number
  input: string
  normalized: string
  segments: Segment[]
  indicators: Indicator[]
  stats: {
    inputChars: number
    normalizedChars: number
    sectionCount: number
    sentenceCount: number
    indicatorCount: number
  }
}

function createUrlRe() {
  return /https?:\/\/[^\s<>"']+/gi
}

function createIpRe() {
  return /\b(?:\d{1,3}\.){3}\d{1,3}\b/g
}

function createMd5Re() {
  return /\b[a-fA-F0-9]{32}\b/g
}

function createSha1Re() {
  return /\b[a-fA-F0-9]{40}\b/g
}

function createSha256Re() {
  return /\b[a-fA-F0-9]{64}\b/g
}

function createEmailRe() {
  return /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi
}

function createDomainRe() {
  return /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b/gi
}
const DOMAIN_DENY_TLDS = new Set(['local', 'lan', 'internal'])

function clamp(min: number, max: number, value: number): number {
  return Math.max(min, Math.min(max, value))
}

function normalizeNewlines(value: string): string {
  return value.replace(/\r\n/g, '\n').replace(/\r/g, '\n')
}

function removeZeroWidth(value: string): string {
  return value.replace(/[\u200B-\u200F\uFEFF]/g, '')
}

function normalizeWhitespace(value: string): string {
  return value
    .replace(/[\t\f\v]+/g, ' ')
    .replace(/\u00A0/g, ' ')
    .replace(/[ ]{2,}/g, ' ')
}

export function normalizeText(input: string): string {
  const value = input ?? ''
  return normalizeWhitespace(removeZeroWidth(normalizeNewlines(value))).trim()
}

function splitSections(normalized: string): string[] {
  const sections = normalized
    .split(/\n{2,}/)
    .map((item) => item.trim())
    .filter((item) => item.length > 0)

  return sections.length > 0 ? sections : [normalized]
}

function isBulletLine(line: string): boolean {
  return /^\s*(?:[-*•]|\d+\.|\u2022)\s+/.test(line)
}

function isHeadingLine(line: string): boolean {
  return /^\s*(?:#{1,6}\s+|[A-Z][A-Z0-9 _\-]{6,})/.test(line)
}

function sentenceTokenize(paragraph: string): string[] {
  const text = paragraph.replace(/\n+/g, ' ').trim()
  if (!text) return []

  const matches = text.match(/[^.!?؟]+[.!?؟]+(?=\s|$)|[^.!?؟]+$/g) ?? []
  return matches.map((item) => item.trim()).filter(Boolean)
}

export function segmentReport(normalized: string): { segments: Segment[]; sectionCount: number } {
  const sections = splitSections(normalized)
  const segments: Segment[] = []
  let sentenceIndex = 0

  sections.forEach((sectionText, sectionIndex) => {
    const lines = sectionText
      .split(/\n/)
      .map((line) => line.trim())
      .filter(Boolean)

    let paragraphBuffer: string[] = []

    const flushParagraph = () => {
      const paragraph = paragraphBuffer.join(' ').trim()
      paragraphBuffer = []
      if (!paragraph) return

      for (const sentence of sentenceTokenize(paragraph)) {
        segments.push({ sentenceIndex, sectionIndex, text: sentence })
        sentenceIndex += 1
      }
    }

    for (const line of lines) {
      if (isBulletLine(line) || isHeadingLine(line)) {
        flushParagraph()
        segments.push({ sentenceIndex, sectionIndex, text: line })
        sentenceIndex += 1
        continue
      }

      paragraphBuffer.push(line)
    }

    flushParagraph()
  })

  if (segments.length === 0 && normalized.trim()) {
    return {
      sectionCount: 1,
      segments: [{ sentenceIndex: 0, sectionIndex: 0, text: normalized.trim() }],
    }
  }

  return { segments, sectionCount: sections.length }
}

function isValidIpv4(ip: string): boolean {
  const parts = ip.split('.')
  if (parts.length !== 4) return false

  return parts.every((part) => {
    if (!/^\d{1,3}$/.test(part)) return false
    const num = Number(part)
    return num >= 0 && num <= 255
  })
}

function isPrivateIpv4(ip: string): boolean {
  const [a, b] = ip.split('.').map((item) => Number(item))

  if (a === 10) return true
  if (a === 172 && b >= 16 && b <= 31) return true
  if (a === 192 && b === 168) return true
  if (a === 127) return true
  if (a === 169 && b === 254) return true

  return false
}

function confidenceFromStrictness(strictness: number, base: number): number {
  return clamp(45, 99, Math.round(base + strictness * 0.35))
}

function uniqueIndicatorKey(type: IndicatorType, value: string): string {
  return `${type}:${value.toLowerCase()}`
}

function buildIndicator(
  type: IndicatorType,
  value: string,
  confidence: number,
  segment: Segment
): Omit<Indicator, 'id'> {
  return {
    type,
    value,
    confidence,
    evidenceSentenceIndex: segment.sentenceIndex,
    evidenceText: segment.text,
  }
}

function upsertIndicator(store: Map<string, Indicator>, indicator: Omit<Indicator, 'id'>) {
  const key = uniqueIndicatorKey(indicator.type, indicator.value)
  const next: Indicator = { id: key, ...indicator }
  const existing = store.get(key)

  if (!existing || next.confidence > existing.confidence) {
    store.set(key, next)
  }
}

export function extractUrls(text: string, strictness: number): string[] {
  const urls = text.match(createUrlRe()) ?? []

  return urls
    .map((url) => url.replace(/[),.;:!?]+$/g, ''))
    .filter((url) => !(strictness >= 70 && url.length < 12))
}

export function extractIps(text: string, strictness: number): string[] {
  const ips = text.match(createIpRe()) ?? []

  return ips.filter((ip) => {
    if (!isValidIpv4(ip)) return false
    if (strictness >= 60 && isPrivateIpv4(ip)) return false
    return true
  })
}

export function extractHashes(text: string, strictness: number): string[] {
  const hashes = [
    ...(text.match(createSha256Re()) ?? []),
    ...(text.match(createSha1Re()) ?? []),
    ...(text.match(createMd5Re()) ?? []),
  ]

  return hashes.filter((hash) => !(strictness >= 80 && /[a-fA-F0-9]{65,}/.test(hash)))
}
export function extractEmails(text: string): string[] {
  return text.match(createEmailRe()) ?? []
}

export function extractDomains(text: string, strictness: number): string[] {
  const domains = text.match(createDomainRe()) ?? []

  return domains.filter((domain) => {
    const tld = domain.split('.').pop()?.toLowerCase() ?? ''

    if (DOMAIN_DENY_TLDS.has(tld)) return false
    if (strictness >= 75 && tld.length > 24) return false
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(domain)) return false

    return true
  })
}
export function extractIndicators(
  segments: Segment[],
  strictness: number,
  mode: AnalysisMode
): Indicator[] {
  const indicators = new Map<string, Indicator>()
  const segmentLimit = mode === 'quick' ? Math.min(segments.length, 250) : segments.length

  for (let index = 0; index < segmentLimit; index += 1) {
    const segment = segments[index]
    const text = segment.text

    for (const url of extractUrls(text, strictness)) {
      upsertIndicator(
        indicators,
        buildIndicator('URL', url, confidenceFromStrictness(strictness, 50), segment)
      )
    }

    for (const ip of extractIps(text, strictness)) {
      upsertIndicator(
        indicators,
        buildIndicator('IP', ip, confidenceFromStrictness(strictness, 55), segment)
      )
    }

    for (const hash of extractHashes(text, strictness)) {
      upsertIndicator(
        indicators,
        buildIndicator('Hash', hash, confidenceFromStrictness(strictness, 60), segment)
      )
    }

    for (const email of extractEmails(text)) {
      upsertIndicator(
        indicators,
        buildIndicator('Email', email, confidenceFromStrictness(strictness, 45), segment)
      )
    }

    for (const domain of extractDomains(text, strictness)) {
      upsertIndicator(
        indicators,
        buildIndicator('Domain', domain, confidenceFromStrictness(strictness, 48), segment)
      )
    }
  }

  return Array.from(indicators.values()).sort((a, b) => b.confidence - a.confidence)
}
export function buildPipelineStats(
  input: string,
  normalized: string,
  sectionCount: number,
  segments: Segment[],
  indicators: Indicator[]
) {
  return {
    inputChars: (input ?? '').length,
    normalizedChars: normalized.length,
    sectionCount,
    sentenceCount: segments.length,
    indicatorCount: indicators.length,
  }
}

export function runPipeline(input: string, mode: AnalysisMode, strictness: number): PipelineRun {
  const normalized = normalizeText(input)
  const { segments, sectionCount } = segmentReport(normalized)
  const normalizedStrictness = clamp(0, 100, Math.round(strictness))

  let indicators = extractIndicators(segments, normalizedStrictness, mode)

  if (indicators.length === 0 && normalized.trim()) {
    indicators = extractIndicators(
      [{ sentenceIndex: 0, sectionIndex: 0, text: normalized }],
      normalizedStrictness,
      'deep'
    )
  }

  return {
    version: 1,
    createdAtIso: new Date().toISOString(),
    mode,
    strictness: normalizedStrictness,
    input,
    normalized,
    segments,
    indicators,
    stats: buildPipelineStats(input, normalized, sectionCount, segments, indicators),
  }
}