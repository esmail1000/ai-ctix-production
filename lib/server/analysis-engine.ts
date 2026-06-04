import type { FindingStatus, ReportStatus, Severity } from '@/lib/mock-data'
import { runPipeline, type Indicator, type Segment } from '@/lib/pipeline'
import {
  parseStructuredFindings,
  type ParsedFindingCandidate,
} from '@/lib/server/report-parser'
import type { StoredFinding, StoredReport } from '@/lib/server/types'

const severityKeywords: Array<{ severity: Severity; terms: string[]; score: number }> = [
  {
    severity: 'Critical',
    score: 94,
    terms: [
      'critical',
      'rce',
      'remote code execution',
      'sql injection',
      'admin takeover',
      'public bucket',
      'exposed secrets',
      'domain admin',
      'full compromise',
      'command injection',
    ],
  },
  {
    severity: 'High',
    score: 84,
    terms: [
      'privilege escalation',
      'authentication bypass',
      'missing mfa',
      'outdated',
      'exposure',
      'ssrf',
      'bypass',
      'malware',
      'command and control',
      'c2',
      'suspicious outbound',
      'suspicious communication',
      'unauthorized communication',
    ],
  },
  {
    severity: 'Medium',
    score: 67,
    terms: [
      'weak password',
      'sensitive information',
      'token lifetime',
      'directory listing',
      'rate limit',
      'suspicious',
      'external communication',
      'containment',
      'forensic review',
      'hash',
      'indicator',
    ],
  },
  {
    severity: 'Low',
    score: 35,
    terms: ['verbose error', 'banner disclosure', 'clickjacking', 'security headers'],
  },
]

const findingSignalRe =
  /(vulnerab|finding|issue|expos|weak|misconfig|cve-|mfa|sql|token|password|bucket|error|inject|xss|ssrf|rce|bypass|malware|suspicious|command and control|external communication|outbound|hash|domain|ip|url|email|containment|remediation|impact)/i

const genericHeadingRe =
  /^(?:executive summary|summary|impact|description|details|evidence|remediation|recommendation|recommendations|severity|risk|asset(?: type)?|affected asset|host|target|references?|finding(?:s)?|issue(?:s)?|threat assessment|threat pressure|attack pressure|attack path|observed|ioc(?:s)?|indicator(?:s)?|status|confidence|notes?)[:\s-]*$/i

const fieldLabelPrefixRe =
  /^(?:asset(?: type)?|affected asset|target|host|summary|impact|description|details|evidence|remediation|recommendation(?:s)?|severity|risk|status|confidence|references?|threat assessment|attack pressure|iocs?|indicators?)\s*:\s*/i

const severityBaseScore: Record<Severity, number> = {
  Critical: 94,
  High: 84,
  Medium: 67,
  Low: 35,
}

function matchesAny(text: string, patterns: RegExp[]): boolean {
  return patterns.some((pattern) => pattern.test(text))
}

function slugify(input: string): string {
  return (
    input
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 80) || 'item'
  )
}
function reportKeyForFindingId(reportId: string) {
  return (
    reportId
      .replace(/^R-/i, '')
      .replace(/[^a-zA-Z0-9]+/g, '-')
      .replace(/^-|-$/g, '') || 'report'
  )
}

function makeFindingId(reportId: string, index: number) {
  return `F-${reportKeyForFindingId(reportId)}-${String(index + 1).padStart(
    3,
    '0'
  )}`
}

function titleCase(input: string): string {
  return input
    .split(/\s+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ')
}

function normalizeSentence(text: string): string {
  return String(text ?? '')
    .replace(/^[-*•]\s*/, '')
    .replace(/\s+/g, ' ')
    .trim()
}

function dedupeBy<T>(items: T[], keyFn: (item: T) => string): T[] {
  const seen = new Set<string>()
  const output: T[] = []

  for (const item of items) {
    const key = keyFn(item)
    if (!key || seen.has(key)) continue
    seen.add(key)
    output.push(item)
  }

  return output
}

function sanitizeCandidateText(text: string): string {
  return normalizeSentence(text).replace(fieldLabelPrefixRe, '').trim()
}

function isNoiseFindingCandidate(text: string): boolean {
  const cleaned = sanitizeCandidateText(text)

  if (cleaned.length < 18) return true
  if (genericHeadingRe.test(cleaned)) return true

  if (
    /^(?:com|asset|type|risk|severity|summary|impact|details|remediation|recommendation|observed|threat|attack)(?:\s+[a-z]+){0,3}$/i.test(
      cleaned
    ) &&
    !findingSignalRe.test(cleaned)
  ) {
    return true
  }

  if (
    /^[a-z]+(?:\s+[a-z]+){0,3}$/i.test(cleaned) &&
    !findingSignalRe.test(cleaned) &&
    !/cve-\d{4}-\d+/i.test(cleaned)
  ) {
    return true
  }

  return false
}

function pickSeverity(text: string): { severity: Severity; score: number } {
  const lower = text.toLowerCase()

  for (const item of severityKeywords) {
    if (item.terms.some((term) => lower.includes(term))) {
      return { severity: item.severity, score: item.score }
    }
  }

  if (/cve-\d{4}-\d+/i.test(text)) return { severity: 'High', score: 81 }

  if (/https?:\/\//i.test(text) || /\b\d{1,3}(?:\.\d{1,3}){3}\b/.test(text)) {
    return { severity: 'Medium', score: 64 }
  }

  return { severity: 'Medium', score: 60 }
}

function guessTitle(text: string): string {
  const cleaned = sanitizeCandidateText(text)
  const lower = cleaned.toLowerCase()

  const rules: Array<{ title: string; patterns: RegExp[] }> = [
    {
      title: 'Missing MFA for Privileged Access',
      patterns: [/missing mfa/, /multi-factor/, /\bmfa\b/, /privileged access/, /admin portal/],
    },
    {
      title: 'Privilege Escalation Through Access Control Weakness',
      patterns: [/privilege escalation/, /access control/, /role/, /admin/, /authorization/],
    },
    {
      title: 'SQL Injection Enables Database Manipulation',
      patterns: [/sql injection/, /\bsqli\b/, /database error/, /query manipulation/],
    },
    {
      title: 'Authentication Bypass Risk',
      patterns: [/authentication bypass/, /auth bypass/, /login bypass/],
    },
    {
      title: 'Weak Authentication Controls Enable Account Abuse',
      patterns: [/weak password/, /credential stuffing/, /brute-force/, /password policy/],
    },
    {
      title: 'Session Management Weakness',
      patterns: [/session/, /token/, /cookie/, /idle timeout/],
    },
    {
      title: 'Public Storage Exposure',
      patterns: [/public bucket/, /anonymous access/, /storage/, /bucket/, /object storage/],
    },
    {
      title: 'Sensitive Data Exposure',
      patterns: [/sensitive data/, /data exposure/, /secrets/, /internal artifacts/, /information disclosure/],
    },
    {
      title: 'Outdated Software With Known Vulnerability Exposure',
      patterns: [/outdated/, /unsupported/, /known vulnerabilities/, /apache/, /public security advisories/, /cve-/],
    },
    {
      title: 'Suspicious External Communication',
      patterns: [/external communication/, /outbound/, /command and control/, /\bc2\b/, /unauthorized communication/, /external ip/],
    },
    {
      title: 'Application Information Disclosure',
      patterns: [/verbose error/, /stack trace/, /banner disclosure/, /exception/, /framework traces/],
    },
  ]

  for (const rule of rules) {
    if (matchesAny(lower, rule.patterns)) {
      return rule.title
    }
  }

  const cveMatch = cleaned.match(/CVE-\d{4}-\d+/i)
  if (cveMatch) {
    return `Security Finding Related To ${cveMatch[0].toUpperCase()}`
  }

  const asset = extractBestAsset(cleaned)
  if (asset) {
    return `Security Finding Affecting ${asset}`
  }

  const beforeColon = cleaned.split(':')[0]?.trim() || cleaned
  const firstSentence = beforeColon.split(/[.!?؟]/)[0]?.trim() || beforeColon

  if (isNoiseFindingCandidate(firstSentence)) {
    return 'Security Finding Requiring Review'
  }

  return titleCase(firstSentence).slice(0, 90) || 'Security Finding Requiring Review'
}

function extractLabeledAsset(text: string): string | null {
  const match = text.match(/\b(?:affected asset|asset|target|host)\s*:\s*([^\n\r|]+)/i)
  return match?.[1]?.replace(/[.,;:!?]+$/g, '').trim() ?? null
}

function extractBestAsset(text: string): string | null {
  const normalized = text.trim()

  const labeled = extractLabeledAsset(normalized)
  if (labeled) return labeled

  const domainMatch = normalized.match(
    /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b/i
  )
  if (domainMatch) return domainMatch[0]

  const hostMatch = normalized.match(
    /\b(?:admin|portal|gateway|vpn|storage|app|server|db|web)[-_a-z0-9.]*\b/i
  )
  if (hostMatch) return hostMatch[0]

  return null
}

function guessAsset(text: string, reportText?: string): string {
  const direct = extractBestAsset(text)
  if (direct) return direct

  if (reportText) {
    const reportLevelLabeled = extractLabeledAsset(reportText)
    if (reportLevelLabeled) return reportLevelLabeled
  }

  return 'investigation-scope'
}

function guessStatus(severity: Severity): FindingStatus {
  if (severity === 'Critical' || severity === 'High') return 'Open'
  return 'In Review'
}

function guessReportStatus(findings: StoredFinding[]): ReportStatus {
  if (
    findings.some(
      (item) =>
        item.status === 'Open' &&
        (item.severity === 'Critical' || item.severity === 'High')
    )
  ) {
    return 'Ready'
  }

  if (findings.length > 0) return 'Reviewed'
  return 'Pending'
}

function buildSummary(text: string): string {
  return sanitizeCandidateText(text).slice(0, 220)
}

function buildImpactText(
  asset: string,
  severity: Severity,
  reportedImpact?: string
): string {
  const normalizedReported = normalizeSentence(reportedImpact ?? '')
  if (normalizedReported) return normalizedReported

  if (severity === 'Critical' || severity === 'High') {
    return `Potential impact includes attacker access, persistence, or abuse against ${asset} if this finding remains unaddressed.`
  }

  return `Potential impact includes increased attacker opportunity against ${asset} if this finding remains unaddressed.`
}

function buildRemediationText(
  severity: Severity,
  reportedRemediation?: string
): string {
  const normalizedReported = normalizeSentence(reportedRemediation ?? '')
  if (normalizedReported) return normalizedReported

  if (severity === 'Critical' || severity === 'High') {
    return 'Validate scope, patch or reconfigure the affected asset, contain exposure if needed, and confirm remediation with a targeted retest.'
  }

  return 'Review the affected control, harden the configuration, and confirm the issue no longer reproduces.'
}

function isUsefulSummaryLine(text: string): boolean {
  const normalized = normalizeSentence(text)
  if (normalized.length < 20) return false
  if (/^executive summary$/i.test(normalized)) return false
  if (/^findings$/i.test(normalized)) return false
  if (/^impact$/i.test(normalized)) return false
  return true
}

function buildExecutiveSummaryFromSegments(segments: Segment[]): string {
  const useful = segments
    .map((segment) => normalizeSentence(segment.text))
    .filter(isUsefulSummaryLine)
    .slice(0, 3)

  if (useful.length === 0) return 'Generated analysis report.'
  return useful.join(' ').slice(0, 320)
}

function buildExecutiveSummaryFromStructuredFindings(findings: StoredFinding[]): string {
  const top = findings
    .slice(0, 3)
    .map((item) => `${item.title} affecting ${item.asset}.`)
    .filter(Boolean)

  if (top.length === 0) return 'Generated analysis report.'
  return top.join(' ').slice(0, 320)
}

function segmentLooksLikeFinding(segment: Segment): boolean {
  const text = sanitizeCandidateText(segment.text)

  if (isNoiseFindingCandidate(text)) return false
  if (/cve-\d{4}-\d+/i.test(text)) return true

  return findingSignalRe.test(text)
}

function indicatorToSentence(indicator: Indicator): string {
  switch (indicator.type) {
    case 'URL':
      return `Suspicious URL observed: ${indicator.value}.`
    case 'IP':
      return `Suspicious IP communication observed: ${indicator.value}.`
    case 'Domain':
      return `Suspicious domain observed: ${indicator.value}.`
    case 'Email':
      return `Suspicious contact email observed: ${indicator.value}.`
    case 'Hash':
      return `Potential malicious file hash observed: ${indicator.value}.`
    default:
      return `Suspicious indicator observed: ${indicator.value}.`
  }
}

function canonicalFallbackFindingKey(text: string): string {
  const normalized = normalizeSentence(text).toLowerCase()

  return normalized
    .replace(/cve-\d{4}-\d+/g, 'cve')
    .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, 'ip')
    .replace(/\b[a-f0-9]{32,64}\b/g, 'hash')
    .replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, 'email')
    .replace(/\b(?:https?:\/\/[^\s]+)\b/gi, 'url')
    .replace(
      /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b/gi,
      'domain'
    )
    .slice(0, 120)
}

function buildFallbackCandidates(
  segments: Segment[],
  indicators: Indicator[]
): Segment[] {
  const fromSegments = segments.filter(segmentLooksLikeFinding)

  const fromIndicators: Segment[] = indicators.map((indicator, index) => ({
    sentenceIndex: 10000 + index,
    sectionIndex: undefined,
    text: indicatorToSentence(indicator),
  }))

  return dedupeBy(
    [...fromSegments, ...fromIndicators],
    (item) => canonicalFallbackFindingKey(item.text)
  )
}

function scoreFromCandidate(candidate: ParsedFindingCandidate): {
  severity: Severity
  score: number
} {
  const combined = [
    candidate.title,
    candidate.summary,
    candidate.impact,
    candidate.evidence,
    candidate.remediation,
    candidate.cve,
  ]
    .filter(Boolean)
    .join(' ')

  if (candidate.severity) {
    return {
      severity: candidate.severity,
      score: severityBaseScore[candidate.severity],
    }
  }

  return pickSeverity(combined)
}

function findEvidenceSentenceIndex(
  segments: Segment[],
  texts: Array<string | undefined>
): number | undefined {
  const needles = texts
    .map((item) => normalizeSentence(item ?? '').toLowerCase())
    .filter((item) => item.length >= 16)

  if (needles.length === 0) return undefined

  for (const segment of segments) {
    const hay = normalizeSentence(segment.text).toLowerCase()

    if (needles.some((needle) => hay.includes(needle) || needle.includes(hay))) {
      return segment.sentenceIndex
    }
  }

  return undefined
}

function mapStructuredCandidateToFinding(params: {
  candidate: ParsedFindingCandidate
  reportId: string
  reportName: string
  uploadedAt: string
  index: number
  pipelineSegments: Segment[]
}): StoredFinding {
  const { candidate } = params
  const { severity, score } = scoreFromCandidate(candidate)
  const status = candidate.status ?? guessStatus(severity)
  const asset = candidate.asset ?? 'investigation-scope'
  const title = candidate.title || 'Security Finding Requiring Review'
  const findingId = makeFindingId(params.reportId, params.index)

  return {
    id: findingId,
    slug: slugify(title),
    reportId: params.reportId,
    reportName: params.reportName,
    title,
    cve: candidate.cve ?? '—',
    severity,
    asset,
    score,
    status,
    detectedAt: params.uploadedAt,
    summary:
      candidate.summary ??
      buildSummary([title, candidate.evidence].filter(Boolean).join('. ')),
    impact: buildImpactText(asset, severity, candidate.impact),
    evidence: normalizeSentence(candidate.evidence ?? candidate.summary ?? title),
    remediation: buildRemediationText(severity, candidate.remediation),
    history: [
      {
        atIso: new Date().toISOString(),
        status,
        note: 'Finding generated from structured report parsing.',
      },
    ],
    evidenceSentenceIndex: findEvidenceSentenceIndex(params.pipelineSegments, [
      candidate.evidence,
      candidate.summary,
      candidate.title,
    ]),
    reported: candidate.reported,
    normalization: candidate.normalization,
    provenance: {
      ...candidate.provenance,
      fieldSources: {
        ...candidate.provenance.fieldSources,
        status: candidate.status ? 'reported' : 'inferred',
        severity: candidate.severity ? 'reported' : 'inferred',
      },
    },
  }
}

function mapFallbackSegmentToFinding(params: {
  segment: Segment
  reportId: string
  reportName: string
  uploadedAt: string
  input: string
  index: number
}): StoredFinding {
  const normalizedText = normalizeSentence(params.segment.text)
  const { severity, score } = pickSeverity(normalizedText)
  const title = guessTitle(normalizedText)
  const findingId = makeFindingId(params.reportId, params.index)
  const cveMatch = normalizedText.match(/CVE-\d{4}-\d+/i)
  const status = guessStatus(severity)
  const asset = guessAsset(normalizedText, params.input)

  return {
    id: findingId,
    slug: slugify(title),
    reportId: params.reportId,
    reportName: params.reportName,
    title,
    cve: cveMatch?.[0]?.toUpperCase() ?? '—',
    severity,
    asset,
    score,
    status,
    detectedAt: params.uploadedAt,
    summary: buildSummary(normalizedText),
    impact: buildImpactText(asset, severity),
    evidence: normalizedText,
    remediation: buildRemediationText(severity),
    history: [
      {
        atIso: new Date().toISOString(),
        status,
        note: 'Finding generated from heuristic fallback analysis.',
      },
    ],
    evidenceSentenceIndex: params.segment.sentenceIndex,
    reported: {
      title,
      cve: cveMatch?.[0]?.toUpperCase(),
      summary: buildSummary(normalizedText),
      evidence: normalizedText,
      severity,
      asset,
      status,
    },
    normalization: {
      normalizedTitle: title.toLowerCase(),
      normalizedAsset: asset.toLowerCase(),
      canonicalKey: canonicalFallbackFindingKey(
        `${title} ${asset} ${cveMatch?.[0] ?? ''}`
      ),
    },
    provenance: {
      extractionMethod: 'heuristic-fallback',
      parserConfidence: 55,
      sourceText: params.segment.text,
      sourceSpans: [],
      fieldSources: {
        title: 'inferred',
        severity: 'inferred',
        asset: 'inferred',
        status: 'inferred',
        summary: 'derived',
        evidence: 'reported',
        cve: cveMatch?.[0] ? 'reported' : undefined,
      },
    },
  }
}

export function analyzeContent(params: {
  reportId: string
  reportName: string
  uploadedAt: string
  input: string
  sourceType: StoredReport['type']
}) {
  const pipeline = runPipeline(params.input, 'deep', 70)
  const structuredCandidates = parseStructuredFindings(params.input)

  const findings =
    structuredCandidates.length > 0
      ? dedupeBy(
          structuredCandidates.map((candidate, index) =>
            mapStructuredCandidateToFinding({
              candidate,
              reportId: params.reportId,
              reportName: params.reportName,
              uploadedAt: params.uploadedAt,
              index,
              pipelineSegments: pipeline.segments,
            })
          ),
          (item) =>
            item.normalization?.canonicalKey ??
            `${item.slug}:${item.asset}:${item.severity}:${item.cve}`
        )
      : dedupeBy(
          buildFallbackCandidates(pipeline.segments, pipeline.indicators).map(
            (segment, index) =>
              mapFallbackSegmentToFinding({
                segment,
                reportId: params.reportId,
                reportName: params.reportName,
                uploadedAt: params.uploadedAt,
                input: params.input,
                index,
              })
          ),
          (item) =>
            item.normalization?.canonicalKey ??
            `${item.slug}:${item.asset}:${item.severity}:${item.cve}`
        )

  const report: Omit<
    StoredReport,
    'content' | 'sourceFileName' | 'createdAtIso' | 'updatedAtIso'
  > = {
    id: params.reportId,
    slug: slugify(params.reportName),
    name: params.reportName,
    type: params.sourceType,
    uploadedAt: params.uploadedAt,
    owner: 'AI CTIX Analyzer',
    status: guessReportStatus(findings),
    findings: findings.length,
    critical: findings.filter((item) => item.severity === 'Critical').length,
    high: findings.filter((item) => item.severity === 'High').length,
    medium: findings.filter((item) => item.severity === 'Medium').length,
    low: findings.filter((item) => item.severity === 'Low').length,
    summary:
      structuredCandidates.length > 0
        ? buildExecutiveSummaryFromStructuredFindings(findings)
        : buildExecutiveSummaryFromSegments(pipeline.segments),
    parsingStatus: 'parsed',
    analysisVersion: pipeline.version,
    parserVersion: 1,
    parsingNotes:
      structuredCandidates.length > 0
        ? ['Structured parser matched finding blocks successfully.']
        : ['Structured parser found no blocks; heuristic fallback was used.'],
  }

  return { pipeline, report, findings }
}