import type { Finding, Report } from '@/lib/mock-data'
import type { PipelineRun } from '@/lib/pipeline'

export type ExtractionMethod =
  | 'seed'
  | 'structured-parser'
  | 'heuristic-fallback'
  | 'nlp-hybrid'
  | 'manual'
export type FieldSource = 'reported' | 'derived' | 'inferred'

export type FindingSourceSpan = {
  label:
    | 'title'
    | 'severity'
    | 'asset'
    | 'status'
    | 'summary'
    | 'impact'
    | 'evidence'
    | 'remediation'
    | 'cve'
    | 'reference'
    | 'block'
  start: number
  end: number
  text: string
}

export type ParsedFindingFields = {
  title?: string
  severity?: Finding['severity']
  asset?: string
  status?: Finding['status']
  summary?: string
  impact?: string
  evidence?: string
  remediation?: string
  cve?: string
  references?: string[]
}

export type FindingNormalization = {
  normalizedTitle?: string
  normalizedAsset?: string
  canonicalKey?: string
}

export type FindingFieldSources = Partial<
  Record<
    | 'title'
    | 'severity'
    | 'asset'
    | 'status'
    | 'summary'
    | 'impact'
    | 'evidence'
    | 'remediation'
    | 'cve',
    FieldSource
  >
>

export type FindingProvenance = {
  extractionMethod: ExtractionMethod
  parserConfidence?: number
  sourceSectionTitle?: string
  sourceBlockIndex?: number
  sourceText?: string
  sourceSpans?: FindingSourceSpan[]
  fieldSources?: FindingFieldSources
}

export type StoredReport = Report & {
  content: string
  sourceFileName?: string
  createdAtIso: string
  updatedAtIso: string
  parsingStatus: 'seeded' | 'parsed' | 'failed'
  analysisVersion: number
  parserVersion?: number
  parsingNotes?: string[]
}

export type FindingHistoryEntry = {
  atIso: string
  status: Finding['status']
  note: string
}

export type StoredFinding = Finding & {
  reportName: string
  history: FindingHistoryEntry[]
  evidenceSentenceIndex?: number

  // Reported/raw fields captured directly from the source report when available
  reported?: ParsedFindingFields

  // Normalized fields used for matching, dedupe, and downstream scoring
  normalization?: FindingNormalization

  // Extraction metadata and provenance
  provenance?: FindingProvenance
}

export type AppDatabase = {
  version: 1
  initializedAtIso: string
  reports: StoredReport[]
  findings: StoredFinding[]
  runs: Array<{
    reportId: string
    run: PipelineRun
  }>
}