import { extractIndicators, normalizeText, segmentReport, type AnalysisMode, type PipelineRun } from './pipeline'

export function runPipeline(input: string, mode: AnalysisMode = 'quick', strictness = 70): PipelineRun {
  const normalized = normalizeText(input)
  const { segments, sectionCount } = segmentReport(normalized)
  const indicators = extractIndicators(segments, strictness, mode)

  return {
    version: 1,
    createdAtIso: new Date().toISOString(),
    mode,
    strictness,
    input,
    normalized,
    segments,
    indicators,
    stats: {
      inputChars: input.length,
      normalizedChars: normalized.length,
      sectionCount,
      sentenceCount: segments.length,
      indicatorCount: indicators.length,
    },
  }
}

export { extractIndicators, normalizeText }
