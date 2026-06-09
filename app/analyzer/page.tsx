'use client'

import type { Finding, Report, Severity } from '@/lib/mock-data'
import { runPipeline } from '@/lib/pipeline-client'
import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react'

const allowedTypes = [
  'text/plain',
  'text/markdown',
  'text/csv',
  'application/json',
  'application/pdf',
  'application/octet-stream',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
]

const allowedExtensions = ['.txt', '.md', '.log', '.csv', '.json', '.pdf', '.docx']
const maxFileSize = 25 * 1024 * 1024
const minTextLength = 50

const analysisSteps = [
  {
    title: 'Uploading report',
    detail: 'Securely loading your file or pasted content.',
    ai: 'AI input router checks source quality.',
  },
  {
    title: 'Extracting text',
    detail: 'Parsing PDF, DOCX, TXT, logs, JSON, and raw content.',
    ai: 'AI parser normalizes noisy report text.',
  },
  {
    title: 'Cleaning content',
    detail: 'Removing noise, repeated lines, and formatting artifacts.',
    ai: 'AI prepares semantic security context.',
  },
  {
    title: 'Segmenting sections',
    detail: 'Finding scope, evidence, findings, impact, and remediation sections.',
    ai: 'AI understands the report structure.',
  },
  {
    title: 'Extracting vulnerabilities',
    detail: 'Detecting weaknesses, affected assets, evidence, severity, and fixes.',
    ai: 'AI extracts security meaning, not just keywords.',
  },
  {
    title: 'Detecting CVEs',
    detail: 'Mapping CVEs, indicators, attack terms, and MITRE-like evidence.',
    ai: 'AI performs cyber entity recognition.',
  },
  {
    title: 'Calculating risk',
    detail: 'Prioritizing exploitability, business impact, and analyst review.',
    ai: 'AI ranks what matters first.',
  },
  {
    title: 'Preparing output',
    detail: 'Saving the report, findings, graph-ready data, and next actions.',
    ai: 'AI turns the report into actionable CTI.',
  },
]

const severityOrder: Severity[] = ['Critical', 'High', 'Medium', 'Low']

type InputMode = 'file' | 'text'
type StepStatus = 'done' | 'active' | 'pending'
type StatusTone = 'ready' | 'waiting' | 'warning' | 'danger' | 'neutral'

type AnalyzeResponse = {
  error?: string
  report?: Report
  findings?: Finding[]
  postAnalysis?: unknown
  graphBuildStatus?: unknown
}

function getFileExtension(fileName: string) {
  const match = fileName.toLowerCase().match(/\.[^.]+$/)
  return match?.[0] ?? ''
}

function formatFileSize(size: number) {
  if (size >= 1024 * 1024) return `${(size / (1024 * 1024)).toFixed(1)} MB`
  if (size >= 1024) return `${Math.round(size / 1024)} KB`
  return `${size} B`
}

function validateFile(file: File) {
  const extension = getFileExtension(file.name)
  const mimeType = String(file.type ?? '').toLowerCase()
  const isAllowedByExtension = allowedExtensions.includes(extension)
  const isAllowedByMime = allowedTypes.includes(mimeType) || mimeType.startsWith('text/')

  if (!isAllowedByExtension && !isAllowedByMime) {
    return 'Unsupported file type. Please upload PDF, DOCX, TXT, MD, LOG, CSV, or JSON.'
  }

  if (file.size > maxFileSize) {
    return 'File is too large. Maximum allowed size is 25MB.'
  }

  return ''
}

function average(values: number[]) {
  if (values.length === 0) return 0
  return Math.round(values.reduce((sum, value) => sum + value, 0) / values.length)
}

function clamp(value: number, min = 0, max = 100) {
  return Math.max(min, Math.min(max, value))
}

function confidenceFromFinding(finding: Finding) {
  const raw = Number(finding.provenance?.parserConfidence ?? 0)
  if (!Number.isFinite(raw) || raw <= 0) return 0
  return clamp(Math.round(raw <= 1 ? raw * 100 : raw))
}

function findingNeedsReview(finding: Finding) {
  const confidence = confidenceFromFinding(finding)
  const evidence = String(finding.evidence ?? '').trim()
  const remediation = String(finding.remediation ?? '').trim()

  return finding.status !== 'Resolved' && (confidence < 70 || !evidence || !remediation)
}

function countCves(findings: Finding[]) {
  return new Set(
    findings
      .flatMap((finding) => [
        finding.cve,
        ...(finding.title.match(/\bCVE-\d{4}-\d{4,7}\b/gi) ?? []),
        ...(finding.summary.match(/\bCVE-\d{4}-\d{4,7}\b/gi) ?? []),
        ...(finding.evidence.match(/\bCVE-\d{4}-\d{4,7}\b/gi) ?? []),
      ])
      .map((item) => String(item ?? '').trim().toUpperCase())
      .filter(Boolean)
  ).size
}

function countAssets(findings: Finding[]) {
  return new Set(findings.map((finding) => String(finding.asset ?? '').trim()).filter(Boolean)).size
}

function riskBand(score: number) {
  if (score >= 80) return 'High Risk'
  if (score >= 60) return 'Elevated'
  if (score >= 40) return 'Moderate'
  return 'Controlled'
}

function shortFileType(file: File | null) {
  if (!file) return 'No file selected'
  const extension = getFileExtension(file.name).replace('.', '').toUpperCase()
  return extension || file.type || 'File'
}

function shortDate(value: string) {
  try {
    return new Intl.DateTimeFormat('en', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      timeZone: 'Africa/Cairo',
    }).format(new Date(value))
  } catch {
    return value
  }
}

export default function AnalyzerPage() {
  const router = useRouter()
  const fileInputRef = useRef<HTMLInputElement | null>(null)

  const [inputMode, setInputMode] = useState<InputMode>('file')
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [pastedText, setPastedText] = useState('')
  const [isDragging, setIsDragging] = useState(false)
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [progress, setProgress] = useState(0)
  const [activeStep, setActiveStep] = useState(0)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [createdReport, setCreatedReport] = useState<Report | null>(null)
  const [createdFindings, setCreatedFindings] = useState<Finding[]>([])
  const [recentReports, setRecentReports] = useState<Report[]>([])

  useEffect(() => {
    fetch('/api/reports')
      .then((response) => response.json())
      .then((data) => setRecentReports((data.reports ?? []).slice(0, 3)))
      .catch(() => undefined)
  }, [])

  useEffect(() => {
    if (!isSubmitting) return undefined

    const timer = window.setInterval(() => {
      setActiveStep((current) => Math.min(current + 1, analysisSteps.length - 1))
    }, 920)

    return () => window.clearInterval(timer)
  }, [isSubmitting])

  const pastedTextLength = pastedText.trim().length
  const canAnalyze = Boolean(selectedFile || pastedTextLength >= minTextLength)
  const selectedFileError = selectedFile ? validateFile(selectedFile) : ''

  const preview = useMemo(() => {
    const input = pastedText.trim()
    if (input.length < minTextLength) return null

    return runPipeline(input.slice(0, 30000))
  }, [pastedText])

  const output = useMemo(() => {
    const findings = createdFindings
    const severityCounts = severityOrder.map((severity) => ({
      severity,
      count: findings.filter((finding) => finding.severity === severity).length,
    }))

    const riskScore = average(findings.map((finding) => finding.score))
    const cves = countCves(findings)
    const assets = countAssets(findings)
    const needsReview = findings.filter(findingNeedsReview).length
    const confidence = average(findings.map(confidenceFromFinding))

    return {
      totalFindings: findings.length,
      severityCounts,
      riskScore,
      cves,
      assets,
      needsReview,
      confidence,
    }
  }, [createdFindings])

  const fallbackSummary = preview
    ? {
        totalFindings: preview.stats.indicatorCount,
        cves: preview.indicators.filter((item) => String(item.type).toLowerCase().includes('cve')).length,
        assets: preview.stats.sectionCount,
        riskScore: clamp(42 + preview.indicators.length * 3),
        needsReview: Math.min(3, Math.max(1, preview.stats.sectionCount - 1)),
      }
    : {
        totalFindings: 0,
        cves: 0,
        assets: 0,
        riskScore: 0,
        needsReview: 0,
      }

  const summary = createdReport
    ? output
    : {
        ...output,
        totalFindings: fallbackSummary.totalFindings,
        cves: fallbackSummary.cves,
        assets: fallbackSummary.assets,
        riskScore: fallbackSummary.riskScore,
        needsReview: fallbackSummary.needsReview,
      }

  function clearMessages() {
    setError('')
    setSuccess('')
  }

  function chooseFile(file: File | null) {
    clearMessages()

    if (!file) {
      setSelectedFile(null)
      if (fileInputRef.current) fileInputRef.current.value = ''
      return
    }

    const validationError = validateFile(file)

    if (validationError) {
      setSelectedFile(null)
      setError(validationError)
      if (fileInputRef.current) fileInputRef.current.value = ''
      return
    }

    setSelectedFile(file)
    setInputMode('file')
  }

  function resetInput() {
    setInputMode('file')
    setSelectedFile(null)
    setPastedText('')
    setIsDragging(false)
    setProgress(0)
    setActiveStep(0)
    setError('')
    setSuccess('')
    setCreatedReport(null)
    setCreatedFindings([])

    if (fileInputRef.current) fileInputRef.current.value = ''
  }

  async function handleAnalyze() {
    let progressTimer: number | undefined

    try {
      setError('')
      setSuccess('')
      setCreatedReport(null)
      setCreatedFindings([])
      setIsSubmitting(true)
      setProgress(2)
      setActiveStep(0)

      progressTimer = window.setInterval(() => {
        setProgress((current) => (current >= 94 ? current : current + 2))
      }, 260)

      const formData = new FormData()
      if (pastedText.trim()) formData.append('text', pastedText.trim())
      if (selectedFile) formData.append('file', selectedFile)

      const response = await fetch('/api/analyze', {
        method: 'POST',
        body: formData,
      })

      const responseText = await response.text()
      let data: AnalyzeResponse = {}

      try {
        data = responseText ? JSON.parse(responseText) : {}
      } catch {
        throw new Error(
          response.ok
            ? 'Analysis returned an invalid response.'
            : 'Analysis service returned a non-JSON error. Check the terminal logs.'
        )
      }

      if (!response.ok) {
        throw new Error(
          data.error ?? 'Analysis failed. Your input was not lost. You can retry or edit the content.'
        )
      }

      if (!data.report) {
        throw new Error('Analysis completed but no report was returned.')
      }

      setProgress(100)
      setActiveStep(analysisSteps.length - 1)
      setCreatedReport(data.report)
      setCreatedFindings(data.findings ?? [])
      setSuccess('AI analysis completed. The report and findings were saved to the workspace.')
      setRecentReports((current) =>
        [data.report as Report, ...current.filter((item) => item.id !== data.report?.id)].slice(0, 3)
      )
      router.refresh()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Analysis failed. Your input was not lost.')
    } finally {
      if (progressTimer) window.clearInterval(progressTimer)

      window.setTimeout(() => {
        setIsSubmitting(false)
        setProgress(0)
      }, 650)
    }
  }

  return (
    <main className="relative min-h-screen overflow-hidden bg-[#fafdfb] text-[#0f1f18]">
      {/* Layered ambient light */}
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_10%_-5%,rgba(16,149,80,0.10),transparent_42%),radial-gradient(ellipse_at_90%_-5%,rgba(10,125,60,0.08),transparent_44%),radial-gradient(ellipse_at_50%_110%,rgba(22,163,74,0.05),transparent_50%)]" />
      <div className="pointer-events-none absolute left-[-220px] top-[240px] h-[520px] w-[720px] rounded-full bg-[#e9f8f0]/70 blur-[100px]" />
      <div className="pointer-events-none absolute right-[-220px] top-[60px] h-[600px] w-[720px] rounded-full bg-[#ddf4e8]/50 blur-[100px]" />
      {/* Faint grid texture for depth */}
      <div className="ai-page-grid pointer-events-none absolute inset-0 opacity-[0.5]" />

      <section className="relative mx-auto w-full max-w-none px-5 pb-16 pt-6 2xl:px-10">
        <Hero />

        <section className="mt-8 grid gap-6 xl:grid-cols-[1fr_1.22fr_0.9fr]">
          {/* Panel 1 — Input */}
          <Panel className="min-h-[430px]" number="1" title="Input Your Report" subtitle="File or pasted text">
            {/* Tab switcher */}
            <div className="relative mt-5 grid grid-cols-2 rounded-2xl border border-[#e0eee7] bg-[#f3faf6] p-1">
              <span
                className="absolute inset-y-1 w-[calc(50%-4px)] rounded-xl bg-white shadow-[0_2px_10px_rgba(10,125,60,0.10)] ring-1 ring-[#d4eade] transition-transform duration-300 ease-out"
                style={{ transform: inputMode === 'file' ? 'translateX(4px)' : 'translateX(calc(100% + 4px))' }}
              />
              <button
                type="button"
                onClick={() => setInputMode('file')}
                className={`relative z-10 rounded-xl px-4 py-2.5 text-sm font-semibold transition-colors duration-200 ${
                  inputMode === 'file' ? 'text-[#0a7d3c]' : 'text-[#5e7569] hover:text-[#0f1f18]'
                }`}
              >
                Upload File
              </button>
              <button
                type="button"
                onClick={() => setInputMode('text')}
                className={`relative z-10 rounded-xl px-4 py-2.5 text-sm font-semibold transition-colors duration-200 ${
                  inputMode === 'text' ? 'text-[#0a7d3c]' : 'text-[#5e7569] hover:text-[#0f1f18]'
                }`}
              >
                Paste Text
              </button>
            </div>

            {inputMode === 'file' ? (
              <div
                onDragOver={(event) => {
                  event.preventDefault()
                  setIsDragging(true)
                }}
                onDragLeave={() => setIsDragging(false)}
                onDrop={(event) => {
                  event.preventDefault()
                  setIsDragging(false)
                  chooseFile(event.dataTransfer.files?.[0] ?? null)
                }}
                className={`group relative mt-5 overflow-hidden rounded-[24px] border border-dashed p-8 text-center transition-all duration-300 ${
                  isDragging
                    ? 'border-[#0a7d3c] bg-[#edfaf2] shadow-[0_0_0_4px_rgba(10,125,60,0.08),inset_0_2px_16px_rgba(10,125,60,0.05)]'
                    : 'border-[#bfe2cd] bg-[#f7fdf9] hover:border-[#93cfac] hover:shadow-[0_10px_34px_rgba(15,43,29,0.06)]'
                }`}
              >
                {/* Subtle corner marks */}
                <span className="pointer-events-none absolute left-3.5 top-3.5 h-3.5 w-3.5 rounded-tl border-l border-t border-[#0a7d3c]/30 transition-all duration-300 group-hover:border-[#0a7d3c]/55" />
                <span className="pointer-events-none absolute right-3.5 top-3.5 h-3.5 w-3.5 rounded-tr border-r border-t border-[#0a7d3c]/30 transition-all duration-300 group-hover:border-[#0a7d3c]/55" />
                <span className="pointer-events-none absolute bottom-3.5 left-3.5 h-3.5 w-3.5 rounded-bl border-b border-l border-[#0a7d3c]/30 transition-all duration-300 group-hover:border-[#0a7d3c]/55" />
                <span className="pointer-events-none absolute bottom-3.5 right-3.5 h-3.5 w-3.5 rounded-br border-b border-r border-[#0a7d3c]/30 transition-all duration-300 group-hover:border-[#0a7d3c]/55" />

                {/* Upload icon */}
                <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-2xl border border-[#cbe8d6] bg-white text-[#0a7d3c] shadow-[0_10px_28px_rgba(10,125,60,0.12)] transition-transform duration-300 group-hover:-translate-y-0.5">
                  <Icon name="upload" className="h-6 w-6" />
                </div>

                <p className="text-base font-semibold text-[#0f1f18]">
                  {isDragging ? 'Release to upload' : 'Drag & drop your file here'}
                </p>
                <p className="mt-2 text-sm leading-6 text-[#5e7569]">
                  PDF, DOCX, TXT, MD, LOG, CSV, or JSON&nbsp;&middot;&nbsp;Max 25&nbsp;MB
                </p>

                <label className="mt-5 inline-flex cursor-pointer items-center gap-2 rounded-xl border border-[#bfe2cd] bg-white px-5 py-2.5 text-sm font-semibold text-[#0a7d3c] shadow-[0_4px_16px_rgba(10,125,60,0.09)] transition-all duration-200 hover:-translate-y-0.5 hover:shadow-[0_10px_24px_rgba(10,125,60,0.15)] focus-within:ring-2 focus-within:ring-[#0a7d3c]/30 active:translate-y-0">
                  Browse files
                  <input
                    ref={fileInputRef}
                    type="file"
                    className="hidden"
                    accept=".pdf,.docx,.txt,.md,.log,.csv,.json"
                    onChange={(event) => chooseFile(event.target.files?.[0] ?? null)}
                  />
                </label>
              </div>
            ) : (
              <div className="mt-5">
                <div className="relative">
                  <textarea
                    value={pastedText}
                    onChange={(event) => {
                      setPastedText(event.target.value)
                      clearMessages()
                    }}
                    placeholder="Paste the pentesting report content here..."
                    className="min-h-[220px] w-full resize-y rounded-[22px] border border-[#cbe8d6] bg-[#f7fdf9] p-5 text-sm leading-7 text-[#16261d] outline-none transition-all duration-200 placeholder:text-[#9bb3a7] focus:border-[#0a7d3c] focus:bg-white focus:shadow-[0_0_0_3px_rgba(10,125,60,0.07),0_10px_34px_rgba(10,125,60,0.05)]"
                  />
                  {pastedTextLength >= minTextLength && (
                    <span className="absolute right-4 top-4 flex h-6 w-6 items-center justify-center rounded-full bg-[#0a7d3c] text-white shadow-[0_4px_12px_rgba(10,125,60,0.28)]">
                      <Icon name="check" className="h-3.5 w-3.5" />
                    </span>
                  )}
                </div>
                <p className="mt-2.5 text-sm text-[#5e7569]">
                  <span className={pastedTextLength >= minTextLength ? 'font-semibold text-[#0a7d3c]' : ''}>
                    {pastedTextLength.toLocaleString()}
                  </span>{' '}
                  characters&nbsp;&middot;&nbsp;minimum {minTextLength} required
                </p>
              </div>
            )}

            {/* File info bar */}
            <div className="mt-4 overflow-hidden rounded-2xl border border-[#e0eee7] bg-white shadow-[0_4px_18px_rgba(15,43,29,0.04)]">
              <div className="flex flex-wrap items-center justify-between gap-3 p-4">
                <div className="flex min-w-0 items-center gap-3">
                  <div className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-xl text-[11px] font-bold tracking-wide ${
                    selectedFile || (inputMode === 'text' && pastedTextLength)
                      ? 'bg-[#eaf8ef] text-[#0a7d3c]'
                      : 'bg-[#f0f5f2] text-[#9bb3a7]'
                  }`}>
                    {selectedFile ? shortFileType(selectedFile).slice(0, 4) : inputMode === 'text' && pastedTextLength ? 'TXT' : '—'}
                  </div>
                  <div className="min-w-0">
                    <p className="truncate text-sm font-semibold text-[#0f1f18]">
                      {selectedFile ? selectedFile.name : inputMode === 'text' && pastedTextLength ? 'Pasted report text' : 'No file selected yet'}
                    </p>
                    <p className="truncate text-xs text-[#5e7569]">
                      {selectedFile
                        ? `${formatFileSize(selectedFile.size)} · ${shortFileType(selectedFile)}`
                        : inputMode === 'text' && pastedTextLength
                          ? `${pastedTextLength.toLocaleString()} characters ready for AI preview`
                          : 'Upload or paste content to begin'}
                    </p>
                  </div>
                </div>

                {selectedFile ? (
                  <button
                    type="button"
                    onClick={() => chooseFile(null)}
                    className="rounded-xl border border-red-200 bg-red-50/70 px-3 py-1.5 text-xs font-semibold text-red-600 transition-all duration-200 hover:bg-red-100 active:scale-95"
                  >
                    Remove
                  </button>
                ) : null}
              </div>
            </div>

            {/* Action buttons */}
            <div className="mt-4 grid gap-3 sm:grid-cols-[1fr_auto]">
              <button
                type="button"
                onClick={handleAnalyze}
                disabled={isSubmitting || !canAnalyze || Boolean(selectedFileError)}
                className="ai-button group relative overflow-hidden rounded-2xl px-6 py-3.5 text-sm font-semibold text-white shadow-[0_10px_28px_rgba(10,125,60,0.26),0_2px_6px_rgba(10,125,60,0.14)] transition-all duration-200 hover:-translate-y-0.5 hover:shadow-[0_16px_40px_rgba(10,125,60,0.34)] active:translate-y-0 disabled:cursor-not-allowed disabled:opacity-50 disabled:shadow-none"
              >
                <span className="ai-shimmer pointer-events-none absolute inset-0" />
                <span className="relative inline-flex items-center justify-center gap-2">
                  {isSubmitting ? (
                    <>
                      <Icon name="spinner" className="h-4 w-4 animate-spin" />
                      Analyzing&nbsp;{progress}%
                    </>
                  ) : (
                    <>
                      Start AI Analysis
                      <Icon name="arrow" className="h-4 w-4 transition-transform duration-200 group-hover:translate-x-0.5" />
                    </>
                  )}
                </span>
              </button>

              <button
                type="button"
                onClick={resetInput}
                disabled={isSubmitting}
                className="rounded-2xl border border-[#cbe8d6] bg-white px-5 py-3.5 text-sm font-semibold text-[#16261d] transition-all duration-200 hover:-translate-y-0.5 hover:border-[#93cfac] hover:bg-[#f5fdf8] hover:shadow-[0_10px_24px_rgba(15,43,29,0.06)] active:translate-y-0 disabled:cursor-not-allowed disabled:opacity-50"
              >
                Reset
              </button>
            </div>

            {selectedFileError ? <Message tone="danger">{selectedFileError}</Message> : null}
            {error ? <Message tone="danger">{error}</Message> : null}
            {success ? <Message tone="ready">{success}</Message> : null}
          </Panel>

          {/* Panel 2 — Pipeline Progress */}
          <Panel className="relative min-h-[430px] overflow-hidden" number="2" title="AI Analysis Pipeline" subtitle="Eight-stage processing">
            <div className="pointer-events-none absolute inset-y-0 right-0 hidden w-[42%] bg-[radial-gradient(ellipse_at_62%_42%,rgba(16,149,80,0.09),transparent_56%)] lg:block" />
            <div className="relative mt-5 grid gap-5 lg:grid-cols-[1fr_0.72fr]">
              <div className="space-y-2.5">
                {analysisSteps.map((step, index) => {
                  const status: StepStatus = createdReport
                    ? 'done'
                    : isSubmitting && index < activeStep
                      ? 'done'
                      : isSubmitting && index === activeStep
                        ? 'active'
                        : 'pending'

                  return (
                    <PipelineStep
                      key={step.title}
                      index={index + 1}
                      title={step.title}
                      detail={step.detail}
                      status={status}
                    />
                  )
                })}
              </div>

              <div className="hidden min-h-[360px] flex-col justify-center lg:flex">
                <AICylinder3D active={isSubmitting || Boolean(createdReport)} />
                <div className="mt-3 overflow-hidden rounded-[20px] border border-[#e0eee7] bg-white/90 p-4 shadow-[0_12px_36px_rgba(15,43,29,0.06)] backdrop-blur">
                  <div className="flex items-center justify-between gap-2">
                    <div>
                      <p className="text-sm font-semibold text-[#0f1f18]">AI Engine Status</p>
                      <p className="mt-0.5 text-xs text-[#5e7569]">Model: CTX-NLP v2.1</p>
                    </div>
                    <span className={`text-sm font-bold tabular-nums ${isSubmitting || createdReport ? 'text-[#0a7d3c]' : 'text-[#9bb3a7]'}`}>
                      {isSubmitting ? `${progress}%` : createdReport ? '100%' : 'Ready'}
                    </span>
                  </div>
                  <ProgressBar value={isSubmitting ? progress : createdReport ? 100 : 18} className="mt-3" />
                  {isSubmitting && (
                    <p className="mt-2 line-clamp-1 text-[11px] text-[#5e7569]">
                      {analysisSteps[activeStep]?.detail ?? ''}
                    </p>
                  )}
                </div>
              </div>
            </div>
          </Panel>

          {/* Panel 3 — AI Reasoning Lab */}
          <aside>
            <AIReasoningLab
              isSubmitting={isSubmitting}
              hasPreview={Boolean(preview)}
              hasReport={Boolean(createdReport)}
              sections={preview?.stats.sectionCount ?? 0}
              signals={preview?.stats.indicatorCount ?? 0}
              riskScore={summary.riskScore}
              confidence={createdReport ? output.confidence : preview ? 74 : 0}
            />
          </aside>
        </section>

        {/* Row 2 — Summary + Actions */}
        <section className="mt-6 grid gap-6 xl:grid-cols-[1fr_0.44fr]">
          <Panel number="3" title="Analysis Summary" subtitle="Live metrics overview">
            {/* Metric grid */}
            <div className="mt-5 grid grid-cols-2 gap-3 sm:grid-cols-4 xl:grid-cols-8">
              <Metric
                label="Findings"
                value={summary.totalFindings || '-'}
                helper={createdReport ? 'AI extracted' : 'Preview'}
                accent="green"
              />
              <Metric
                label="Critical"
                value={output.severityCounts.find((s) => s.severity === 'Critical')?.count ?? 0}
                helper="High priority"
                accent="red"
              />
              <Metric
                label="High"
                value={output.severityCounts.find((s) => s.severity === 'High')?.count ?? 0}
                helper="Needs attention"
                accent="amber"
              />
              <Metric
                label="Medium"
                value={output.severityCounts.find((s) => s.severity === 'Medium')?.count ?? 0}
                helper="Monitor"
                accent="gold"
              />
              <Metric
                label="Low"
                value={output.severityCounts.find((s) => s.severity === 'Low')?.count ?? 0}
                helper="Informational"
                accent="slate"
              />
              <Metric
                label="CVEs"
                value={summary.cves || '-'}
                helper="Known CVEs"
                accent="slate"
              />
              <Metric
                label="Risk Score"
                value={summary.riskScore || '-'}
                helper={summary.riskScore ? riskBand(summary.riskScore) : 'Waiting'}
                accent={summary.riskScore >= 80 ? 'red' : summary.riskScore >= 60 ? 'amber' : 'green'}
              />
              <Metric
                label="Review"
                value={summary.needsReview || '-'}
                helper="Need review"
                accent="amber"
              />
            </div>

            {/* Key insights strip */}
            <div className="mt-5 overflow-hidden rounded-[22px] border border-[#e0eee7] bg-gradient-to-br from-[#f3faf6] to-[#fbfffd] shadow-[0_4px_22px_rgba(15,43,29,0.04)]">
              <div className="grid lg:grid-cols-[auto_1fr_1fr_1fr_1fr]">
                <div className="relative flex flex-col justify-center overflow-hidden bg-gradient-to-br from-[#0a7d3c] to-[#0e9550] p-5 lg:rounded-l-[22px]">
                  <span className="pointer-events-none absolute inset-x-0 top-0 h-px bg-white/25" />
                  <p className="text-[10px] font-bold uppercase tracking-[0.22em] text-white/70">Key</p>
                  <p className="mt-0.5 text-lg font-bold tracking-[-0.02em] text-white">Insights</p>
                  <p className="mt-1 text-xs font-medium text-white/65">Generated by AI</p>
                </div>
                <InsightText icon="search">
                  {createdReport
                    ? `AI extracted ${output.totalFindings} findings from ${createdReport.name}.`
                    : preview
                      ? `AI preview found ${preview.stats.sectionCount} sections and ${preview.stats.indicatorCount} indicators.`
                      : 'Upload or paste a report to let AI produce security insight.'}
                </InsightText>
                <InsightText icon="shield">
                  {createdReport
                    ? `${output.cves} CVE references and ${output.assets} affected assets were detected.`
                    : 'CVEs, assets, evidence, impact, and remediation will be extracted.'}
                </InsightText>
                <InsightText icon="eye">
                  {createdReport
                    ? `${output.needsReview} findings require manual review based on confidence and evidence.`
                    : 'Low-confidence or missing-evidence findings will be marked for review.'}
                </InsightText>
                <InsightText icon="chart">
                  {createdReport
                    ? `Risk score ${output.riskScore}/100 indicates ${riskBand(output.riskScore).toLowerCase()} exposure.`
                    : 'Risk score will be generated after analysis is complete.'}
                </InsightText>
              </div>
            </div>
          </Panel>

          <Panel number="4" title="Next Actions" subtitle="Continue your workflow">
            <div className="mt-5 grid gap-2.5 sm:grid-cols-2 xl:grid-cols-1 2xl:grid-cols-2">
              <Action
                href={createdReport ? `/reports/${createdReport.id}` : '/reports'}
                title="View Full Report"
                detail="Extracted report details"
                state={createdReport ? 'Ready' : 'Browse'}
                icon="document"
                ready={Boolean(createdReport)}
              />
              <Action
                href={createdReport ? `/results?reportId=${encodeURIComponent(createdReport.id)}` : '/results'}
                title="View Findings"
                detail="Browse extracted findings"
                state={createdReport ? 'Filtered' : 'All'}
                icon="list"
                ready={Boolean(createdReport)}
              />
              <Action
                href={createdReport ? `/risk-scoring?reportId=${encodeURIComponent(createdReport.id)}` : '/risk-scoring'}
                title="Risk Score"
                detail="Detailed risk calculation"
                state={createdReport ? 'Run' : 'Select'}
                icon="bolt"
                ready={Boolean(createdReport)}
              />
              <Action
                href={createdReport ? `/graph?reportId=${encodeURIComponent(createdReport.id)}` : '/graph'}
                title="Knowledge Graph"
                detail="Explore relationships"
                state={createdReport ? 'Mapped' : 'Graph'}
                icon="graph"
                ready={Boolean(createdReport)}
              />
              <Action
                href={createdReport ? `/summarization?reportId=${encodeURIComponent(createdReport.id)}` : '/summarization'}
                title="Generate Summary"
                detail="Executive AI summary"
                state={createdReport ? 'Run' : 'Select'}
                icon="summary"
                ready={Boolean(createdReport)}
              />
              <Action
                href={createdReport ? `/export?reportId=${encodeURIComponent(createdReport.id)}` : '/export'}
                title="Export Report"
                detail="Download analysis results"
                state={createdReport ? 'Ready' : 'Export'}
                icon="download"
                ready={Boolean(createdReport)}
              />
            </div>
          </Panel>
        </section>

        {/* Footer badge */}
        <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
          <div className="flex items-center gap-2.5 rounded-full border border-[#d6ecdf] bg-white/80 px-5 py-2 text-xs font-medium text-[#5e7569] shadow-[0_2px_12px_rgba(15,43,29,0.04)] backdrop-blur">
            <Icon name="lock" className="h-3.5 w-3.5 text-[#0a7d3c]" />
            Your data is secure and private.
            <span className="h-3 w-px bg-[#cbe8d6]" />
            Reports are processed through the isolated analysis pipeline.
          </div>
        </div>
      </section>

      {isSubmitting ? <AnalysisOverlay progress={progress} activeStep={activeStep} /> : null}

      <style>{`
        /* ── Page grid texture ───────────────────── */
        .ai-page-grid {
          background-image:
            linear-gradient(rgba(10,125,60,0.035) 1px, transparent 1px),
            linear-gradient(90deg, rgba(10,125,60,0.035) 1px, transparent 1px);
          background-size: 46px 46px;
          mask-image: radial-gradient(ellipse at 50% 30%, black, transparent 78%);
          -webkit-mask-image: radial-gradient(ellipse at 50% 30%, black, transparent 78%);
        }

        /* ── Orb / pulse ─────────────────────────── */
        @keyframes ai-orb-pulse {
          0%, 100% { transform: translateZ(18px) scale(1); box-shadow: 0 22px 64px rgba(10,125,60,0.18); }
          50%       { transform: translateZ(32px) scale(1.04); box-shadow: 0 32px 96px rgba(10,125,60,0.28); }
        }
        @keyframes ai-ring-pulse {
          0%   { transform: translate(-50%, -50%) scale(0.86); opacity: 0.6; }
          70%  { transform: translate(-50%, -50%) scale(1.18); opacity: 0.10; }
          100% { transform: translate(-50%, -50%) scale(1.24); opacity: 0; }
        }

        /* ── Rings ───────────────────────────────── */
        @keyframes ai-ring-spin {
          from { transform: rotateX(72deg) rotateZ(0deg); }
          to   { transform: rotateX(72deg) rotateZ(360deg); }
        }
        @keyframes ai-ring-spin-rev {
          from { transform: rotateX(66deg) rotateZ(360deg); }
          to   { transform: rotateX(66deg) rotateZ(0deg); }
        }

        /* ── Particle stream ─────────────────────── */
        @keyframes ai-flow {
          from { stroke-dashoffset: 900; }
          to   { stroke-dashoffset: 0; }
        }
        @keyframes ai-particle {
          0%   { transform: translateX(-20px); opacity: 0; }
          15%  { opacity: 1; }
          90%  { opacity: 0.5; }
          100% { transform: translateX(1600px); opacity: 0; }
        }

        /* ── Document float ──────────────────────── */
        @keyframes ai-document-float {
          0%, 100% { transform: translate3d(-50%, -50%, 30px) rotateY(-18deg) rotateX(9deg); }
          50%       { transform: translate3d(-50%, calc(-50% - 10px), 46px) rotateY(18deg) rotateX(12deg); }
        }
        @keyframes ai-scan {
          0%, 100% { transform: translateY(0); opacity: 0.2; }
          50%       { transform: translateY(50px); opacity: 0.7; }
        }

        /* ── Button shimmer ──────────────────────── */
        @keyframes ai-button-flow {
          from { background-position: 0% 50%; }
          to   { background-position: 200% 50%; }
        }
        @keyframes ai-shimmer {
          0%   { transform: translateX(-110%) skewX(-12deg); }
          100% { transform: translateX(230%) skewX(-12deg); }
        }
        .ai-button {
          background-image: linear-gradient(110deg, #066f34, #0a7d3c, #0e9550, #0a7d3c, #066f34);
          background-size: 240% 100%;
          animation: ai-button-flow 7s linear infinite;
        }
        .ai-shimmer::after {
          content: '';
          position: absolute;
          inset: 0;
          background: linear-gradient(90deg, transparent 0%, rgba(255,255,255,0.16) 50%, transparent 100%);
          animation: ai-shimmer 3s ease-in-out infinite;
        }

        /* ── Stream paths ────────────────────────── */
        .ai-stream-path {
          stroke-dasharray: 24 22;
          animation: ai-flow 14s linear infinite;
        }
        .ai-stream-path-slow {
          stroke-dasharray: 18 28;
          animation: ai-flow 21s linear infinite reverse;
        }
        .ai-stream-path-ultra {
          stroke-dasharray: 10 36;
          animation: ai-flow 28s linear infinite;
        }
        .ai-particle { animation: ai-particle 9s linear infinite; }

        /* ── Orb ─────────────────────────────────── */
        .ai-orb {
          transform-style: preserve-3d;
          animation: ai-orb-pulse 4s ease-in-out infinite;
          will-change: transform;
        }
        .ai-ring-pulse {
          animation: ai-ring-pulse 3s ease-out infinite;
          transform-origin: center;
        }
        .ai-ring-pulse-delay {
          animation: ai-ring-pulse 3s ease-out infinite;
          animation-delay: 1.5s;
          transform-origin: center;
        }

        /* ── Cards ───────────────────────────────── */
        .ai-tilt-card {
          transform-style: preserve-3d;
          transition: transform 300ms ease, box-shadow 300ms ease, border-color 300ms ease;
        }
        .ai-tilt-card:hover {
          transform: perspective(1100px) rotateX(0.8deg) rotateY(-1deg) translateY(-2px);
        }

        /* ── Platform / rings ────────────────────── */
        .ai-platform-3d { transform: perspective(900px) rotateX(68deg); }
        .ai-ring-3d {
          transform-style: preserve-3d;
          animation: ai-ring-spin 11s linear infinite;
        }
        .ai-ring-3d-rev {
          transform-style: preserve-3d;
          animation: ai-ring-spin-rev 15s linear infinite;
        }

        /* ── Document ────────────────────────────── */
        .ai-document-3d {
          animation: ai-document-float 4.6s ease-in-out infinite;
          transform-style: preserve-3d;
          will-change: transform;
        }
        .ai-scan-line { animation: ai-scan 3s ease-in-out infinite; }

        /* ── Grid backdrop ───────────────────────── */
        @keyframes ai-grid-drift {
          from { transform: translate3d(0, 0, 0); }
          to   { transform: translate3d(28px, 28px, 0); }
        }
        .ai-grid-bg {
          background-image:
            linear-gradient(rgba(10,125,60,0.06) 1px, transparent 1px),
            linear-gradient(90deg, rgba(10,125,60,0.06) 1px, transparent 1px);
          background-size: 26px 26px;
          animation: ai-grid-drift 22s linear infinite;
        }

        /* ── Scan sweep ──────────────────────────── */
        @keyframes ai-scan-sweep {
          0%   { transform: translateY(-130%); opacity: 0; }
          20%  { opacity: 0.32; }
          100% { transform: translateY(130%); opacity: 0; }
        }
        .ai-scan-sweep {
          background: linear-gradient(180deg, transparent, rgba(10,125,60,0.15), transparent);
          animation: ai-scan-sweep 5s ease-in-out infinite;
        }

        /* ── Core ────────────────────────────────── */
        @keyframes ai-core-float {
          0%, 100% { transform: translate3d(-50%, -50%, 34px) rotateX(10deg) rotateY(-16deg); }
          50%       { transform: translate3d(-50%, calc(-50% - 10px), 52px) rotateX(13deg) rotateY(18deg); }
        }
        @keyframes ai-core-ring-spin {
          from { transform: translate(-50%, -50%) rotateX(70deg) rotateZ(0deg); }
          to   { transform: translate(-50%, -50%) rotateX(70deg) rotateZ(360deg); }
        }
        @keyframes ai-core-ring-rev {
          from { transform: translate(-50%, -50%) rotateX(62deg) rotateZ(360deg); }
          to   { transform: translate(-50%, -50%) rotateX(62deg) rotateZ(0deg); }
        }
        .ai-core-platform { transform: perspective(900px) rotateX(68deg); }
        .ai-core-ring {
          transform-style: preserve-3d;
          animation: ai-core-ring-spin 10s linear infinite;
        }
        .ai-core-ring-rev {
          transform-style: preserve-3d;
          animation: ai-core-ring-rev 14s linear infinite;
        }
        .ai-core-cube {
          transform-style: preserve-3d;
          animation: ai-core-float 4.8s ease-in-out infinite;
          will-change: transform;
        }

        /* ── Progress bar glow ───────────────────── */
        @keyframes ai-bar-glow {
          0%, 100% { box-shadow: 0 0 0 0 rgba(10,125,60,0); }
          50%       { box-shadow: 0 0 10px 1px rgba(10,125,60,0.22); }
        }
        .ai-bar-fill { animation: ai-bar-glow 2.6s ease-in-out infinite; }

        /* ── Step pulse ──────────────────────────── */
        @keyframes ai-dot-ping {
          0%   { transform: scale(1); opacity: 0.9; }
          80%  { transform: scale(2.1); opacity: 0; }
          100% { transform: scale(2.1); opacity: 0; }
        }
        .ai-dot-ping { animation: ai-dot-ping 1.6s ease-out infinite; }

        /* ── Reduced motion ──────────────────────── */
        @media (prefers-reduced-motion: reduce) {
          .ai-button,
          .ai-stream-path, .ai-stream-path-slow, .ai-stream-path-ultra,
          .ai-particle, .ai-orb,
          .ai-ring-3d, .ai-ring-3d-rev,
          .ai-ring-pulse, .ai-ring-pulse-delay,
          .ai-document-3d, .ai-scan-line,
          .ai-grid-bg, .ai-scan-sweep,
          .ai-core-ring, .ai-core-ring-rev, .ai-core-cube,
          .ai-bar-fill, .ai-dot-ping {
            animation: none !important;
          }
          .ai-tilt-card, .ai-tilt-card:hover { transform: none !important; }
        }
      `}</style>
    </main>
  )
}

/* ═══════════════════════════════════════════
   Icon — minimal inline line icons (no emojis)
═══════════════════════════════════════════ */
function Icon({ name, className = '' }: { name: string; className?: string }) {
  const common = {
    className,
    viewBox: '0 0 24 24',
    fill: 'none',
    stroke: 'currentColor',
    strokeWidth: 1.7,
    strokeLinecap: 'round' as const,
    strokeLinejoin: 'round' as const,
  }

  switch (name) {
    case 'upload':
      return (
        <svg {...common}>
          <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
          <path d="M7 8l5-5 5 5" />
          <path d="M12 3v12" />
        </svg>
      )
    case 'check':
      return (
        <svg {...common}>
          <path d="M4 12l5 5L20 6" />
        </svg>
      )
    case 'arrow':
      return (
        <svg {...common}>
          <path d="M4 12h15" />
          <path d="M13 6l6 6-6 6" />
        </svg>
      )
    case 'spinner':
      return (
        <svg {...common}>
          <path d="M21 12a9 9 0 1 1-6.2-8.6" />
        </svg>
      )
    case 'lock':
      return (
        <svg {...common}>
          <rect x="4.5" y="10.5" width="15" height="10" rx="2" />
          <path d="M8 10.5V7.5a4 4 0 0 1 8 0v3" />
        </svg>
      )
    case 'search':
      return (
        <svg {...common}>
          <circle cx="11" cy="11" r="6.5" />
          <path d="M20 20l-4-4" />
        </svg>
      )
    case 'shield':
      return (
        <svg {...common}>
          <path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6z" />
          <path d="M9 12l2 2 4-4" />
        </svg>
      )
    case 'eye':
      return (
        <svg {...common}>
          <path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z" />
          <circle cx="12" cy="12" r="2.8" />
        </svg>
      )
    case 'chart':
      return (
        <svg {...common}>
          <path d="M4 20V10" />
          <path d="M10 20V4" />
          <path d="M16 20v-7" />
          <path d="M22 20H2" />
        </svg>
      )
    case 'document':
      return (
        <svg {...common}>
          <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z" />
          <path d="M14 3v5h5" />
          <path d="M9 13h6M9 17h6" />
        </svg>
      )
    case 'list':
      return (
        <svg {...common}>
          <path d="M9 6h11M9 12h11M9 18h11" />
          <circle cx="4.5" cy="6" r="1" fill="currentColor" stroke="none" />
          <circle cx="4.5" cy="12" r="1" fill="currentColor" stroke="none" />
          <circle cx="4.5" cy="18" r="1" fill="currentColor" stroke="none" />
        </svg>
      )
    case 'bolt':
      return (
        <svg {...common}>
          <path d="M13 2L4 14h7l-1 8 9-12h-7z" />
        </svg>
      )
    case 'graph':
      return (
        <svg {...common}>
          <circle cx="6" cy="6" r="2.4" />
          <circle cx="18" cy="7" r="2.4" />
          <circle cx="12" cy="18" r="2.4" />
          <path d="M7.7 7.6l3 8M16.5 9l-3.4 7M8 6.5h7.5" />
        </svg>
      )
    case 'summary':
      return (
        <svg {...common}>
          <rect x="4" y="4" width="16" height="16" rx="2" />
          <path d="M8 9h8M8 13h8M8 17h5" />
        </svg>
      )
    case 'download':
      return (
        <svg {...common}>
          <path d="M12 4v11" />
          <path d="M7 11l5 5 5-5" />
          <path d="M5 20h14" />
        </svg>
      )
    default:
      return null
  }
}

/* ═══════════════════════════════════════════
   Hero
═══════════════════════════════════════════ */
function Hero() {
  return (
    <header className="relative min-h-[180px] overflow-hidden rounded-[30px] border border-[#e0eee7]/90 bg-white/45 px-3 py-4 shadow-[0_10px_44px_rgba(15,43,29,0.06)] backdrop-blur-sm">
      <span className="pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-[#0a7d3c]/35 to-transparent" />
      <NeuralStream />

      <div className="relative z-10 grid gap-6 xl:grid-cols-[0.56fr_0.60fr_0.44fr]">
        {/* Left — headline */}
        <div className="pt-5">
          <div className="mb-3 inline-flex items-center gap-2 rounded-full border border-[#cbe8d6] bg-white/85 px-3.5 py-1.5 text-xs font-semibold text-[#0a7d3c] shadow-[0_2px_10px_rgba(10,125,60,0.06)] backdrop-blur">
            <span className="relative flex h-1.5 w-1.5">
              <span className="ai-dot-ping absolute inset-0 rounded-full bg-[#0a7d3c]/40" />
              <span className="relative h-1.5 w-1.5 rounded-full bg-[#0a7d3c]" />
            </span>
            AI-Powered CTI Platform
          </div>
          <h1 className="text-4xl font-bold tracking-[-0.05em] text-[#0f1f18] md:text-5xl">
            <span className="hero-gradient-text">AI Report</span>
            <br className="hidden sm:block" />
            {' '}Analyzer
          </h1>
          <p className="mt-4 max-w-xl text-base leading-8 text-[#46594f]">
            Upload or paste a pentesting report and let our AI extract vulnerabilities, assess risk, and generate actionable intelligence.
          </p>
        </div>

        {/* Center — orb */}
        <div className="hidden min-h-[160px] items-center justify-center xl:flex">
          <div className="relative">
            <div className="ai-orb relative grid h-28 w-28 place-items-center rounded-full border border-[#bfe2cd] bg-white/90 text-2xl font-bold tracking-[-0.08em] text-[#0a7d3c] shadow-[0_26px_72px_rgba(10,125,60,0.22)] backdrop-blur">
              <span className="relative z-10">AI</span>
              <span className="absolute inset-3 rounded-full bg-[radial-gradient(circle,rgba(10,125,60,0.10),transparent_70%)]" />
              <span className="absolute inset-0 rounded-full ring-1 ring-inset ring-white/60" />
            </div>
            <span className="ai-ring-pulse absolute left-1/2 top-1/2 h-44 w-44 rounded-full border border-[#aeddc1]" />
            <span className="ai-ring-pulse-delay absolute left-1/2 top-1/2 h-56 w-56 rounded-full border border-[#cfeeda]" />
          </div>
        </div>

        {/* Right — tech card */}
        <div className="ai-tilt-card relative overflow-hidden rounded-[24px] border border-[#e0eee7] bg-white/90 p-5 shadow-[0_22px_64px_rgba(15,43,29,0.09),0_2px_8px_rgba(15,43,29,0.04)] backdrop-blur">
          <span className="pointer-events-none absolute inset-x-0 top-0 h-0.5 bg-gradient-to-r from-[#0a7d3c]/50 via-[#16a34a] to-[#0a7d3c]/50" />
          <p className="text-base font-bold tracking-[-0.02em] text-[#0f1f18]">
            Powered by <span className="text-[#0a7d3c]">Advanced AI</span>
          </p>
          <p className="mt-2.5 text-sm leading-6 text-[#5e7569]">
            Our AI models read unstructured content, understand context, and extract what matters most.
          </p>
          <div className="mt-4 flex flex-wrap gap-2">
            <Tag>NLP</Tag>
            <Tag>NER</Tag>
            <Tag>Context AI</Tag>
            <Tag>ML</Tag>
          </div>
          <div className="mt-4 grid grid-cols-3 divide-x divide-[#e6f2ec] overflow-hidden rounded-xl border border-[#e6f2ec] bg-[#f7fdf9]">
            {[['8', 'Steps'], ['NLP', 'Engine'], ['v2.1', 'Model']].map(([val, lbl]) => (
              <div key={lbl} className="py-2 text-center">
                <p className="text-sm font-bold text-[#0a7d3c]">{val}</p>
                <p className="text-[10px] font-semibold uppercase tracking-[0.12em] text-[#7d9a8b]">{lbl}</p>
              </div>
            ))}
          </div>
        </div>
      </div>

      <style>{`
        .hero-gradient-text {
          background: linear-gradient(135deg, #0a7d3c 0%, #16a34a 48%, #0e9550 100%);
          -webkit-background-clip: text;
          -webkit-text-fill-color: transparent;
          background-clip: text;
        }
      `}</style>
    </header>
  )
}

/* ═══════════════════════════════════════════
   NeuralStream
═══════════════════════════════════════════ */
function NeuralStream() {
  return (
    <div className="pointer-events-none absolute inset-0 overflow-hidden">
      <svg
        className="absolute inset-x-0 top-0 h-[200px] w-full"
        viewBox="0 0 1500 200"
        preserveAspectRatio="none"
        aria-hidden="true"
      >
        <defs>
          <linearGradient id="ns-main" x1="0" x2="1" y1="0" y2="0">
            <stop offset="0" stopColor="#0a7d3c" stopOpacity="0" />
            <stop offset="0.5" stopColor="#0a7d3c" stopOpacity="0.34" />
            <stop offset="1" stopColor="#16a34a" stopOpacity="0" />
          </linearGradient>
          <linearGradient id="ns-soft" x1="0" x2="1" y1="0" y2="0">
            <stop offset="0" stopColor="#16a34a" stopOpacity="0" />
            <stop offset="0.5" stopColor="#16a34a" stopOpacity="0.15" />
            <stop offset="1" stopColor="#0a7d3c" stopOpacity="0" />
          </linearGradient>
          <linearGradient id="ns-ultra" x1="0" x2="1" y1="0" y2="0">
            <stop offset="0" stopColor="#22c55e" stopOpacity="0" />
            <stop offset="0.5" stopColor="#22c55e" stopOpacity="0.09" />
            <stop offset="1" stopColor="#22c55e" stopOpacity="0" />
          </linearGradient>
        </defs>
        <path className="ai-stream-path" d="M0 84 C160 24 230 150 360 92 S560 20 710 92 S960 150 1090 76 S1320 42 1500 86" fill="none" stroke="url(#ns-main)" strokeWidth="1.3" />
        <path className="ai-stream-path-slow" d="M0 118 C150 66 270 142 390 108 S590 54 748 105 S988 142 1128 102 S1328 74 1500 115" fill="none" stroke="url(#ns-soft)" strokeWidth="1" />
        <path className="ai-stream-path-ultra" d="M0 160 C200 120 320 175 480 148 S680 110 860 155 S1100 185 1280 148 S1400 130 1500 165" fill="none" stroke="url(#ns-ultra)" strokeWidth="0.8" />
      </svg>
      {Array.from({ length: 16 }).map((_, index) => (
        <span
          key={index}
          className="ai-particle absolute h-[2px] w-[2px] rounded-full bg-[#0a7d3c]/35"
          style={{
            top: `${50 + (index % 5) * 20}px`,
            left: `${index * 92 - 200}px`,
            animationDelay: `${index * 0.5}s`,
            animationDuration: `${8 + (index % 4)}s`,
          }}
        />
      ))}
    </div>
  )
}

/* ═══════════════════════════════════════════
   AICylinder3D
═══════════════════════════════════════════ */
function AICylinder3D({ active }: { active: boolean }) {
  return (
    <div className="relative mx-auto h-[240px] w-full max-w-[300px] [perspective:900px]">
      <div className="absolute left-1/2 top-[44%] h-36 w-36 -translate-x-1/2 -translate-y-1/2 rounded-full bg-[#0a7d3c]/10 blur-2xl" />
      <div className="ai-platform-3d absolute bottom-6 left-1/2 h-20 w-56 -translate-x-1/2 rounded-[50%] border border-[#b4dfc5] bg-gradient-to-b from-white via-[#e4f7ec] to-[#0a7d3c]/20 shadow-[0_28px_60px_rgba(10,125,60,0.18)]" />
      <div className={`ai-ring-3d absolute bottom-[68px] left-1/2 h-28 w-28 -translate-x-1/2 rounded-full border border-[#c4ecd2] ${active ? '' : '[animation-play-state:paused]'}`} />
      <div className={`ai-ring-3d-rev absolute bottom-[82px] left-1/2 h-44 w-44 -translate-x-1/2 rounded-full border border-[#d8f2e2] ${active ? '' : '[animation-play-state:paused]'}`} />
      <div className={`ai-document-3d absolute left-1/2 top-[40%] h-24 w-20 overflow-hidden rounded-[16px] border border-[#bfe2cd] bg-white/90 p-4 shadow-[0_30px_80px_rgba(10,125,60,0.20)] backdrop-blur ${active ? '' : '[animation-play-state:paused]'}`}>
        <div className="h-2 w-9 rounded-full bg-[#0a7d3c]/55" />
        <div className="mt-3 h-1.5 w-12 rounded-full bg-[#c4ecd2]" />
        <div className="mt-2 h-1.5 w-10 rounded-full bg-[#c4ecd2]" />
        <div className="mt-2 h-1.5 w-14 rounded-full bg-[#c4ecd2]" />
        <div className={`ai-scan-line absolute left-3 top-5 h-px w-14 bg-gradient-to-r from-[#0a7d3c]/75 to-transparent ${active ? '' : '[animation-play-state:paused]'}`} />
      </div>
      <div className="absolute left-1/2 top-3 h-[180px] w-px -translate-x-1/2 bg-gradient-to-b from-transparent via-[#0a7d3c]/45 to-transparent opacity-55" />
      <div className={`absolute bottom-5 left-1/2 -translate-x-1/2 whitespace-nowrap rounded-full border px-4 py-1 text-xs font-semibold shadow-sm transition-all duration-500 ${
        active
          ? 'border-[#9ad6b1] bg-[#eafaf0] text-[#0a7d3c]'
          : 'border-[#cbe8d6] bg-white/85 text-[#5e7569]'
      }`}>
        {active ? 'AI reasoning active' : 'AI ready'}
      </div>
    </div>
  )
}

/* ═══════════════════════════════════════════
   Panel
═══════════════════════════════════════════ */
function Panel({
  number,
  title,
  subtitle,
  compact = false,
  className = '',
  children,
}: {
  number?: string
  title: string
  subtitle?: string
  compact?: boolean
  className?: string
  children: ReactNode
}) {
  return (
    <section className={`ai-tilt-card relative overflow-hidden rounded-[26px] border border-[#e3efe9] bg-white/92 ${compact ? 'p-5' : 'p-6'} shadow-[0_18px_56px_rgba(15,43,29,0.07),0_2px_8px_rgba(15,43,29,0.035)] backdrop-blur ${className}`}>
      <span className="pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-[#0a7d3c]/22 to-transparent" />
      <div className="flex items-center gap-3">
        {number ? (
          <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-xl bg-gradient-to-br from-[#eaf8ef] to-[#dcf3e6] text-sm font-bold text-[#0a7d3c] ring-1 ring-inset ring-[#cbe8d6]">
            {number}
          </span>
        ) : null}
        <div>
          <h2 className="text-lg font-bold leading-tight tracking-[-0.025em] text-[#0f1f18]">{title}</h2>
          {subtitle ? <p className="text-xs font-medium text-[#7d9a8b]">{subtitle}</p> : null}
        </div>
      </div>
      {children}
    </section>
  )
}

/* ═══════════════════════════════════════════
   PipelineStep
═══════════════════════════════════════════ */
function PipelineStep({
  index,
  title,
  detail,
  status,
}: {
  index: number
  title: string
  detail: string
  status: StepStatus
}) {
  const active = status === 'active'
  const done = status === 'done'

  return (
    <div className={`relative overflow-hidden rounded-[16px] border px-3.5 py-3 transition-all duration-300 ${
      active
        ? 'border-[#8fd3a8] bg-[#ecfaf2] shadow-[0_8px_26px_rgba(10,125,60,0.10),inset_0_1px_0_rgba(255,255,255,0.8)]'
        : done
          ? 'border-[#c8ecd6] bg-[#f5fdf8]'
          : 'border-[#e6f0ea] bg-white/70'
    }`}>
      {active && <span className="absolute left-0 top-2.5 bottom-2.5 w-[3px] rounded-full bg-[#0a7d3c]" />}

      <div className="grid grid-cols-[30px_1fr_auto] items-center gap-3">
        <span className={`relative flex h-7 w-7 shrink-0 items-center justify-center rounded-full text-xs font-bold transition-all duration-300 ${
          done
            ? 'bg-[#0a7d3c] text-white shadow-[0_4px_12px_rgba(10,125,60,0.26)]'
            : active
              ? 'bg-white text-[#0a7d3c] shadow-[0_4px_14px_rgba(10,125,60,0.14)] ring-2 ring-[#0a7d3c]/30'
              : 'bg-[#eef4f0] text-[#7d9a8b]'
        }`}>
          {done ? <Icon name="check" className="h-3.5 w-3.5" /> : index}
          {active && <span className="ai-dot-ping absolute inset-0 rounded-full bg-[#0a7d3c]/20" />}
        </span>

        <div className="min-w-0">
          <p className={`text-sm font-semibold leading-tight transition-colors duration-200 ${active ? 'text-[#0a7d3c]' : done ? 'text-[#0d5e30]' : 'text-[#0f1f18]'}`}>
            {title}
          </p>
          <p className="mt-0.5 line-clamp-1 text-[11px] text-[#5e7569]">{detail}</p>
        </div>

        <span className={`shrink-0 text-[10px] font-bold uppercase tracking-[0.14em] ${
          active ? 'text-[#0a7d3c]' : done ? 'text-[#3da765]' : 'text-[#9bb3a7]'
        }`}>
          {active ? 'Active' : done ? 'Done' : 'Queued'}
        </span>
      </div>
    </div>
  )
}

/* ═══════════════════════════════════════════
   AIReasoningLab
═══════════════════════════════════════════ */
function AIReasoningLab({
  isSubmitting,
  hasPreview,
  hasReport,
  sections,
  signals,
  riskScore,
  confidence,
}: {
  isSubmitting: boolean
  hasPreview: boolean
  hasReport: boolean
  sections: number
  signals: number
  riskScore: number
  confidence: number
}) {
  const stage = hasReport ? 'completed' : isSubmitting ? 'reasoning' : hasPreview ? 'preview' : 'waiting'
  const stageLabel = hasReport ? 'AI completed' : isSubmitting ? 'AI reasoning' : hasPreview ? 'AI preview ready' : 'Waiting for input'
  const stageDetail = hasReport
    ? 'The model extracted entities, mapped relations, and prepared next actions.'
    : isSubmitting
      ? 'The model is reading context, identifying entities, and scoring risk.'
      : hasPreview
        ? 'The local AI preview detected early structure and signals.'
        : 'Upload or paste a report to activate the reasoning console.'

  return (
    <Panel title="AI Reasoning Console" subtitle="Real-time model state" compact>
      <div className="relative mt-4 overflow-hidden rounded-[22px] border border-[#c8ecd6] bg-[radial-gradient(ellipse_at_50%_0%,rgba(10,125,60,0.14),transparent_50%),linear-gradient(180deg,#ffffff,#f3fdf6)] p-5 shadow-[0_20px_56px_rgba(10,125,60,0.09)]">
        <div className="pointer-events-none absolute inset-0 opacity-55">
          <div className="ai-grid-bg absolute inset-0" />
          <div className="ai-scan-sweep absolute left-0 top-0 h-full w-full" />
        </div>

        <div className="relative flex items-start justify-between gap-3">
          <div>
            <p className="text-[10px] font-bold uppercase tracking-[0.26em] text-[#0a7d3c]">Live AI layer</p>
            <h3 className="mt-1.5 text-xl font-bold tracking-[-0.04em] text-[#0f1f18]">{stageLabel}</h3>
            <p className="mt-1.5 max-w-[280px] text-xs leading-5 text-[#5e7569]">{stageDetail}</p>
          </div>
          <span className={`shrink-0 rounded-full border px-3 py-1 text-[10px] font-bold uppercase tracking-[0.12em] ${
            stage === 'completed'
              ? 'border-[#8fd3a8] bg-[#e4f8ec] text-[#0a7d3c]'
              : stage === 'reasoning'
                ? 'border-[#8fd3a8] bg-white text-[#0a7d3c] shadow-[0_6px_18px_rgba(10,125,60,0.12)]'
                : 'border-[#e0eee7] bg-white/80 text-[#7d9a8b]'
          }`}>
            {stage === 'reasoning' ? 'Active' : stage === 'completed' ? 'Done' : stage === 'preview' ? 'Preview' : 'Idle'}
          </span>
        </div>

        <div className="relative mt-4 grid place-items-center py-1">
          <AIReasoningCore active={isSubmitting || hasReport || hasPreview} />
        </div>

        <div className="relative mt-4 grid grid-cols-3 overflow-hidden rounded-[16px] border border-[#e0eee7] bg-white/88 shadow-[inset_0_1px_3px_rgba(15,43,29,0.04)] backdrop-blur">
          <ReasoningStat label="Sections" value={hasPreview || hasReport ? sections || '-' : '-'} />
          <ReasoningStat label="Signals" value={hasPreview || hasReport ? signals || '-' : '-'} />
          <ReasoningStat label="Confidence" value={confidence ? `${confidence}%` : '-'} />
        </div>
      </div>

      <div className="mt-4 space-y-2.5">
        <ReasoningPhase
          title="Context comprehension"
          description="Understands scope, evidence, impact, and remediation blocks."
          status={hasPreview || isSubmitting || hasReport ? 'Active' : 'Waiting'}
          progress={hasReport ? 100 : isSubmitting ? 78 : hasPreview ? 56 : 18}
        />
        <ReasoningPhase
          title="Entity & CVE extraction"
          description="Finds CVEs, assets, attack terms, domains, and indicators."
          status={hasReport ? 'Complete' : isSubmitting ? 'Running' : hasPreview ? 'Prepared' : 'Waiting'}
          progress={hasReport ? 100 : isSubmitting ? 64 : hasPreview ? 48 : 14}
        />
        <ReasoningPhase
          title="Relationship mapping"
          description="Links vulnerabilities to assets and business impact."
          status={hasReport ? 'Mapped' : isSubmitting ? 'Building' : 'Ready'}
          progress={hasReport ? 92 : isSubmitting ? 52 : 24}
        />
        <ReasoningPhase
          title="Risk decisioning"
          description="Ranks what to fix first by severity and exploitability."
          status={hasReport ? riskBand(riskScore) : isSubmitting ? 'Scoring' : 'Ready'}
          progress={hasReport ? clamp(riskScore) : isSubmitting ? 46 : 20}
        />
      </div>
    </Panel>
  )
}

/* ═══════════════════════════════════════════
   AIReasoningCore
═══════════════════════════════════════════ */
function AIReasoningCore({ active }: { active: boolean }) {
  return (
    <div className="relative h-[176px] w-full max-w-[280px] [perspective:900px]">
      <div className="absolute left-1/2 top-1/2 h-32 w-32 -translate-x-1/2 -translate-y-1/2 rounded-full bg-[#0a7d3c]/10 blur-2xl" />
      <div className="ai-core-platform absolute bottom-5 left-1/2 h-20 w-52 -translate-x-1/2 rounded-[50%] border border-[#b4dfc5] bg-gradient-to-b from-white via-[#e4f7ee] to-[#0a7d3c]/20 shadow-[0_22px_50px_rgba(10,125,60,0.18)]" />
      <div className={`ai-core-ring absolute left-1/2 top-[47%] h-36 w-36 -translate-x-1/2 -translate-y-1/2 rounded-full border border-[#b4dfc5] ${active ? '' : '[animation-play-state:paused]'}`} />
      <div className={`ai-core-ring-rev absolute left-1/2 top-[47%] h-48 w-48 -translate-x-1/2 -translate-y-1/2 rounded-full border border-[#cef0dc] ${active ? '' : '[animation-play-state:paused]'}`} />
      <div className={`ai-core-cube absolute left-1/2 top-[43%] grid h-[76px] w-[76px] -translate-x-1/2 -translate-y-1/2 place-items-center rounded-[20px] border border-[#b4dfc5] bg-white/92 text-lg font-bold text-[#0a7d3c] shadow-[0_28px_76px_rgba(10,125,60,0.22)] backdrop-blur ${active ? '' : '[animation-play-state:paused]'}`}>
        AI
        <span className="absolute inset-0 rounded-[20px] ring-1 ring-inset ring-white/60" />
        <span className="absolute left-3 top-3 h-1 w-9 rounded-full bg-[#b4dfc5]" />
        <span className="absolute bottom-4 left-3 h-1 w-11 rounded-full bg-[#cef0dc]" />
      </div>
      <div className="absolute bottom-1.5 left-1/2 -translate-x-1/2 whitespace-nowrap rounded-full border border-[#e0eee7] bg-white/88 px-3 py-1 text-[10px] font-bold text-[#0a7d3c] shadow-sm">
        Neural reasoning core
      </div>
    </div>
  )
}

/* ═══════════════════════════════════════════
   ReasoningStat
═══════════════════════════════════════════ */
function ReasoningStat({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="border-r border-[#e6f0ea] p-3 text-center last:border-r-0">
      <p className="text-base font-bold tabular-nums text-[#0f1f18]">{value}</p>
      <p className="mt-0.5 text-[10px] font-semibold uppercase tracking-[0.14em] text-[#7d9a8b]">{label}</p>
    </div>
  )
}

/* ═══════════════════════════════════════════
   ReasoningPhase
═══════════════════════════════════════════ */
function ReasoningPhase({
  title,
  description,
  status,
  progress,
}: {
  title: string
  description: string
  status: string
  progress: number
}) {
  return (
    <div className="group relative overflow-hidden rounded-[16px] border border-[#e3efe9] bg-white/88 p-4 transition-all duration-300 hover:-translate-y-0.5 hover:border-[#a3d6b8] hover:shadow-[0_12px_34px_rgba(15,43,29,0.07)]">
      <span className="pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-[#0a7d3c]/20 to-transparent opacity-0 transition group-hover:opacity-100" />
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-sm font-bold tracking-[-0.02em] text-[#0f1f18] transition-colors group-hover:text-[#0a7d3c]">{title}</p>
          <p className="mt-0.5 text-[11px] leading-5 text-[#5e7569]">{description}</p>
        </div>
        <span className="shrink-0 rounded-full border border-[#c8ecd6] bg-[#eaf8f0] px-2.5 py-0.5 text-[10px] font-bold text-[#0a7d3c]">
          {status}
        </span>
      </div>
      <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-[#e6f2ec]">
        <div
          className="ai-bar-fill h-full rounded-full bg-gradient-to-r from-[#066f34] via-[#0a7d3c] to-[#16a34a] transition-all duration-700"
          style={{ width: `${clamp(progress)}%` }}
        />
      </div>
    </div>
  )
}

/* ═══════════════════════════════════════════
   Metric
═══════════════════════════════════════════ */
type MetricAccent = 'green' | 'red' | 'amber' | 'gold' | 'slate'

const accentMap: Record<MetricAccent, { bg: string; border: string; helper: string; bar: string }> = {
  green: { bg: 'bg-[#f5fdf8]', border: 'border-[#d4eddd]', helper: 'text-[#0a7d3c]', bar: 'bg-[#0a7d3c]' },
  red:   { bg: 'bg-[#fdf6f6]', border: 'border-[#f1d0d0]', helper: 'text-[#c0392b]', bar: 'bg-[#d2493a]' },
  amber: { bg: 'bg-[#fdf9f3]', border: 'border-[#f0dcbe]', helper: 'text-[#b5742a]', bar: 'bg-[#d68a36]' },
  gold:  { bg: 'bg-[#fdfbf2]', border: 'border-[#eee0b4]', helper: 'text-[#9a7d1f]', bar: 'bg-[#c8a93a]' },
  slate: { bg: 'bg-[#f7faf9]', border: 'border-[#dde8e3]', helper: 'text-[#5a7468]', bar: 'bg-[#7d9a8b]' },
}

function Metric({
  label,
  value,
  helper,
  accent = 'green',
}: {
  label: string
  value: string | number
  helper: string
  accent?: MetricAccent
}) {
  const a = accentMap[accent]
  return (
    <div className={`group relative overflow-hidden rounded-[16px] border ${a.border} ${a.bg} p-3.5 text-center shadow-[0_2px_10px_rgba(15,43,29,0.035)] transition-all duration-200 hover:-translate-y-0.5 hover:shadow-[0_10px_26px_rgba(15,43,29,0.08)]`}>
      <span className={`pointer-events-none absolute inset-x-0 top-0 h-[3px] rounded-t-full ${a.bar} opacity-55`} />
      <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-[#7d9a8b]">{label}</p>
      <p className="mt-2 text-2xl font-bold leading-none tabular-nums text-[#0f1f18]">{value}</p>
      <p className={`mt-1.5 text-[10px] font-semibold ${a.helper}`}>{helper}</p>
    </div>
  )
}

/* ═══════════════════════════════════════════
   InsightText
═══════════════════════════════════════════ */
function InsightText({ children, icon }: { children: ReactNode; icon: string }) {
  return (
    <div className="group border-t border-[#e3efe9] p-4 transition-colors duration-150 hover:bg-[#f3fbf6] lg:border-l lg:border-t-0">
      <span className="mb-2 flex h-7 w-7 items-center justify-center rounded-lg bg-[#eaf8ef] text-[#0a7d3c] ring-1 ring-inset ring-[#d4eddd] transition-transform duration-200 group-hover:scale-105">
        <Icon name={icon} className="h-4 w-4" />
      </span>
      <p className="text-xs leading-5 text-[#16261d]">{children}</p>
    </div>
  )
}

/* ═══════════════════════════════════════════
   Action
═══════════════════════════════════════════ */
function Action({
  href,
  title,
  detail,
  state,
  icon,
  ready,
}: {
  href: string
  title: string
  detail: string
  state: string
  icon: string
  ready?: boolean
}) {
  return (
    <Link
      href={href}
      className="group relative overflow-hidden rounded-[16px] border border-[#e3efe9] bg-[#f8fdfa] p-4 transition-all duration-300 hover:-translate-y-0.5 hover:border-[#8fd3a8] hover:bg-white hover:shadow-[0_12px_32px_rgba(15,43,29,0.09)] active:translate-y-0"
    >
      <span className="pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-[#0a7d3c]/45 to-transparent opacity-0 transition-opacity group-hover:opacity-100" />

      <div className="flex items-start justify-between gap-3">
        <div className="flex items-start gap-2.5">
          <span className="mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-[#eaf8ef] text-[#0a7d3c] ring-1 ring-inset ring-[#d4eddd] transition-all duration-200 group-hover:bg-[#0a7d3c] group-hover:text-white">
            <Icon name={icon} className="h-[18px] w-[18px]" />
          </span>
          <div>
            <p className="text-sm font-bold tracking-[-0.02em] text-[#0f1f18] transition-colors group-hover:text-[#0a7d3c]">{title}</p>
            <p className="mt-0.5 text-[11px] leading-4 text-[#5e7569]">{detail}</p>
          </div>
        </div>
        <span className={`shrink-0 rounded-full border px-2 py-0.5 text-[10px] font-bold transition-all ${
          ready
            ? 'border-[#8fd3a8] bg-[#e4f8ec] text-[#0a7d3c]'
            : 'border-[#e0eee7] bg-[#f3fbf6] text-[#7d9a8b]'
        }`}>
          {state}
        </span>
      </div>

      <div className="mt-3 h-1 overflow-hidden rounded-full bg-[#e6f2ec]">
        <div className={`h-full rounded-full bg-gradient-to-r from-[#0a7d3c] to-[#16a34a] transition-all duration-500 ${ready ? 'w-full' : 'w-1/3 group-hover:w-2/3'}`} />
      </div>

      <Icon
        name="arrow"
        className="absolute bottom-3.5 right-3.5 h-3.5 w-3.5 text-[#0a7d3c]/35 transition-all duration-200 group-hover:translate-x-0.5 group-hover:text-[#0a7d3c]"
      />
    </Link>
  )
}

/* ═══════════════════════════════════════════
   ProgressBar
═══════════════════════════════════════════ */
function ProgressBar({ value, className = '' }: { value: number; className?: string }) {
  return (
    <div className={`h-2 overflow-hidden rounded-full bg-[#e4f1ea] ${className}`}>
      <div
        className="ai-bar-fill h-full rounded-full bg-gradient-to-r from-[#066f34] via-[#0a7d3c] to-[#16a34a] transition-all duration-700"
        style={{ width: `${clamp(value)}%` }}
      />
    </div>
  )
}

/* ═══════════════════════════════════════════
   Message
═══════════════════════════════════════════ */
function Message({ tone, children }: { tone: Exclude<StatusTone, 'waiting' | 'neutral'>; children: ReactNode }) {
  const danger = tone === 'danger'
  const classes = danger
    ? 'border-red-200 bg-red-50/70 text-red-700 shadow-[0_4px_14px_rgba(239,68,68,0.07)]'
    : 'border-[#aeddc1] bg-[#eafaf2] text-[#0a7d3c] shadow-[0_4px_14px_rgba(10,125,60,0.07)]'

  return (
    <div className={`mt-4 flex items-start gap-2.5 rounded-2xl border px-4 py-3 text-sm font-semibold ${classes}`}>
      <span className={`mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full ${danger ? 'bg-red-100 text-red-600' : 'bg-[#d6f2e1] text-[#0a7d3c]'}`}>
        <Icon name={danger ? 'eye' : 'check'} className="h-3 w-3" />
      </span>
      <span>{children}</span>
    </div>
  )
}

/* ═══════════════════════════════════════════
   Tag
═══════════════════════════════════════════ */
function Tag({ children }: { children: ReactNode }) {
  return (
    <span className="rounded-full border border-[#c8ecd6] bg-[#f0fdf6] px-3 py-1 text-[11px] font-semibold text-[#0a7d3c] transition-all duration-150 hover:bg-[#e4f8ec] hover:shadow-sm">
      {children}
    </span>
  )
}

/* ═══════════════════════════════════════════
   AnalysisOverlay
═══════════════════════════════════════════ */
function AnalysisOverlay({ progress, activeStep }: { progress: number; activeStep: number }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-[#f1fbf6]/80 px-6 backdrop-blur-md">
      <div className="pointer-events-none absolute left-1/4 top-1/4 h-80 w-80 rounded-full bg-[#0a7d3c]/8 blur-3xl" />
      <div className="pointer-events-none absolute bottom-1/4 right-1/4 h-96 w-96 rounded-full bg-[#16a34a]/6 blur-3xl" />

      <div className="relative w-full max-w-md overflow-hidden rounded-[32px] border border-[#cbeed9] bg-white/96 p-8 text-center shadow-[0_40px_120px_rgba(15,43,29,0.20),0_8px_32px_rgba(15,43,29,0.09)] backdrop-blur">
        <span className="pointer-events-none absolute inset-x-0 top-0 h-0.5 bg-gradient-to-r from-transparent via-[#0a7d3c]/50 to-transparent" />
        <NeuralStream />

        <div className="relative mx-auto h-44 w-44 [perspective:900px]">
          <div className="ai-platform-3d absolute bottom-6 left-1/2 h-14 w-40 -translate-x-1/2 rounded-[50%] border border-[#b4dfc5] bg-gradient-to-b from-white via-[#e4f7ec] to-[#0a7d3c]/18 shadow-[0_20px_46px_rgba(10,125,60,0.16)]" />
          <div className="ai-orb absolute left-1/2 top-1/2 grid h-24 w-24 -translate-x-1/2 -translate-y-1/2 place-items-center rounded-full border border-[#b4dfc5] bg-white text-3xl font-bold tracking-[-0.08em] text-[#0a7d3c] shadow-[0_28px_70px_rgba(10,125,60,0.20)]">
            <span className="relative z-10">AI</span>
            <span className="absolute inset-4 rounded-full bg-[radial-gradient(circle,rgba(10,125,60,0.10),transparent_70%)]" />
            <span className="absolute inset-0 rounded-full ring-1 ring-inset ring-white/60" />
          </div>
          <span className="ai-ring-pulse absolute left-1/2 top-1/2 h-40 w-40 rounded-full border border-[#a6d9bc]" />
          <span className="ai-ring-pulse-delay absolute left-1/2 top-1/2 h-52 w-52 rounded-full border border-[#c8ecd6]" />
        </div>

        <p className="relative mt-4 text-xl font-bold tracking-[-0.03em] text-[#0f1f18]">
          AI is analyzing your report
        </p>
        <p className="relative mt-2 text-sm leading-6 text-[#5e7569]">
          {analysisSteps[activeStep]?.ai ?? 'AI is preparing the analysis output.'}
        </p>

        <div className="relative mt-6 overflow-hidden rounded-2xl border border-[#e0eee7] bg-[#f5fdf8] p-4 text-left">
          <span className="pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-[#0a7d3c]/30 to-transparent" />
          <div className="flex items-center justify-between gap-3">
            <p className="text-[10px] font-bold uppercase tracking-[0.20em] text-[#0a7d3c]">Current step</p>
            <span className="text-sm font-bold tabular-nums text-[#0f1f18]">{progress}%</span>
          </div>
          <p className="mt-2 text-sm font-semibold text-[#16261d]">
            {analysisSteps[activeStep]?.title ?? 'Processing'}
          </p>
          <ProgressBar value={progress} className="mt-3 h-2.5" />
        </div>

        <div className="relative mt-4 flex flex-wrap justify-center gap-1.5">
          {analysisSteps.map((step, i) => (
            <span
              key={step.title}
              className={`h-1.5 rounded-full transition-all duration-300 ${
                i < activeStep ? 'w-4 bg-[#0a7d3c]' : i === activeStep ? 'w-6 bg-[#0a7d3c]' : 'w-1.5 bg-[#d6ecdf]'
              }`}
            />
          ))}
        </div>
      </div>
    </div>
  )
}
