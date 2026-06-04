'use client'

import type { Finding, Report } from '@/lib/mock-data'
import { runPipeline } from '@/lib/pipeline-client'
import { getReviewBadges, truncateText } from '@/lib/ui-quality'
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

const processingSteps = [
  'Preparing input',
  'Uploading report',
  'Extracting findings',
  'Saving report',
  'Refreshing workspace',
]

type InputMode = 'file' | 'text'

type ReadinessState = 'Ready' | 'Incomplete' | 'Needs Review'

const reportStatusClass: Record<string, string> = {
  Ready: 'border-emerald-200 bg-emerald-50 text-emerald-700',
  Reviewed: 'border-[#c4e3cf] bg-[#f6fff9] text-[#087a3a]',
  Pending: 'border-yellow-200 bg-yellow-50 text-yellow-700',
}

const severityBadgeClass: Record<string, string> = {
  Critical: 'border-red-200 bg-red-50 text-red-700',
  High: 'border-orange-200 bg-orange-50 text-orange-700',
  Medium: 'border-yellow-200 bg-yellow-50 text-yellow-700',
  Low: 'border-emerald-200 bg-emerald-50 text-emerald-700',
}

function formatFileSize(size: number) {
  if (size >= 1024 * 1024) return `${(size / (1024 * 1024)).toFixed(1)} MB`
  if (size >= 1024) return `${Math.round(size / 1024)} KB`
  return `${size} B`
}

function getFileExtension(fileName: string) {
  const match = fileName.toLowerCase().match(/\.[^.]+$/)
  return match?.[0] ?? ''
}

function validateFile(file: File) {
  const extension = getFileExtension(file.name)
  const typeAllowed = file.type
    ? allowedTypes.includes(file.type)
    : allowedExtensions.includes(extension)
  const extensionAllowed = allowedExtensions.includes(extension)

  if (!typeAllowed || !extensionAllowed) {
    return 'Unsupported file type. Please upload PDF, DOCX, TXT, MD, LOG, CSV, or JSON.'
  }

  if (file.size > maxFileSize) {
    return 'File is too large. Maximum allowed size is 25MB.'
  }

  return ''
}

function normalizeConfidence(value: unknown) {
  const numeric = Number(value ?? 0)

  if (!Number.isFinite(numeric) || numeric <= 0) return 0

  const percentage = numeric <= 1 ? numeric * 100 : numeric

  return Math.max(0, Math.min(100, Math.round(percentage)))
}

function averageConfidence(findings: Finding[]) {
  if (findings.length === 0) return 0

  const values = findings.map((item) => normalizeConfidence(item.provenance?.parserConfidence))

  return Math.round(values.reduce((sum, value) => sum + value, 0) / values.length)
}

function needsReview(finding: Finding) {
  const confidence = normalizeConfidence(finding.provenance?.parserConfidence)
  const evidence = String(finding.evidence ?? '').trim()
  const remediation = String(finding.remediation ?? '').trim()

  return finding.status !== 'Resolved' && (confidence < 70 || !evidence || !remediation)
}

function safeText(value: unknown, fallback = 'Unknown') {
  const text = String(value ?? '').trim()
  return text.length > 0 ? text : fallback
}

function formatDate(value: string) {
  try {
    return new Intl.DateTimeFormat('en', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      hour12: true,
      timeZone: 'Africa/Cairo',
    }).format(new Date(value))
  } catch {
    return value
  }
}

function statusClass(status: string) {
  return reportStatusClass[status] ?? 'border-[#dceee3] bg-[#fbfffd] text-[#44554b]'
}

function extractionLabel(value: unknown) {
  return safeText(value, 'Hybrid')
    .split(/[_\s-]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase())
    .join(' ')
}

export default function AnalyzerPage() {
  const router = useRouter()
  const fileInputRef = useRef<HTMLInputElement | null>(null)

  const [recentReports, setRecentReports] = useState<Report[]>([])
  const [pastedText, setPastedText] = useState('')
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [inputMode, setInputMode] = useState<InputMode>('file')
  const [isDragging, setIsDragging] = useState(false)
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [activeStep, setActiveStep] = useState(0)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [createdReport, setCreatedReport] = useState<Report | null>(null)
  const [createdFindings, setCreatedFindings] = useState<Finding[]>([])

  useEffect(() => {
    fetch('/api/reports')
      .then((res) => res.json())
      .then((data) => setRecentReports((data.reports ?? []).slice(0, 3)))
      .catch(() => undefined)
  }, [])

  useEffect(() => {
    if (!isSubmitting) {
      setActiveStep(0)
      return undefined
    }

    const interval = window.setInterval(() => {
      setActiveStep((current) => Math.min(current + 1, processingSteps.length - 1))
    }, 700)

    return () => window.clearInterval(interval)
  }, [isSubmitting])

  const analysis = useMemo(() => {
    const input = pastedText.trim()
    if (!input) return null
    return runPipeline(input)
  }, [pastedText])

  const pastedTextLength = pastedText.trim().length
  const canAnalyze = Boolean(selectedFile || pastedTextLength > 0)
  const selectedFileError = selectedFile ? validateFile(selectedFile) : ''
  const outputAverageConfidence = averageConfidence(createdFindings)
  const outputNeedsReviewCount = createdFindings.filter(needsReview).length

  const checklist = [
    {
      label: 'Input source',
      value:
        selectedFile && pastedTextLength > 0
          ? 'File and pasted text'
          : selectedFile
            ? 'Uploaded file'
            : pastedTextLength > 0
              ? 'Pasted text'
              : 'No input yet',
      state: canAnalyze ? 'Ready' : 'Incomplete',
    },
    {
      label: 'File validation',
      value: selectedFile
        ? `${selectedFile.name} - ${formatFileSize(selectedFile.size)}`
        : 'Optional',
      state: selectedFileError ? 'Needs Review' : 'Ready',
    },
    {
      label: 'Text preview',
      value: pastedTextLength > 0 ? `${pastedTextLength.toLocaleString()} characters` : 'Waiting',
      state: pastedTextLength > 0 ? 'Ready' : 'Incomplete',
    },
    {
      label: 'Backend action',
      value: 'Uses the existing /api/analyze endpoint',
      state: 'Ready',
    },
  ] satisfies Array<{ label: string; value: string; state: ReadinessState }>

  function clearMessages() {
    setError('')
    setSuccess('')
  }

  function chooseFile(file: File | null) {
    clearMessages()

    if (!file) {
      setSelectedFile(null)

      if (fileInputRef.current) {
        fileInputRef.current.value = ''
      }

      return
    }

    const validationError = validateFile(file)
    if (validationError) {
      setSelectedFile(null)
      setError(validationError)

      if (fileInputRef.current) {
        fileInputRef.current.value = ''
      }

      return
    }

    setSelectedFile(file)
    setInputMode('file')
  }

  function handleReset() {
    setPastedText('')
    setSelectedFile(null)
    setError('')
    setSuccess('')
    setCreatedReport(null)
    setCreatedFindings([])
    setInputMode('file')

    if (fileInputRef.current) {
      fileInputRef.current.value = ''
    }
  }

  async function handleAnalyze() {
    try {
      setError('')
      setSuccess('')
      setCreatedReport(null)
      setCreatedFindings([])
      setIsSubmitting(true)
      setActiveStep(0)

      const formData = new FormData()
      if (pastedText.trim()) formData.append('text', pastedText)
      if (selectedFile) formData.append('file', selectedFile)

      const response = await fetch('/api/analyze', { method: 'POST', body: formData })
      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.error ?? 'Analysis failed.')
      }

      setCreatedReport(data.report)
      setCreatedFindings(data.findings ?? [])
      setSuccess('Report analyzed successfully and saved to the workspace.')
      setRecentReports((current) =>
        [data.report, ...current.filter((item) => item.id !== data.report.id)].slice(0, 3)
      )
      router.refresh()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Analysis failed.')
    } finally {
      setIsSubmitting(false)
    }
  }

  return (
    <main className="relative min-h-screen overflow-hidden bg-[#fbfefd] text-[#111827]">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_18%_10%,rgba(34,197,94,0.10),transparent_30%),radial-gradient(circle_at_86%_18%,rgba(8,122,58,0.08),transparent_34%)]" />
      <div className="pointer-events-none absolute right-0 top-24 h-[420px] w-[560px] rounded-full bg-[#dcf7e7]/60 blur-3xl" />
      <div className="pointer-events-none absolute left-0 top-[560px] h-[320px] w-[520px] rounded-full bg-[#eefaf3] blur-3xl" />

      <section className="relative mx-auto max-w-[1480px] px-6 pb-16 pt-10 lg:px-8">
        <header className="relative overflow-hidden rounded-[34px] border border-[#dceee3] bg-white/92 p-7 shadow-[0_24px_80px_rgba(15,43,29,0.07)] backdrop-blur">
          <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(135deg,rgba(8,122,58,0.05),transparent_42%),radial-gradient(circle_at_86%_24%,rgba(22,163,74,0.12),transparent_28%)]" />

          <div className="pointer-events-none absolute right-[180px] bottom-8 h-20 w-52 rounded-[50%] border border-[#bfe6cc] bg-gradient-to-b from-white to-[#e5f8ec] shadow-[0_24px_60px_rgba(8,122,58,0.12)] analyzer-platform" />
          <div className="pointer-events-none absolute right-24 top-12 h-28 w-28 rounded-full border border-[#c7efd4] bg-white/70 shadow-[0_22px_55px_rgba(8,122,58,0.12)] analyzer-orbit">
            <div className="absolute left-1/2 top-1/2 h-14 w-14 -translate-x-1/2 -translate-y-1/2 rounded-full bg-gradient-to-br from-[#dff7e8] to-[#087a3a] shadow-[0_18px_45px_rgba(8,122,58,0.18)]" />
            <div className="absolute left-1/2 top-1/2 h-5 w-5 -translate-x-1/2 -translate-y-[58px] rounded-full bg-[#087a3a] shadow-[0_12px_28px_rgba(8,122,58,0.20)]" />
          </div>

          <div className="relative grid gap-8 lg:grid-cols-[1fr_0.72fr]">
            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.22em] text-[#087a3a]">
                Analyze Report
              </p>

              <h1 className="mt-4 max-w-4xl text-4xl font-semibold tracking-[-0.04em] text-[#111827] md:text-5xl">
                Upload and analyze a security report
              </h1>

              <p className="mt-4 max-w-3xl text-base leading-8 text-[#5f6f66]">
                Upload a PDF, DOCX, TXT, MD, LOG, CSV, or JSON file, or paste report content to create a
persisted report and linked findings through the existing backend.
              </p>

              <div className="mt-7 flex flex-wrap gap-3">
                <ActionLink href="/results">Review Findings</ActionLink>
                <ActionLink href="/reports">View Reports</ActionLink>
                <ActionLink href="/dashboard">Dashboard</ActionLink>
              </div>
            </div>

            <div className="rounded-[28px] border border-[#dceee3] bg-white/78 p-5 shadow-[0_20px_60px_rgba(15,43,29,0.07)] backdrop-blur">
              <p className="text-xs font-semibold uppercase tracking-[0.18em] text-[#087a3a]">
                Workspace status
              </p>

              <div className="mt-5 grid gap-3 sm:grid-cols-2">
                <MiniStat label="Input" value={canAnalyze ? 'Ready' : 'Waiting'} />
                <MiniStat label="Recent reports" value={String(recentReports.length)} />
                <MiniStat
                  label="Text length"
                  value={pastedTextLength > 0 ? pastedTextLength.toLocaleString() : '0'}
                />
                <MiniStat
                  label="Generated"
                  value={createdReport ? createdReport.id : 'None'}
                />
              </div>
            </div>
          </div>
        </header>

        <section className="mt-6 grid gap-6 xl:grid-cols-[1fr_430px]">
          <div className="space-y-6">
            <section className="rounded-[32px] border border-[#dceee3] bg-white/95 p-6 shadow-[0_22px_60px_rgba(15,43,29,0.06)] backdrop-blur">
              <div className="flex flex-wrap items-center justify-between gap-4">
                <div>
                  <p className="text-sm font-semibold uppercase tracking-[0.18em] text-[#087a3a]">
                    Analysis input
                  </p>
                  <h2 className="mt-2 text-2xl font-semibold text-[#0d2217]">
                    Source material
                  </h2>
                </div>

                <div className="rounded-2xl border border-[#dceee3] bg-[#fbfffd] p-1">
                  <button
                    type="button"
                    onClick={() => setInputMode('file')}
                    className={`rounded-xl px-4 py-2 text-sm font-semibold transition ${
                      inputMode === 'file'
                        ? 'bg-white text-[#087a3a] shadow-sm'
                        : 'text-[#5a7668] hover:text-[#173128]'
                    }`}
                  >
                    Upload file
                  </button>
                  <button
                    type="button"
                    onClick={() => setInputMode('text')}
                    className={`rounded-xl px-4 py-2 text-sm font-semibold transition ${
                      inputMode === 'text'
                        ? 'bg-white text-[#087a3a] shadow-sm'
                        : 'text-[#5a7668] hover:text-[#173128]'
                    }`}
                  >
                    Paste text
                  </button>
                </div>
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
                  className={`mt-6 rounded-[28px] border border-dashed p-8 text-center transition ${
                    isDragging
                      ? 'border-[#087a3a] bg-[#ecfdf3] shadow-inner'
                      : 'border-[#bde5c9] bg-[#f6fff9]'
                  }`}
                >
                  <p className="text-lg font-semibold text-[#0d2217]">
                    Drag and drop a PDF, DOCX, TXT, MD, LOG, CSV, or JSON file here
                  </p>
                  <p className="mt-2 text-sm leading-6 text-[#5a7668]">
                    Maximum file size is 25MB. Legacy .doc is blocked unless extraction support is added.
                  </p>

                  <label className="mt-5 inline-flex cursor-pointer rounded-2xl bg-[#087a3a] px-5 py-3 text-sm font-semibold text-white shadow-[0_16px_32px_rgba(8,122,58,0.18)] transition hover:bg-[#066b33] focus-within:ring-2 focus-within:ring-emerald-500 focus-within:ring-offset-2">
                    Choose file
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
                <div className="mt-6">
                  <label className="mb-3 block text-sm font-semibold text-[#173128]" htmlFor="report-text">
                    Paste report text
                  </label>
                  <textarea
                    id="report-text"
                    value={pastedText}
                    onChange={(event) => {
                      setPastedText(event.target.value)
                      clearMessages()
                    }}
                    placeholder="Paste executive summary, findings, evidence, or any report section here..."
                    className="min-h-[310px] w-full rounded-[28px] border border-[#c4e3cf] bg-[#f6fff9] p-5 text-sm text-[#173128] outline-none placeholder:text-[#91a19a] focus:border-[#087a3a] focus:ring-2 focus:ring-emerald-500/20"
                  />
                  <p className="mt-2 text-sm text-[#5a7668]">
                    {pastedTextLength.toLocaleString()} characters ready for preview.
                  </p>
                </div>
              )}

              {selectedFile ? (
                <div className="mt-5 rounded-2xl border border-[#cfe9d7] bg-white p-4">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div>
                      <p className="text-sm font-semibold text-[#0f2b1d]">Selected file</p>
                      <p className="mt-1 text-sm text-[#5a7668]">
                        {selectedFile.name} - {formatFileSize(selectedFile.size)} - {selectedFile.type || getFileExtension(selectedFile.name)}
                      </p>
                    </div>

                    <button
                      type="button"
                      onClick={() => chooseFile(null)}
                      className="rounded-xl border border-red-200 bg-red-50 px-3 py-2 text-xs font-semibold text-red-700 transition hover:bg-red-100"
                    >
                      Remove
                    </button>
                  </div>
                </div>
              ) : null}

              <div className="mt-6 border-t border-[#e4f2e9] pt-5">
                <div className="flex flex-wrap gap-3">
                  <button
                    type="button"
                    onClick={handleAnalyze}
                    disabled={isSubmitting || Boolean(error) || !canAnalyze}
                    className="rounded-2xl bg-[#087a3a] px-6 py-3 text-sm font-semibold text-white shadow-[0_16px_32px_rgba(8,122,58,0.18)] transition hover:bg-[#066b33] disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    {isSubmitting ? 'Analyzing report...' : 'Analyze Report'}
                  </button>

                  <button
                    type="button"
                    onClick={handleReset}
                    disabled={isSubmitting}
                    className="rounded-2xl border border-[#c4e3cf] bg-white px-6 py-3 text-sm font-semibold text-[#173128] transition hover:bg-[#f4fff7] disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    Reset
                  </button>

                  {createdReport ? (
                    <ActionLink href={`/reports/${createdReport.id}`}>Open Generated Report</ActionLink>
                  ) : null}
                </div>
              </div>
            </section>

            {isSubmitting ? (
              <section className="rounded-[28px] border border-[#dceee3] bg-white/95 p-6 shadow-[0_22px_60px_rgba(15,43,29,0.05)]">
                <p className="text-sm font-semibold uppercase tracking-[0.18em] text-[#087a3a]">
                  Analysis in progress
                </p>
                <p className="mt-2 text-sm leading-6 text-[#5a7668]">
                  The existing backend is processing the FormData payload and saving the report.
                </p>

                <div className="mt-4 grid gap-2 sm:grid-cols-5">
                  {processingSteps.map((step, index) => (
                    <div
                      key={step}
                      className={`rounded-2xl border px-3 py-2 text-xs font-semibold ${
                        index <= activeStep
                          ? 'border-[#bbf7d0] bg-[#f0fdf4] text-[#15803d]'
                          : 'border-[#e4f2e9] bg-[#f8fffa] text-[#6b8477]'
                      }`}
                    >
                      {index + 1}. {step}
                    </div>
                  ))}
                </div>
              </section>
            ) : null}

            {error ? <MessageBox tone="danger">{error}</MessageBox> : null}
            {success ? <MessageBox tone="success">{success}</MessageBox> : null}

            {createdReport ? (
              <section className="rounded-[32px] border border-[#dceee3] bg-white/95 p-6 shadow-[0_22px_60px_rgba(15,43,29,0.06)] backdrop-blur">
                <div className="flex flex-wrap items-center justify-between gap-4">
                  <div>
                    <p className="text-sm font-semibold uppercase tracking-[0.18em] text-[#087a3a]">
                      Generated output
                    </p>
                    <h2 className="mt-2 text-2xl font-semibold text-[#0d2217]">
                      {createdReport.name}
                    </h2>
                  </div>

                  <ActionLink href={`/reports/${createdReport.id}`}>Open report</ActionLink>
                </div>

                <div className="mt-5 grid gap-4 md:grid-cols-4">
                  <MetricCard label="Findings" value={String(createdFindings.length)} helper="Created from analysis" />
                  <MetricCard label="Needs review" value={String(outputNeedsReviewCount)} helper="Pending analyst review" />
                  <MetricCard label="Avg confidence" value={createdFindings.length ? `${outputAverageConfidence}%` : '-'} helper="Normalized confidence" />
                  <MetricCard label="Parser mode" value="Hybrid" helper="Backend extraction" />
                </div>

                <div className="mt-5 flex flex-wrap gap-3">
                  <ActionLink href={`/results?reportId=${encodeURIComponent(createdReport.id)}`}>Review findings</ActionLink>
                  <ActionLink href={`/export?reportId=${encodeURIComponent(createdReport.id)}`} primary>Export report</ActionLink>
                  <ActionLink href={`/graph?reportId=${encodeURIComponent(createdReport.id)}`}>Open graph</ActionLink>
                </div>

                <div className="mt-5 grid gap-3">
                  {createdFindings.slice(0, 4).map((item) => (
                    <article
                      key={item.id}
                      className="rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] p-4"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-3">
                        <div className="min-w-0">
                          <Link href={`/results/${item.id}`} className="font-semibold text-[#0f2b1d] hover:text-[#087a3a]">
                            {item.title}
                          </Link>
                          <p className="mt-1 text-sm leading-6 text-[#5a7668]">
                            {truncateText(item.evidence || item.summary, 120)}
                          </p>
                        </div>

                        <div className="flex flex-wrap justify-end gap-2">
                          <Badge className={severityBadgeClass[item.severity] ?? 'border-[#dceee3] bg-white text-[#44554b]'}>
                            {item.severity}
                          </Badge>
                          <Badge className="border-[#c4e3cf] bg-white text-[#087a3a]">
                            {extractionLabel(item.provenance?.extractionMethod)}
                          </Badge>
                          <Badge className="border-[#c4e3cf] bg-white text-[#087a3a]">
                            {normalizeConfidence(item.provenance?.parserConfidence)}%
                          </Badge>
                        </div>
                      </div>

                      <div className="mt-3 flex flex-wrap gap-2">
                        {getReviewBadges(item).map((badge, index) => (
                          <span
                            key={`${badge.label}-${index}`}
                            className="rounded-full border border-[#dcefe2] bg-white px-3 py-1 text-xs font-semibold text-[#173128]"
                          >
                            {badge.label}
                          </span>
                        ))}
                      </div>
                    </article>
                  ))}
                </div>
              </section>
            ) : null}
          </div>

          <aside className="space-y-5">
            <SidePanel title="Workspace snapshot">
              <div className="mb-4 flex items-center justify-between gap-3">
                <p className="text-sm text-[#5a7668]">Recent Reports</p>
                <Link href="/reports" className="text-sm font-semibold text-[#087a3a] hover:underline">
                  View all
                </Link>
              </div>

              <div className="space-y-3">
                {recentReports.length === 0 ? (
                  <p className="rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] p-4 text-sm text-[#5a7668]">
                    No reports yet. Analyze a report to populate the workspace.
                  </p>
                ) : (
                  recentReports.map((item) => (
                    <div key={item.id} className="rounded-2xl border border-[#d6efe0] bg-[#f6fff9] p-4">
                      <div className="flex items-start justify-between gap-3">
                        <Link href={`/reports/${item.id}`} className="font-semibold text-[#0f2b1d] hover:text-[#087a3a]">
                          {item.name}
                        </Link>
                        <Badge className={statusClass(item.status)}>{item.status}</Badge>
                      </div>
                      <p className="mt-2 text-sm text-[#6b8477]">
                        {item.type} - {formatDate(item.uploadedAt)}
                      </p>
                    </div>
                  ))
                )}
              </div>
            </SidePanel>

            <SidePanel title="Analyzer preview">
              {!analysis ? (
                <p className="rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] p-4 text-sm leading-6 text-[#5a7668]">
                  Paste report text to preview normalized text, sentence count, and extracted indicators before upload.
                </p>
              ) : (
                <div className="grid gap-3">
                  <div className="grid grid-cols-2 gap-3">
                    <QualityBox label="Sections" value={String(analysis.stats.sectionCount)} helper="Detected" />
                    <QualityBox label="Sentences" value={String(analysis.stats.sentenceCount)} helper="Detected" />
                    <QualityBox label="Indicators" value={String(analysis.indicators.length)} helper="Found" />
                    <QualityBox label="Status" value="Ready" helper="Ready to analyze" />
                  </div>

                  <div className="rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] p-4">
                    <p className="text-xs font-semibold uppercase tracking-wide text-[#5a7668]">
                      Indicator sample
                    </p>
                    <p className="mt-2 text-sm leading-6 text-[#173128]">
                      {analysis.indicators.length > 0
                        ? analysis.indicators
                            .map((item) => `${item.type}: ${item.value}`)
                            .slice(0, 6)
                            .join(' - ')
                        : 'No indicators detected in the pasted content.'}
                    </p>
                  </div>
                </div>
              )}
            </SidePanel>

            <SidePanel title="Pre-analysis checklist">
              <div className="space-y-3">
                {checklist.map((item) => (
                  <ChecklistLine
                    key={item.label}
                    label={item.label}
                    value={item.value}
                    state={item.state}
                  />
                ))}
              </div>
            </SidePanel>
          </aside>
        </section>
      </section>

      <style>{`
        @keyframes analyzer-orbit-spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }

        @keyframes analyzer-logo-float {
          0%, 100% { transform: translateY(0) rotate(0deg); }
          50% { transform: translateY(-12px) rotate(2deg); }
        }

        .analyzer-orbit {
          animation: analyzer-orbit-spin 14s linear infinite;
        }

        .analyzer-orbit > div:first-child {
          animation: analyzer-logo-float 6s ease-in-out infinite;
        }

        .analyzer-platform {
          transform: perspective(800px) rotateX(58deg);
        }
      `}</style>
    </main>
  )
}

function ActionLink({
  href,
  children,
  primary = false,
}: {
  href: string
  children: ReactNode
  primary?: boolean
}) {
  return (
    <Link
      href={href}
      className={
        primary
          ? 'inline-flex items-center justify-center rounded-2xl bg-[#087a3a] px-5 py-3 text-sm font-semibold text-white shadow-[0_16px_32px_rgba(8,122,58,0.18)] transition hover:-translate-y-0.5 hover:bg-[#066b33]'
          : 'inline-flex items-center justify-center rounded-2xl border border-[#c4e3cf] bg-white px-5 py-3 text-sm font-semibold text-[#173128] transition hover:-translate-y-0.5 hover:bg-[#f4fff7]'
      }
    >
      {children}
    </Link>
  )
}

function MiniStat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] p-4">
      <p className="text-xs font-semibold uppercase tracking-wide text-[#5a7668]">{label}</p>
      <p className="mt-2 text-xl font-semibold text-[#0d2217]">{value}</p>
    </div>
  )
}

function MetricCard({
  label,
  value,
  helper,
}: {
  label: string
  value: string
  helper: string
}) {
  return (
    <article className="rounded-[22px] border border-[#dceee3] bg-white p-4 shadow-[0_12px_34px_rgba(15,43,29,0.04)]">
      <p className="text-xs font-semibold uppercase tracking-wide text-[#5a7668]">{label}</p>
      <p className="mt-2 text-2xl font-semibold text-[#0d2217]">{value}</p>
      <p className="mt-1 text-xs text-[#5a7668]">{helper}</p>
    </article>
  )
}

function SidePanel({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="rounded-[28px] border border-[#dceee3] bg-white/95 p-6 shadow-[0_22px_60px_rgba(15,43,29,0.06)] backdrop-blur">
      <h2 className="mb-5 text-xl font-semibold text-[#0d2217]">{title}</h2>
      {children}
    </section>
  )
}

function QualityBox({
  label,
  value,
  helper,
}: {
  label: string
  value: string
  helper: string
}) {
  return (
    <div className="rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] p-4">
      <p className="text-xs font-semibold uppercase tracking-wide text-[#5a7668]">{label}</p>
      <p className="mt-2 text-2xl font-semibold text-[#087a3a]">{value}</p>
      <p className="mt-1 text-xs text-[#5a7668]">{helper}</p>
    </div>
  )
}

function ChecklistLine({
  label,
  value,
  state,
}: {
  label: string
  value: string
  state: ReadinessState
}) {
  const className =
    state === 'Ready'
      ? 'border-emerald-200 bg-emerald-50 text-emerald-700'
      : state === 'Needs Review'
        ? 'border-yellow-200 bg-yellow-50 text-yellow-700'
        : 'border-[#dceee3] bg-[#fbfffd] text-[#44554b]'

  return (
    <div className="rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] p-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-sm font-semibold text-[#173128]">{label}</p>
          <p className="mt-1 text-sm leading-6 text-[#5a7668]">{value}</p>
        </div>
        <Badge className={className}>{state}</Badge>
      </div>
    </div>
  )
}

function Badge({ className, children }: { className: string; children: ReactNode }) {
  return (
    <span className={`inline-flex rounded-full border px-3 py-1 text-xs font-semibold ${className}`}>
      {children}
    </span>
  )
}

function MessageBox({
  tone,
  children,
}: {
  tone: 'danger' | 'success'
  children: ReactNode
}) {
  const className =
    tone === 'danger'
      ? 'border-red-200 bg-red-50 text-red-700'
      : 'border-emerald-200 bg-emerald-50 text-emerald-700'

  return (
    <section className={`rounded-2xl border p-4 text-sm font-semibold ${className}`}>
      {children}
    </section>
  )
}
