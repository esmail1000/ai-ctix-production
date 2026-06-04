'use client'

import Link from 'next/link'
import { useSearchParams } from 'next/navigation'
import { Suspense, useEffect, useMemo, useState, type ReactNode } from 'react'

type Severity = 'Critical' | 'High' | 'Medium' | 'Low'

type ExportReport = {
  id: string
  slug?: string
  name: string
  type?: string
  uploadedAt?: string
  owner?: string
  status?: string
  findings?: number
  critical?: number
  high?: number
  medium?: number
  low?: number
  summary?: string
  content?: string
  sourceFileName?: string
  parsingStatus?: string
  analysisVersion?: number
  parserVersion?: number
  parsingNotes?: string[]
  createdAtIso?: string
  updatedAtIso?: string
}

type ExportFinding = {
  id: string
  slug?: string
  reportId: string
  reportName?: string
  title: string
  cve?: string
  severity: Severity
  asset: string
  score?: number
  status?: string
  detectedAt?: string
  summary?: string
  impact?: string
  evidence?: string
  remediation?: string
  provenance?: {
    extractionMethod?: string
    parserConfidence?: number
    sourceSectionTitle?: string
  }
}

type ExportSnapshot = {
  version?: number
  initializedAtIso?: string
  reports?: ExportReport[]
  findings?: ExportFinding[]
}

type SeverityCounts = Record<Severity, number>

const APP_TIME_ZONE = 'Africa/Cairo'
const severityOrder: Severity[] = ['Critical', 'High', 'Medium', 'Low']

const severityBadgeClass: Record<Severity, string> = {
  Critical: 'border-red-200 bg-red-50 text-red-700',
  High: 'border-orange-200 bg-orange-50 text-orange-700',
  Medium: 'border-yellow-200 bg-yellow-50 text-yellow-700',
  Low: 'border-emerald-200 bg-emerald-50 text-emerald-700',
}

const reportStatusClass: Record<string, string> = {
  Ready: 'border-emerald-200 bg-emerald-50 text-emerald-700',
  Reviewed: 'border-[#c4e3cf] bg-[#f6fff9] text-[#087a3a]',
  Pending: 'border-yellow-200 bg-yellow-50 text-yellow-700',
}

function clean(value: unknown, fallback = '-') {
  const text = String(value ?? '').trim()
  if (!text || text === 'ΓÇö' || text === '╬ô├ç├╢') return fallback
  return text
}

function formatDate(value?: string) {
  if (!value) return '-'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value

  return new Intl.DateTimeFormat('en', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    hour12: true,
    timeZone: APP_TIME_ZONE,
  }).format(date)
}

function escapeHtml(value: unknown) {
  const text = clean(value, '')
  const map: Record<string, string> = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;',
  }

  return text.replace(/[&<>"']/g, (char) => map[char] ?? char)
}

function safeFileName(value: string) {
  return clean(value, 'report')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/gi, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
}

function normalizeConfidence(value: unknown) {
  const numeric = Number(value ?? 0)
  if (!Number.isFinite(numeric) || numeric <= 0) return 0
  const percentage = numeric <= 1 ? numeric * 100 : numeric
  return Math.max(0, Math.min(100, Math.round(percentage)))
}

function severityCounts(findings: ExportFinding[]): SeverityCounts {
  const counts: SeverityCounts = { Critical: 0, High: 0, Medium: 0, Low: 0 }

  for (const finding of findings) {
    if (severityOrder.includes(finding.severity)) {
      counts[finding.severity] += 1
    }
  }

  return counts
}

function reportRiskScore(findings: ExportFinding[]) {
  if (findings.length === 0) return 0
  return Math.max(...findings.map((finding) => Number(finding.score ?? 0)))
}

function averageConfidence(findings: ExportFinding[]) {
  if (findings.length === 0) return 0
  const values = findings.map((finding) =>
    normalizeConfidence(finding.provenance?.parserConfidence)
  )
  return Math.round(values.reduce((sum, value) => sum + value, 0) / values.length)
}

function riskBand(score: number) {
  if (score >= 90) return 'Critical'
  if (score >= 70) return 'High'
  if (score >= 40) return 'Medium'
  return 'Low'
}

function riskTone(score: number) {
  if (score >= 90) return 'text-red-700'
  if (score >= 70) return 'text-orange-700'
  if (score >= 40) return 'text-yellow-700'
  return 'text-emerald-700'
}

function topAssets(findings: ExportFinding[]) {
  const counters = new Map<string, number>()

  for (const finding of findings) {
    const asset = clean(finding.asset, 'Unknown asset')
    counters.set(asset, (counters.get(asset) ?? 0) + 1)
  }

  return Array.from(counters.entries())
    .map(([asset, count]) => ({ asset, count }))
    .sort((a, b) => b.count - a.count || a.asset.localeCompare(b.asset))
    .slice(0, 8)
}

function hasUsefulValue(value: string | undefined | null) {
  const normalized = (value ?? '').trim().toLowerCase()
  return Boolean(
    normalized &&
      normalized !== '-' &&
      normalized !== 'ΓÇö' &&
      normalized !== 'n/a' &&
      normalized !== 'none' &&
      normalized !== 'unknown'
  )
}

function formatExtractionMethod(method: string | undefined) {
  switch (method) {
    case 'nlp-hybrid':
      return 'NLP Hybrid'
    case 'structured-parser':
      return 'Structured Parser'
    case 'heuristic-fallback':
      return 'Heuristic Fallback'
    case 'manual':
      return 'Manual Review'
    case 'seed':
      return 'Seed Data'
    default:
      return clean(method, 'Unknown')
  }
}

function percent(part: number, total: number) {
  if (total === 0) return 0
  return Math.round((part / total) * 100)
}

function exportReadinessScore(findings: ExportFinding[]) {
  if (findings.length === 0) return 0

  const withEvidence = findings.filter((finding) => hasUsefulValue(finding.evidence)).length
  const withRemediation = findings.filter((finding) => hasUsefulValue(finding.remediation)).length
  const confidence = averageConfidence(findings)

  return Math.round(
    (withEvidence / findings.length) * 35 +
      (withRemediation / findings.length) * 35 +
      confidence * 0.3
  )
}

function severityNarrative(counts: SeverityCounts, total: number, band: string, riskScore: number) {
  if (total === 0) return 'No findings are currently included in this export package.'

  const criticalHigh = counts.Critical + counts.High

  if (criticalHigh > 0) {
    return `This report is classified as ${band} with a top observed risk score of ${riskScore}/100. ${criticalHigh} finding${criticalHigh > 1 ? 's' : ''} require priority review before closure.`
  }

  return `This report is classified as ${band} with a top observed risk score of ${riskScore}/100. Findings are currently concentrated in medium and low severity ranges.`
}

function reportFindingCount(report: ExportReport, findings: ExportFinding[]) {
  const countFromFindings = findings.filter((finding) => finding.reportId === report.id).length
  return countFromFindings || Number(report.findings ?? 0)
}

function csvEscape(value: unknown) {
  const text = clean(value, '')
  return `"${text.replace(/"/g, '""')}"`
}

function downloadBlob(blob: Blob, fileName: string) {
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')

  anchor.href = url
  anchor.download = fileName
  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()

  URL.revokeObjectURL(url)
}

function buildCsv(report: ExportReport, findings: ExportFinding[]) {
  const rows = [
    [
      'Report ID',
      'Report Name',
      'Finding ID',
      'Title',
      'Severity',
      'Score',
      'Asset',
      'CVE',
      'Status',
      'Method',
      'Confidence',
      'Detected At',
      'Summary',
      'Impact',
      'Evidence',
      'Remediation',
    ],
    ...findings.map((finding) => [
      report.id,
      report.name,
      finding.id,
      finding.title,
      finding.severity,
      finding.score ?? '',
      finding.asset,
      finding.cve ?? '',
      finding.status ?? '',
      formatExtractionMethod(finding.provenance?.extractionMethod),
      `${normalizeConfidence(finding.provenance?.parserConfidence)}%`,
      formatDate(finding.detectedAt),
      finding.summary ?? '',
      finding.impact ?? '',
      finding.evidence ?? '',
      finding.remediation ?? '',
    ]),
  ]

  return rows.map((row) => row.map(csvEscape).join(',')).join('\r\n')
}

function buildJson(report: ExportReport, findings: ExportFinding[]) {
  const counts = severityCounts(findings)
  const riskScore = reportRiskScore(findings)

  return JSON.stringify(
    {
      generatedAtIso: new Date().toISOString(),
      report,
      metrics: {
        riskScore,
        riskBand: riskBand(riskScore),
        findings: findings.length,
        severityCounts: counts,
        averageConfidence: averageConfidence(findings),
        exportReadiness: exportReadinessScore(findings),
        topAssets: topAssets(findings),
      },
      findings,
    },
    null,
    2
  )
}

function buildHtmlDocument(report: ExportReport, findings: ExportFinding[]) {
  const counts = severityCounts(findings)
  const riskScore = reportRiskScore(findings)
  const band = riskBand(riskScore)
  const assets = topAssets(findings)
  const topFindings = [...findings]
    .sort((a, b) => Number(b.score ?? 0) - Number(a.score ?? 0))
    .slice(0, 8)

  const findingRows = findings
    .map(
      (finding) => `
        <tr>
          <td>${escapeHtml(finding.id)}</td>
          <td>${escapeHtml(finding.title)}</td>
          <td>${escapeHtml(finding.severity)}</td>
          <td>${escapeHtml(finding.score ?? '-')}</td>
          <td>${escapeHtml(finding.asset)}</td>
          <td>${escapeHtml(finding.cve ?? '-')}</td>
          <td>${escapeHtml(finding.status ?? '-')}</td>
          <td>${escapeHtml(formatExtractionMethod(finding.provenance?.extractionMethod))}</td>
          <td>${normalizeConfidence(finding.provenance?.parserConfidence)}%</td>
        </tr>
      `
    )
    .join('')

  const topFindingRows = topFindings
    .map(
      (finding) => `
        <li>
          <strong>${escapeHtml(finding.title)}</strong>
          <span>${escapeHtml(finding.severity)} - ${escapeHtml(finding.score ?? '-')} / 100</span>
          <p>${escapeHtml(finding.summary ?? finding.impact ?? '')}</p>
        </li>
      `
    )
    .join('')

  const assetRows = assets
    .map((item) => `<li>${escapeHtml(item.asset)} <strong>${item.count}</strong></li>`)
    .join('')

  const noteRows = (report.parsingNotes ?? [])
    .map((note) => `<li>${escapeHtml(note)}</li>`)
    .join('')

  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>${escapeHtml(report.id)} - AI CTIX Report</title>
  <style>
    body { margin: 0; background: #ffffff; color: #0d2217; font-family: Arial, Helvetica, sans-serif; line-height: 1.55; }
    .page { max-width: 1120px; margin: 0 auto; padding: 32px; }
    .header { border-bottom: 3px solid #087a3a; padding-bottom: 20px; margin-bottom: 24px; }
    .kicker { color: #087a3a; font-size: 12px; text-transform: uppercase; letter-spacing: 0.14em; font-weight: 700; }
    h1 { margin: 8px 0 8px; font-size: 34px; line-height: 1.15; }
    h2 { margin-top: 28px; font-size: 21px; border-bottom: 1px solid #dcefe2; padding-bottom: 8px; }
    .summary { color: #4d6b5b; font-size: 15px; }
    .grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 20px 0; }
    .card { border: 1px solid #dcefe2; border-radius: 14px; padding: 14px; background: #f8fffa; }
    .label { color: #5a7668; font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em; font-weight: 700; }
    .value { margin-top: 6px; font-size: 20px; font-weight: 700; }
    table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 12px; }
    th { background: #edfdf3; color: #173128; text-align: left; padding: 10px; border: 1px solid #dcefe2; }
    td { padding: 9px; border: 1px solid #dcefe2; vertical-align: top; }
    li { margin-bottom: 10px; }
    li span { display: block; color: #5a7668; font-size: 13px; }
    .footer { margin-top: 36px; padding-top: 16px; border-top: 1px solid #dcefe2; color: #5a7668; font-size: 12px; }
    @media print { .page { padding: 0; } .card, table, tr, li { break-inside: avoid; } }
  </style>
</head>
<body>
  <main class="page">
    <section class="header">
      <div class="kicker">AI CTIX Export Report</div>
      <h1>${escapeHtml(report.name)}</h1>
      <p class="summary">${escapeHtml(report.summary ?? 'No executive summary available.')}</p>
    </section>

    <section class="grid">
      <div class="card"><div class="label">Report ID</div><div class="value">${escapeHtml(report.id)}</div></div>
      <div class="card"><div class="label">Risk Band</div><div class="value">${escapeHtml(band)}</div></div>
      <div class="card"><div class="label">Risk Score</div><div class="value">${riskScore}/100</div></div>
      <div class="card"><div class="label">Findings</div><div class="value">${findings.length}</div></div>
    </section>

    <h2>Report Metadata</h2>
    <table>
      <tr><th>Type</th><td>${escapeHtml(report.type ?? '-')}</td></tr>
      <tr><th>Status</th><td>${escapeHtml(report.status ?? '-')}</td></tr>
      <tr><th>Uploaded At</th><td>${escapeHtml(formatDate(report.uploadedAt))}</td></tr>
      <tr><th>Owner</th><td>${escapeHtml(report.owner ?? '-')}</td></tr>
      <tr><th>Source File</th><td>${escapeHtml(report.sourceFileName ?? '-')}</td></tr>
    </table>

    <h2>Severity Breakdown</h2>
    <table>
      <tr><th>Critical</th><th>High</th><th>Medium</th><th>Low</th></tr>
      <tr><td>${counts.Critical}</td><td>${counts.High}</td><td>${counts.Medium}</td><td>${counts.Low}</td></tr>
    </table>

    <h2>Top Affected Assets</h2>
    <ul>${assetRows || '<li>No affected assets available.</li>'}</ul>

    <h2>Top Risk Findings</h2>
    <ol>${topFindingRows || '<li>No findings available.</li>'}</ol>

    <h2>All Findings</h2>
    <table>
      <thead>
        <tr><th>ID</th><th>Finding</th><th>Severity</th><th>Score</th><th>Asset</th><th>CVE</th><th>Status</th><th>Method</th><th>Confidence</th></tr>
      </thead>
      <tbody>${findingRows || '<tr><td colspan="9">No findings available.</td></tr>'}</tbody>
    </table>

    <h2>NLP / Parser Notes</h2>
    <ul>${noteRows || '<li>No parser notes available.</li>'}</ul>

    <section class="footer">Generated from AI CTIX Extractor - ${escapeHtml(new Date().toISOString())}</section>
  </main>
</body>
</html>`
}

function buildPowerPointHtml(report: ExportReport, findings: ExportFinding[]) {
  const counts = severityCounts(findings)
  const riskScore = reportRiskScore(findings)
  const band = riskBand(riskScore)
  const assets = topAssets(findings)
  const topFindings = findings.slice(0, 6)
  const readiness = exportReadinessScore(findings)

  const findingRows = topFindings
    .map(
      (finding) => `
        <tr>
          <td>${escapeHtml(finding.title)}</td>
          <td>${escapeHtml(finding.severity)}</td>
          <td>${escapeHtml(finding.score ?? '-')}</td>
          <td>${escapeHtml(finding.asset)}</td>
        </tr>
      `
    )
    .join('')

  const assetRows = assets
    .slice(0, 7)
    .map((asset) => `<li>${escapeHtml(asset.asset)} - ${asset.count} finding${asset.count > 1 ? 's' : ''}</li>`)
    .join('')

  return `<!doctype html>
<html xmlns:o="urn:schemas-microsoft-com:office:office"
      xmlns:p="urn:schemas-microsoft-com:office:powerpoint"
      xmlns="http://www.w3.org/TR/REC-html40">
<head>
  <meta charset="utf-8" />
  <meta name="ProgId" content="PowerPoint.Slide" />
  <meta name="Generator" content="AI CTIX" />
  <title>${escapeHtml(report.name)} - AI CTIX Briefing</title>
  <style>
    body {
      margin: 0;
      background: #fbfefd;
      color: #0d2217;
      font-family: Arial, Helvetica, sans-serif;
    }

    .slide {
      width: 960px;
      height: 540px;
      padding: 42px;
      box-sizing: border-box;
      page-break-after: always;
      background: linear-gradient(135deg, #fbfefd 0%, #ffffff 58%, #edfdf3 100%);
      border-top: 10px solid #087a3a;
      position: relative;
    }

    .kicker {
      color: #087a3a;
      font-size: 12px;
      letter-spacing: 0.16em;
      text-transform: uppercase;
      font-weight: 700;
      margin-bottom: 14px;
    }

    h1 {
      font-size: 38px;
      line-height: 1.08;
      margin: 0 0 18px;
      max-width: 760px;
    }

    h2 {
      font-size: 30px;
      line-height: 1.1;
      margin: 0 0 18px;
    }

    p {
      font-size: 17px;
      line-height: 1.5;
      color: #5a7668;
      max-width: 790px;
    }

    .metrics {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 14px;
      margin-top: 36px;
    }

    .metric {
      background: #ffffff;
      border: 1px solid #dceee3;
      border-radius: 18px;
      padding: 18px;
    }

    .label {
      color: #5a7668;
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      font-weight: 700;
    }

    .value {
      margin-top: 8px;
      font-size: 26px;
      font-weight: 700;
      color: #0d2217;
    }

    .green {
      color: #087a3a;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 24px;
      font-size: 14px;
      background: white;
    }

    th {
      text-align: left;
      background: #edfdf3;
      color: #173128;
      padding: 12px;
      border: 1px solid #dceee3;
    }

    td {
      padding: 12px;
      border: 1px solid #dceee3;
      color: #173128;
      vertical-align: top;
    }

    li {
      font-size: 18px;
      line-height: 1.55;
      margin-bottom: 12px;
      color: #173128;
    }

    .footer {
      position: absolute;
      bottom: 24px;
      left: 42px;
      right: 42px;
      color: #7a8d83;
      font-size: 11px;
      border-top: 1px solid #dceee3;
      padding-top: 10px;
    }
  </style>
</head>
<body>
  <section class="slide">
    <div class="kicker">AI CTIX Export Briefing</div>
    <h1>${escapeHtml(report.name)}</h1>
    <p>${escapeHtml(clean(report.summary, 'Generated security intelligence export briefing.'))}</p>

    <div class="metrics">
      <div class="metric"><div class="label">Risk</div><div class="value green">${escapeHtml(band)}</div></div>
      <div class="metric"><div class="label">Score</div><div class="value">${riskScore}/100</div></div>
      <div class="metric"><div class="label">Findings</div><div class="value">${findings.length}</div></div>
      <div class="metric"><div class="label">Readiness</div><div class="value">${readiness}%</div></div>
    </div>

    <div class="footer">Generated from AI CTIX Extractor - ${escapeHtml(new Date().toISOString())}</div>
  </section>

  <section class="slide">
    <div class="kicker">Executive Summary</div>
    <h2>Security posture overview</h2>
    <p>${escapeHtml(severityNarrative(counts, findings.length, band, riskScore))}</p>

    <div class="metrics">
      <div class="metric"><div class="label">Critical</div><div class="value">${counts.Critical}</div></div>
      <div class="metric"><div class="label">High</div><div class="value">${counts.High}</div></div>
      <div class="metric"><div class="label">Medium</div><div class="value">${counts.Medium}</div></div>
      <div class="metric"><div class="label">Low</div><div class="value">${counts.Low}</div></div>
    </div>

    <div class="footer">AI CTIX Export Briefing</div>
  </section>

  <section class="slide">
    <div class="kicker">Priority Findings</div>
    <h2>Top risk findings</h2>
    <table>
      <thead>
        <tr>
          <th>Finding</th>
          <th>Severity</th>
          <th>Score</th>
          <th>Asset</th>
        </tr>
      </thead>
      <tbody>${findingRows || '<tr><td colspan="4">No findings available.</td></tr>'}</tbody>
    </table>

    <div class="footer">AI CTIX Export Briefing</div>
  </section>

  <section class="slide">
    <div class="kicker">Affected Assets</div>
    <h2>Exposure concentration</h2>
    <ul>${assetRows || '<li>No affected assets available.</li>'}</ul>

    <div class="footer">AI CTIX Export Briefing</div>
  </section>
</body>
</html>`
}

function ExportLoading() {
  return (
    <main className="relative min-h-screen overflow-hidden bg-[#fbfefd] text-[#111827]">
      <Background />
      <section className="relative mx-auto max-w-7xl px-6 py-16 lg:px-8">
        <div className="rounded-[28px] border border-[#dceee3] bg-white/95 p-10 text-center shadow-[0_22px_60px_rgba(15,43,29,0.06)]">
          <div className="mx-auto h-12 w-12 animate-spin rounded-full border-4 border-[#087a3a] border-t-transparent" />
          <p className="mt-4 text-sm font-semibold text-[#087a3a]">Loading export workspace...</p>
        </div>
      </section>
    </main>
  )
}

export default function ExportPage() {
  return (
    <Suspense fallback={<ExportLoading />}>
      <ExportPageContent />
    </Suspense>
  )
}

function ExportPageContent() {
  const [snapshot, setSnapshot] = useState<ExportSnapshot | null>(null)
  const searchParams = useSearchParams()
  const requestedReportId = searchParams.get('reportId')?.trim() ?? ''
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    let cancelled = false

    async function loadExportData() {
      try {
        setLoading(true)
        setError('')

        const response = await fetch('/api/export', { cache: 'no-store' })

        if (!response.ok) {
          throw new Error('Failed to load export snapshot.')
        }

        const payload: ExportSnapshot = await response.json()

        if (!cancelled) {
          setSnapshot(payload)
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : 'Export page failed to load.')
        }
      } finally {
        if (!cancelled) {
          setLoading(false)
        }
      }
    }

    loadExportData()

    return () => {
      cancelled = true
    }
  }, [])

  const reports = useMemo(() => snapshot?.reports ?? [], [snapshot])
  const allFindings = useMemo(() => snapshot?.findings ?? [], [snapshot])

  const selectedReport = useMemo(() => {
    if (!requestedReportId) return null
    return reports.find((report) => report.id === requestedReportId) ?? null
  }, [reports, requestedReportId])

  const reportFindings = useMemo(() => {
    if (!selectedReport) return []
    return allFindings
      .filter((finding) => finding.reportId === selectedReport.id)
      .sort((a, b) => Number(b.score ?? 0) - Number(a.score ?? 0))
  }, [allFindings, selectedReport])

  const counts = useMemo(() => severityCounts(reportFindings), [reportFindings])
  const riskScore = useMemo(() => reportRiskScore(reportFindings), [reportFindings])
  const band = riskBand(riskScore)
  const assets = useMemo(() => topAssets(reportFindings), [reportFindings])
  const avgConfidence = useMemo(() => averageConfidence(reportFindings), [reportFindings])

  useEffect(() => {
    if (selectedReport) {
      document.title = `${selectedReport.id} Export Report - AI CTIX`
    }
  }, [selectedReport])

  function printReport() {
    window.print()
  }

  function downloadHtmlReport() {
    if (!selectedReport) return
    const html = buildHtmlDocument(selectedReport, reportFindings)
    downloadBlob(new Blob([html], { type: 'text/html;charset=utf-8' }), `${safeFileName(selectedReport.id)}-ai-ctix-report.html`)
  }

  function downloadJsonReport() {
    if (!selectedReport) return
    const json = buildJson(selectedReport, reportFindings)
    downloadBlob(new Blob([json], { type: 'application/json;charset=utf-8' }), `${safeFileName(selectedReport.id)}-ai-ctix-report.json`)
  }

  function downloadCsvReport() {
    if (!selectedReport) return
    const csv = buildCsv(selectedReport, reportFindings)
    downloadBlob(new Blob([csv], { type: 'text/csv;charset=utf-8' }), `${safeFileName(selectedReport.id)}-ai-ctix-findings.csv`)
  }

  function downloadPptxReport() {
    if (!selectedReport) return

    const ppt = buildPowerPointHtml(selectedReport, reportFindings)

    downloadBlob(
      new Blob([ppt], { type: 'application/vnd.ms-powerpoint;charset=utf-8' }),
      `${safeFileName(selectedReport.id)}-ai-ctix-briefing.ppt`
    )
  }

  if (loading) return <ExportLoading />

  if (error) {
    return (
      <main className="relative min-h-screen overflow-hidden bg-[#fbfefd] text-[#111827]">
        <Background />
        <section className="relative mx-auto max-w-7xl px-6 py-16 lg:px-8">
          <div className="rounded-[28px] border border-red-200 bg-red-50 p-8 text-center">
            <h1 className="text-2xl font-semibold text-red-700">Export Error</h1>
            <p className="mt-3 text-sm text-red-600">{error}</p>
          </div>
        </section>
      </main>
    )
  }

  if (!requestedReportId) {
    return (
      <main className="relative min-h-screen overflow-hidden bg-[#fbfefd] text-[#111827]">
        <Background />
        <section className="relative mx-auto max-w-[1480px] px-6 pb-16 pt-10 lg:px-8">
          <ExportHero
            title="Export intelligence reports"
            description="Choose a report and generate PDF, CSV, JSON, HTML, or PPT exports from the existing /api/export snapshot."
            primaryAction={<ActionLink href="/api/export" primary>Raw JSON Export</ActionLink>}
          />

          <section className="mt-6 grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            {reports.length === 0 ? (
              <div className="rounded-[28px] border border-dashed border-[#c4e3cf] bg-white p-10 text-center shadow-sm md:col-span-2 xl:col-span-3">
                <p className="text-lg font-semibold text-[#173128]">No reports available.</p>
                <p className="mt-2 text-sm text-[#5a7668]">Analyze a report first, then return to export.</p>
                <div className="mt-5"><ActionLink href="/analyzer" primary>Analyze Report</ActionLink></div>
              </div>
            ) : (
              reports.map((report) => {
                const findingCount = reportFindingCount(report, allFindings)

                return (
                  <Link
                    key={report.id}
                    href={`/export?reportId=${encodeURIComponent(report.id)}`}
                    className="group rounded-[28px] border border-[#dceee3] bg-white/95 p-5 shadow-[0_22px_60px_rgba(15,43,29,0.05)] transition hover:-translate-y-1 hover:border-[#b7ddc4] hover:shadow-[0_30px_80px_rgba(15,43,29,0.09)]"
                  >
                    <div className="flex items-center justify-between gap-3">
                      <Badge className="border-[#c4e3cf] bg-[#f6fff9] text-[#173128]">{report.id}</Badge>
                      <Badge className={reportStatusClass[report.status ?? ''] ?? 'border-[#dceee3] bg-white text-[#44554b]'}>
                        {report.status ?? 'Unknown'}
                      </Badge>
                    </div>

                    <h2 className="mt-4 text-xl font-semibold text-[#0d2217]">{report.name}</h2>
                    <p className="mt-2 line-clamp-3 text-sm leading-6 text-[#5a7668]">{report.summary ?? 'No summary available.'}</p>

                    <div className="mt-4 grid grid-cols-4 gap-2 text-center text-xs">
                      <span className="rounded-2xl bg-red-50 px-2 py-2 font-semibold text-red-700">C {report.critical ?? 0}</span>
                      <span className="rounded-2xl bg-orange-50 px-2 py-2 font-semibold text-orange-700">H {report.high ?? 0}</span>
                      <span className="rounded-2xl bg-yellow-50 px-2 py-2 font-semibold text-yellow-700">M {report.medium ?? 0}</span>
                      <span className="rounded-2xl bg-emerald-50 px-2 py-2 font-semibold text-emerald-700">L {report.low ?? 0}</span>
                    </div>

                    <div className="mt-5 rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] p-4">
                      <p className="text-xs font-semibold uppercase tracking-wide text-[#5a7668]">Export package</p>
                      <p className="mt-2 text-sm font-semibold text-[#173128]">{findingCount} findings included</p>
                    </div>
                  </Link>
                )
              })
            )}
          </section>
        </section>
      </main>
    )
  }

  if (!selectedReport) {
    return (
      <main className="relative min-h-screen overflow-hidden bg-[#fbfefd] text-[#111827]">
        <Background />
        <section className="relative mx-auto max-w-7xl px-6 py-16 lg:px-8">
          <div className="rounded-[28px] border border-amber-200 bg-amber-50 p-8 text-center">
            <h1 className="text-2xl font-semibold text-amber-800">Report not found</h1>
            <p className="mt-3 text-sm text-amber-700">No report found for ID: {requestedReportId}</p>
            <div className="mt-6"><ActionLink href="/export" primary>Choose another report</ActionLink></div>
          </div>
        </section>
      </main>
    )
  }

  const topFindings = reportFindings.slice(0, 8)
  const findingsWithEvidence = reportFindings.filter((finding) => hasUsefulValue(finding.evidence)).length
  const findingsWithRemediation = reportFindings.filter((finding) => hasUsefulValue(finding.remediation)).length
  const lowConfidenceFindings = reportFindings.filter(
    (finding) => normalizeConfidence(finding.provenance?.parserConfidence) < 70
  ).length
  const fallbackFindings = reportFindings.filter(
    (finding) => finding.provenance?.extractionMethod === 'heuristic-fallback'
  ).length

  const readiness = exportReadinessScore(reportFindings)

  const exportChecks = [
    { label: 'Report selected', value: 'Yes', ready: true },
    { label: 'Findings available', value: String(reportFindings.length), ready: reportFindings.length > 0 },
    { label: 'Evidence available', value: `${findingsWithEvidence}/${reportFindings.length}`, ready: reportFindings.length > 0 && findingsWithEvidence === reportFindings.length },
    { label: 'Remediation available', value: `${findingsWithRemediation}/${reportFindings.length}`, ready: reportFindings.length > 0 && findingsWithRemediation === reportFindings.length },
    { label: 'Critical findings included', value: counts.Critical > 0 ? 'Yes' : 'No critical findings', ready: true },
    { label: 'Low-confidence findings', value: String(lowConfidenceFindings), ready: lowConfidenceFindings === 0 },
    { label: 'Fallback findings', value: String(fallbackFindings), ready: fallbackFindings === 0 },
  ]

  const exportReady = exportChecks.every((check) => check.ready)

  return (
    <>
      <style>{`
        @media print {
          @page { margin: 14mm; }
          body { background: #ffffff !important; }
          body > header, .no-print { display: none !important; }
          .print-page { max-width: none !important; padding: 0 !important; }
          .print-card { border: 0 !important; box-shadow: none !important; padding: 0 !important; }
          .print-section, table, tr { break-inside: avoid; }
          .print-table-wrapper { overflow: visible !important; }
        }

        @keyframes export-orbit-spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        @keyframes export-logo-float { 0%, 100% { transform: translateY(0) rotate(0deg); } 50% { transform: translateY(-12px) rotate(2deg); } }
        .export-orbit { animation: export-orbit-spin 14s linear infinite; }
        .export-orbit > div:first-child { animation: export-logo-float 6s ease-in-out infinite; }
        .export-platform { transform: perspective(800px) rotateX(58deg); }
      `}</style>

      <main className="relative min-h-screen overflow-hidden bg-[#fbfefd] text-[#111827]">
        <Background />

        <section className="print-page relative mx-auto max-w-[1480px] px-6 pb-16 pt-10 lg:px-8">
          <div className="no-print">
            <ExportHero
              title="Export report package"
              description="Generate a polished report and export it as PDF, CSV, JSON, HTML, or PPT without changing the backend."
              primaryAction={<button onClick={printReport} className="rounded-2xl bg-[#087a3a] px-5 py-3 text-sm font-semibold text-white shadow-[0_16px_32px_rgba(8,122,58,0.18)] transition hover:-translate-y-0.5 hover:bg-[#066b33]">PDF</button>}
            />
          </div>

          <section className="no-print mt-6 grid gap-4 md:grid-cols-2 xl:grid-cols-5">
            <ExportOption title="PDF" description="Use browser print and save the polished report as PDF." action={printReport} primary />
            <ExportOption title="CSV" description="Download findings rows for Excel, Sheets, or BI tools." action={downloadCsvReport} />
            <ExportOption title="JSON" description="Download report, metrics, and findings as structured JSON." action={downloadJsonReport} />
            <ExportOption title="HTML" description="Download a standalone readable HTML report." action={downloadHtmlReport} />
            <ExportOption title="PPT" description="Download a briefing deck with summary slides." action={downloadPptxReport} />
          </section>

          <section className="no-print mt-6 grid gap-4 md:grid-cols-2 xl:grid-cols-5">
            <MetricCard label="Risk band" value={band} helper="Highest score band" />
            <MetricCard label="Risk score" value={`${riskScore}/100`} helper="Report maximum" valueClass={riskTone(riskScore)} />
            <MetricCard label="Findings" value={String(reportFindings.length)} helper="Included in export" />
            <MetricCard label="Confidence" value={`${avgConfidence}%`} helper="Normalized average" />
            <MetricCard label="Readiness" value={`${readiness}%`} helper={exportReady ? 'Ready' : 'Review'} />
          </section>

          <section className="no-print mt-6 grid gap-6 xl:grid-cols-[1fr_430px]">
            <div className="rounded-[32px] border border-[#dceee3] bg-white/95 p-6 shadow-[0_22px_60px_rgba(15,43,29,0.06)] backdrop-blur">
              <div className="flex flex-wrap items-start justify-between gap-4">
                <div>
                  <p className="text-sm font-semibold uppercase tracking-[0.18em] text-[#087a3a]">Selected report</p>
                  <h1 className="mt-2 text-3xl font-semibold tracking-[-0.035em] text-[#0d2217]">{selectedReport.name}</h1>
                  <p className="mt-3 max-w-4xl text-sm leading-7 text-[#5a7668]">{selectedReport.summary ?? 'No executive summary available.'}</p>
                </div>
                <Badge className={reportStatusClass[selectedReport.status ?? ''] ?? 'border-[#dceee3] bg-white text-[#44554b]'}>
                  {selectedReport.status ?? 'Unknown'}
                </Badge>
              </div>

              <div className="mt-5 flex flex-wrap gap-3">
                <ActionLink href="/export">Choose Report</ActionLink>
                <ActionLink href={`/reports/${encodeURIComponent(selectedReport.id)}`}>Report Details</ActionLink>
                <ActionLink href={`/results?reportId=${encodeURIComponent(selectedReport.id)}`}>Findings</ActionLink>
                <ActionLink href={`/risk-scoring?reportId=${encodeURIComponent(selectedReport.id)}`}>Risk</ActionLink>
                <ActionLink href={`/graph?reportId=${encodeURIComponent(selectedReport.id)}`}>Graph</ActionLink>
              </div>
            </div>

            <SidePanel title="Export readiness">
              <div className="mb-5">
                <Badge className={exportReady ? 'border-emerald-200 bg-emerald-50 text-emerald-700' : 'border-yellow-200 bg-yellow-50 text-yellow-700'}>
                  {exportReady ? 'Ready for export' : 'Needs analyst review'}
                </Badge>
              </div>

              <div className="space-y-3">
                {exportChecks.map((check) => (
                  <div key={check.label} className="rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] p-4">
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <p className="text-sm font-semibold text-[#173128]">{check.label}</p>
                        <p className="mt-1 text-sm text-[#5a7668]">{check.value}</p>
                      </div>
                      <span className={`text-xs font-semibold ${check.ready ? 'text-[#087a3a]' : 'text-yellow-700'}`}>
                        {check.ready ? 'Ready' : 'Review'}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </SidePanel>
          </section>

          <article className="print-card mt-6 overflow-hidden rounded-[34px] border border-[#dceee3] bg-white shadow-[0_24px_80px_rgba(15,43,29,0.07)]">
            <section className="print-section relative overflow-hidden border-b border-[#dcefe2] bg-[#fbfffd] p-8">
              <div className="pointer-events-none absolute right-0 top-0 h-full w-1/2 bg-[radial-gradient(circle_at_70%_30%,rgba(8,122,58,0.11),transparent_34%),linear-gradient(135deg,rgba(8,122,58,0.04),transparent_55%)]" />

              <div className="relative grid gap-8 xl:grid-cols-[1fr_340px]">
                <div>
                  <p className="text-xs font-bold uppercase tracking-[0.24em] text-[#087a3a]">AI CTIX Export Report</p>
                  <h1 className="mt-4 max-w-4xl text-4xl font-semibold tracking-[-0.04em] text-[#0d2217] md:text-5xl">{selectedReport.name}</h1>
                  <p className="mt-4 max-w-5xl text-base leading-8 text-[#5a7668]">{selectedReport.summary ?? 'No executive summary available.'}</p>

                  <div className="mt-6 flex flex-wrap gap-3">
                    <Badge className="border-[#c4e3cf] bg-white text-[#173128]">Report {selectedReport.id}</Badge>
                    <Badge className={reportStatusClass[selectedReport.status ?? ''] ?? 'border-[#dceee3] bg-white text-[#44554b]'}>
                      {selectedReport.status ?? 'Unknown'}
                    </Badge>
                    <Badge className="border-[#c4e3cf] bg-white text-[#087a3a]">Generated {formatDate(new Date().toISOString())}</Badge>
                  </div>
                </div>

                <div className="rounded-[28px] border border-[#dceee3] bg-white/92 p-6 shadow-[0_20px_60px_rgba(15,43,29,0.06)]">
                  <p className="text-xs font-semibold uppercase tracking-[0.18em] text-[#5a7668]">Report scorecard</p>
                  <div className="mt-5 grid gap-4">
                    <div>
                      <p className="text-sm text-[#5a7668]">Risk band</p>
                      <p className={`mt-1 text-4xl font-semibold ${riskTone(riskScore)}`}>{band}</p>
                    </div>
                    <div className="h-2 overflow-hidden rounded-full bg-[#e6f5eb]">
                      <div className="h-full rounded-full bg-[#087a3a]" style={{ width: `${Math.max(6, riskScore)}%` }} />
                    </div>
                    <div className="grid grid-cols-2 gap-3">
                      <MiniStat label="Score" value={`${riskScore}/100`} />
                      <MiniStat label="Readiness" value={`${readiness}%`} />
                    </div>
                  </div>
                </div>
              </div>
            </section>

            <section className="print-section p-8">
              <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-5">
                <MetricCard label="Risk Band" value={band} helper="Highest score band" />
                <MetricCard label="Risk Score" value={`${riskScore}/100`} helper="Maximum finding score" valueClass={riskTone(riskScore)} />
                <MetricCard label="Findings" value={String(reportFindings.length)} helper="Included records" />
                <MetricCard label="Avg Confidence" value={`${avgConfidence}%`} helper="Normalized confidence" />
                <MetricCard label="Export Readiness" value={`${readiness}%`} helper="Evidence and remediation quality" />
              </div>
            </section>

            <section className="print-section px-8 pb-8">
              <div className="grid gap-6 xl:grid-cols-[1fr_430px]">
                <div className="rounded-[28px] border border-[#dceee3] bg-[#fbfffd] p-6">
                  <p className="text-sm font-semibold uppercase tracking-[0.18em] text-[#087a3a]">Executive narrative</p>
                  <h2 className="mt-2 text-2xl font-semibold text-[#0d2217]">Security posture summary</h2>
                  <p className="mt-4 text-base leading-8 text-[#173128]">
                    {severityNarrative(counts, reportFindings.length, band, riskScore)}
                  </p>
                  <p className="mt-4 text-sm leading-7 text-[#5a7668]">
                    The package below contains report metadata, severity distribution, affected assets, top risk findings, evidence quality indicators, and the complete findings appendix.
                  </p>
                </div>

                <div className="rounded-[28px] border border-[#dceee3] bg-white p-6">
                  <h2 className="text-xl font-semibold text-[#0d2217]">Report metadata</h2>
                  <div className="mt-4 grid gap-3">
                    <InfoLine label="Type" value={selectedReport.type ?? '-'} />
                    <InfoLine label="Uploaded At" value={formatDate(selectedReport.uploadedAt)} />
                    <InfoLine label="Owner" value={selectedReport.owner ?? '-'} />
                    <InfoLine label="Source File" value={selectedReport.sourceFileName ?? '-'} />
                    <InfoLine label="Parser Version" value={selectedReport.parserVersion ?? '-'} />
                  </div>
                </div>
              </div>
            </section>

            <section className="print-section px-8 pb-8">
              <div className="grid gap-6 xl:grid-cols-[1fr_430px]">
                <div className="rounded-[28px] border border-[#dceee3] bg-white p-6">
                  <h2 className="text-2xl font-semibold text-[#0d2217]">Severity distribution</h2>
                  <div className="mt-5 grid gap-4">
                    {severityOrder.map((severity) => {
                      const value = counts[severity]
                      const width = percent(value, reportFindings.length)

                      return (
                        <div key={severity}>
                          <div className="mb-2 flex items-center justify-between gap-3 text-sm">
                            <Badge className={severityBadgeClass[severity]}>{severity}</Badge>
                            <span className="font-semibold text-[#173128]">{value} findings ({width}%)</span>
                          </div>
                          <div className="h-2 overflow-hidden rounded-full bg-[#e6f5eb]">
                            <div className="h-full rounded-full bg-[#087a3a]" style={{ width: `${width}%` }} />
                          </div>
                        </div>
                      )
                    })}
                  </div>
                </div>

                <div className="rounded-[28px] border border-[#dceee3] bg-white p-6">
                  <h2 className="text-2xl font-semibold text-[#0d2217]">Top affected assets</h2>
                  <div className="mt-5 grid gap-3">
                    {assets.length > 0 ? (
                      assets.map((item) => (
                        <div key={item.asset} className="rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] p-4">
                          <div className="flex items-center justify-between gap-4">
                            <span className="break-words text-sm font-semibold text-[#173128]">{item.asset}</span>
                            <span className="rounded-full bg-white px-3 py-1 text-xs font-bold text-[#087a3a]">{item.count}</span>
                          </div>
                          <div className="mt-3 h-2 overflow-hidden rounded-full bg-[#e6f5eb]">
                            <div className="h-full rounded-full bg-[#087a3a]" style={{ width: `${percent(item.count, reportFindings.length)}%` }} />
                          </div>
                        </div>
                      ))
                    ) : (
                      <p className="rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] p-4 text-sm text-[#5a7668]">No affected assets available.</p>
                    )}
                  </div>
                </div>
              </div>
            </section>

            <section className="print-section px-8 pb-8">
              <div className="rounded-[28px] border border-[#dceee3] bg-white p-6">
                <h2 className="text-2xl font-semibold text-[#0d2217]">Top risk findings</h2>
                <div className="mt-5 grid gap-5">
                  {topFindings.length > 0 ? (
                    topFindings.map((finding, index) => (
                      <div key={finding.id} className="rounded-[26px] border border-[#dcefe2] bg-[#fbfffc] p-5">
                        <div className="flex flex-wrap items-center justify-between gap-3">
                          <div className="flex flex-wrap items-center gap-2">
                            <Badge className="border-[#c4e3cf] bg-white text-[#173128]">Priority {index + 1}</Badge>
                            <Badge className="border-[#c4e3cf] bg-white text-[#173128]">{finding.id}</Badge>
                            <Badge className={severityBadgeClass[finding.severity]}>{finding.severity}</Badge>
                          </div>
                          <span className={`text-lg font-semibold ${riskTone(Number(finding.score ?? 0))}`}>{finding.score ?? '-'}/100</span>
                        </div>

                        <h3 className="mt-4 text-xl font-semibold text-[#0d2217]">{finding.title}</h3>
                        <p className="mt-2 text-sm leading-7 text-[#5a7668]">{finding.summary ?? finding.impact ?? 'No summary available.'}</p>

                        <div className="mt-4 grid gap-3 md:grid-cols-3">
                          <InfoLine label="Asset" value={finding.asset} />
                          <InfoLine label="CVE" value={finding.cve ?? '-'} />
                          <InfoLine label="Status" value={finding.status ?? '-'} />
                          <InfoLine label="Method" value={formatExtractionMethod(finding.provenance?.extractionMethod)} />
                          <InfoLine label="Confidence" value={`${normalizeConfidence(finding.provenance?.parserConfidence)}%`} />
                          <InfoLine label="Detected" value={formatDate(finding.detectedAt)} />
                        </div>

                        <div className="mt-4 grid gap-3 md:grid-cols-2">
                          <div className="rounded-2xl border border-[#e4f2e9] bg-white p-4">
                            <p className="text-xs font-semibold uppercase tracking-wide text-[#5a7668]">Evidence</p>
                            <p className="mt-2 text-sm leading-7 text-[#173128]">{finding.evidence ?? 'No evidence available.'}</p>
                          </div>
                          <div className="rounded-2xl border border-[#e4f2e9] bg-white p-4">
                            <p className="text-xs font-semibold uppercase tracking-wide text-[#5a7668]">Remediation</p>
                            <p className="mt-2 text-sm leading-7 text-[#173128]">{finding.remediation ?? 'No remediation available.'}</p>
                          </div>
                        </div>
                      </div>
                    ))
                  ) : (
                    <p className="rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] p-4 text-sm text-[#5a7668]">No findings available for this report.</p>
                  )}
                </div>
              </div>
            </section>

            <section className="print-section px-8 pb-8">
              <div className="grid gap-6 xl:grid-cols-2">
                <div className="rounded-[28px] border border-[#dceee3] bg-white p-6">
                  <h2 className="text-2xl font-semibold text-[#0d2217]">NLP / Parser notes</h2>
                  <div className="mt-4 space-y-3">
                    {(selectedReport.parsingNotes ?? []).length > 0 ? (
                      selectedReport.parsingNotes?.map((note, index) => (
                        <p key={`${note}-${index}`} className="rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] p-4 text-sm leading-6 text-[#5a7668]">{note}</p>
                      ))
                    ) : (
                      <p className="rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] p-4 text-sm text-[#5a7668]">No parser notes available.</p>
                    )}
                  </div>
                </div>

                <div className="rounded-[28px] border border-[#dceee3] bg-white p-6">
                  <h2 className="text-2xl font-semibold text-[#0d2217]">Quality indicators</h2>
                  <div className="mt-4 grid gap-3">
                    <InfoLine label="Evidence coverage" value={`${findingsWithEvidence}/${reportFindings.length}`} />
                    <InfoLine label="Remediation coverage" value={`${findingsWithRemediation}/${reportFindings.length}`} />
                    <InfoLine label="Low confidence findings" value={String(lowConfidenceFindings)} />
                    <InfoLine label="Fallback extraction findings" value={String(fallbackFindings)} />
                  </div>
                </div>
              </div>
            </section>

            <section className="print-section px-8 pb-8">
              <div className="rounded-[28px] border border-[#dceee3] bg-white p-6">
                <h2 className="text-2xl font-semibold text-[#0d2217]">All findings appendix</h2>
                <div className="print-table-wrapper mt-4 overflow-x-auto rounded-[22px] border border-[#dcefe2]">
                  <table className="min-w-full divide-y divide-[#dcefe2] text-left text-sm">
                    <thead className="bg-[#edfdf3] text-xs uppercase tracking-wide text-[#173128]">
                      <tr>
                        <th className="px-4 py-3">ID</th>
                        <th className="px-4 py-3">Finding</th>
                        <th className="px-4 py-3">Severity</th>
                        <th className="px-4 py-3">Score</th>
                        <th className="px-4 py-3">Asset</th>
                        <th className="px-4 py-3">CVE</th>
                        <th className="px-4 py-3">Status</th>
                        <th className="px-4 py-3">Method</th>
                        <th className="px-4 py-3">Confidence</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#e4f2e9] bg-white">
                      {reportFindings.length > 0 ? (
                        reportFindings.map((finding) => (
                          <tr key={finding.id}>
                            <td className="whitespace-nowrap px-4 py-3 font-semibold text-[#173128]">{finding.id}</td>
                            <td className="min-w-[260px] px-4 py-3 text-[#173128]">{finding.title}</td>
                            <td className="whitespace-nowrap px-4 py-3"><Badge className={severityBadgeClass[finding.severity]}>{finding.severity}</Badge></td>
                            <td className="whitespace-nowrap px-4 py-3 font-semibold text-[#173128]">{finding.score ?? '-'}</td>
                            <td className="min-w-[180px] px-4 py-3 text-[#5a7668]">{finding.asset}</td>
                            <td className="whitespace-nowrap px-4 py-3 text-[#5a7668]">{finding.cve ?? '-'}</td>
                            <td className="whitespace-nowrap px-4 py-3 text-[#5a7668]">{finding.status ?? '-'}</td>
                            <td className="whitespace-nowrap px-4 py-3 text-[#5a7668]">{formatExtractionMethod(finding.provenance?.extractionMethod)}</td>
                            <td className="whitespace-nowrap px-4 py-3 text-[#5a7668]">{normalizeConfidence(finding.provenance?.parserConfidence)}%</td>
                          </tr>
                        ))
                      ) : (
                        <tr><td colSpan={9} className="px-4 py-6 text-center text-[#5a7668]">No findings available.</td></tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </section>

            <section className="px-8 pb-8 text-xs leading-6 text-[#5a7668]">
              <div className="border-t border-[#dcefe2] pt-5">
                Generated from AI CTIX Extractor - {new Date().toISOString()}
              </div>
            </section>
          </article>
        </section>
      </main>
    </>
  )
}

function Background() {
  return (
    <>
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_18%_10%,rgba(34,197,94,0.10),transparent_30%),radial-gradient(circle_at_86%_18%,rgba(8,122,58,0.08),transparent_34%)]" />
      <div className="pointer-events-none absolute right-0 top-24 h-[420px] w-[560px] rounded-full bg-[#dcf7e7]/60 blur-3xl" />
      <div className="pointer-events-none absolute left-0 top-[560px] h-[320px] w-[520px] rounded-full bg-[#eefaf3] blur-3xl" />
    </>
  )
}

function ExportHero({
  title,
  description,
  primaryAction,
}: {
  title: string
  description: string
  primaryAction?: ReactNode
}) {
  return (
    <header className="relative overflow-hidden rounded-[34px] border border-[#dceee3] bg-white/92 p-7 shadow-[0_24px_80px_rgba(15,43,29,0.07)] backdrop-blur">
      <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(135deg,rgba(8,122,58,0.05),transparent_42%),radial-gradient(circle_at_86%_24%,rgba(22,163,74,0.12),transparent_28%)]" />
      <div className="pointer-events-none absolute right-[180px] bottom-8 h-20 w-52 rounded-[50%] border border-[#bfe6cc] bg-gradient-to-b from-white to-[#e5f8ec] shadow-[0_24px_60px_rgba(8,122,58,0.12)] export-platform" />
      <div className="pointer-events-none absolute right-24 top-12 h-28 w-28 rounded-full border border-[#c7efd4] bg-white/70 shadow-[0_22px_55px_rgba(8,122,58,0.12)] export-orbit">
        <div className="absolute left-1/2 top-1/2 h-14 w-14 -translate-x-1/2 -translate-y-1/2 rounded-full bg-gradient-to-br from-[#dff7e8] to-[#087a3a] shadow-[0_18px_45px_rgba(8,122,58,0.18)]" />
        <div className="absolute left-1/2 top-1/2 h-5 w-5 -translate-x-1/2 -translate-y-[58px] rounded-full bg-[#087a3a] shadow-[0_12px_28px_rgba(8,122,58,0.20)]" />
      </div>

      <div className="relative grid gap-8 lg:grid-cols-[1fr_0.72fr]">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.22em] text-[#087a3a]">Export Center</p>
          <h1 className="mt-4 max-w-4xl text-4xl font-semibold tracking-[-0.04em] text-[#111827] md:text-5xl">{title}</h1>
          <p className="mt-4 max-w-3xl text-base leading-8 text-[#5f6f66]">{description}</p>
          <div className="mt-7 flex flex-wrap gap-3">
            <ActionLink href="/dashboard">Dashboard</ActionLink>
            <ActionLink href="/reports">All Reports</ActionLink>
            <ActionLink href="/results">All Findings</ActionLink>
            {primaryAction}
          </div>
        </div>

        <div className="rounded-[28px] border border-[#dceee3] bg-white/78 p-5 shadow-[0_20px_60px_rgba(15,43,29,0.07)] backdrop-blur">
          <p className="text-xs font-semibold uppercase tracking-[0.18em] text-[#087a3a]">Export formats</p>
          <div className="mt-5 grid gap-3 sm:grid-cols-2">
            <MiniStat label="PDF" value="Print" />
            <MiniStat label="CSV" value="Rows" />
            <MiniStat label="JSON" value="Snapshot" />
            <MiniStat label="PPT" value="Briefing" />
          </div>
        </div>
      </div>
    </header>
  )
}

function ExportOption({
  title,
  description,
  action,
  primary = false,
}: {
  title: string
  description: string
  action: () => void
  primary?: boolean
}) {
  return (
    <button
      type="button"
      onClick={action}
      className={
        primary
          ? 'rounded-[26px] border border-[#087a3a] bg-[#087a3a] p-5 text-left text-white shadow-[0_18px_40px_rgba(8,122,58,0.18)] transition hover:-translate-y-1 hover:bg-[#066b33]'
          : 'rounded-[26px] border border-[#dceee3] bg-white p-5 text-left shadow-[0_22px_60px_rgba(15,43,29,0.05)] transition hover:-translate-y-1 hover:border-[#b7ddc4] hover:shadow-[0_30px_80px_rgba(15,43,29,0.09)]'
      }
    >
      <p className={primary ? 'text-2xl font-semibold text-white' : 'text-2xl font-semibold text-[#0d2217]'}>{title}</p>
      <p className={primary ? 'mt-2 text-sm leading-6 text-white/85' : 'mt-2 text-sm leading-6 text-[#5a7668]'}>{description}</p>
    </button>
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
  valueClass,
}: {
  label: string
  value: ReactNode
  helper?: string
  valueClass?: string
}) {
  return (
    <div className="rounded-[26px] border border-[#dceee3] bg-white p-5 shadow-[0_22px_60px_rgba(15,43,29,0.05)] transition hover:-translate-y-1 hover:shadow-[0_30px_80px_rgba(15,43,29,0.09)]">
      <p className="text-sm font-medium text-[#5a7668]">{label}</p>
      <div className={`mt-3 text-3xl font-semibold tracking-tight ${valueClass ?? 'text-[#0d2217]'}`}>{value}</div>
      {helper ? <p className="mt-2 text-sm leading-6 text-[#5a7668]">{helper}</p> : null}
    </div>
  )
}

function InfoLine({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="rounded-2xl border border-[#e4f2e9] bg-white p-3">
      <p className="text-xs font-semibold uppercase tracking-wide text-[#5a7668]">{label}</p>
      <div className="mt-1 break-words text-sm font-semibold text-[#173128]">{value}</div>
    </div>
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

function Badge({ className, children }: { className: string; children: ReactNode }) {
  return (
    <span className={`inline-flex rounded-full border px-3 py-1 text-xs font-semibold ${className}`}>
      {children}
    </span>
  )
}
