'use client'

import Link from 'next/link'
import { useSearchParams } from 'next/navigation'
import { Suspense, useEffect, useMemo, useState, type ReactNode } from 'react'

export const dynamic = 'force-dynamic'

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
  severity?: string
  asset?: string
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

type ExportSummaryRecord = {
  id: string
  reportId: string
  summary?: {
    executiveSummary?: string
    technicalSummary?: string
    confidence?: number
    topRisks?: Array<{
      id?: string
      title?: string
      severity?: string
      score?: number
      asset?: string
      reason?: string
    }>
    stats?: Record<string, unknown>
    grounding?: Record<string, unknown>
  }
  summaryMeta?: unknown
  generatedAtIso?: string
  updatedAtIso?: string
}

type ExportRiskRecord = {
  id: string
  reportId: string
  overallRiskScore?: number | null
  overallRiskBand?: string | null
  risk?: {
    overallRiskScore?: number
    overallRiskBand?: string
    rationale?: string[]
    findingRisks?: Array<{
      findingId?: string
      title?: string
      riskScore?: number
      riskBand?: string
      rationale?: string[]
    }>
    stats?: Record<string, unknown>
  }
  riskMeta?: unknown
  generatedAtIso?: string
  updatedAtIso?: string
}

type ExportSnapshot = {
  version?: number
  initializedAtIso?: string
  reports?: ExportReport[]
  findings?: ExportFinding[]
  summaries?: ExportSummaryRecord[]
  riskScores?: ExportRiskRecord[]
}

type AttackPathPrediction = {
  findingId: string
  findingTitle: string
  severity?: string
  riskScore?: number
  attackPathScore?: number
  exploitLikelihood?: string
  confidence?: number
  predictedOutcome?: string
  reasoning?: string[]
  path?: {
    nodes?: Array<{ type?: string; id?: string; name?: string }>
    relationships?: Array<{ type?: string }>
  }
}

type AttackPathsResponse = {
  paths?: AttackPathPrediction[]
  error?: string
  details?: string
}

type Recommendation = {
  findingId: string
  title: string
  priority: 'Immediate' | 'High' | 'Medium' | 'Low'
  category: string
  fix: string
  source: 'Reported remediation' | 'Derived from finding evidence'
  effort: string
  impactReduction: string
  standard: string
}

const APP_TIME_ZONE = 'Africa/Cairo'
const severityOrder = ['Critical', 'High', 'Medium', 'Low']

const severityBadgeClass: Record<string, string> = {
  Critical: 'border-red-200 bg-red-50 text-red-700',
  High: 'border-orange-200 bg-orange-50 text-orange-700',
  Medium: 'border-yellow-200 bg-yellow-50 text-yellow-700',
  Low: 'border-emerald-200 bg-emerald-50 text-emerald-700',
}

const statusClass: Record<string, string> = {
  Ready: 'border-emerald-200 bg-emerald-50 text-emerald-700',
  Reviewed: 'border-[#c4e3cf] bg-[#f6fff9] text-[#087a3a]',
  Pending: 'border-yellow-200 bg-yellow-50 text-yellow-700',
}

function clean(value: unknown, fallback = '-') {
  const text = String(value ?? '').trim()
  if (!text || text === '╬ô├ç├╢' || text === 'Γò¼├┤Γö£├ºΓö£Γòó' || text.toLowerCase() === 'undefined') return fallback
  return text
}

function hasUsefulValue(value: unknown) {
  const normalized = clean(value, '').trim().toLowerCase()
  return Boolean(normalized && normalized !== '-' && normalized !== 'n/a' && normalized !== 'none' && normalized !== 'unknown')
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

function safeFileName(value: string) {
  return clean(value, 'report')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/gi, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
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

function normalizeConfidence(value: unknown) {
  const numeric = Number(value ?? 0)
  if (!Number.isFinite(numeric) || numeric <= 0) return 0
  const percentage = numeric <= 1 ? numeric * 100 : numeric
  return Math.max(0, Math.min(100, Math.round(percentage)))
}

function normalizeSeverity(value: unknown) {
  const severity = clean(value, 'Low')
  return severityOrder.includes(severity) ? severity : 'Low'
}

function severityCounts(findings: ExportFinding[]) {
  const counts: Record<string, number> = { Critical: 0, High: 0, Medium: 0, Low: 0 }
  for (const finding of findings) {
    counts[normalizeSeverity(finding.severity)] += 1
  }
  return counts
}

function fallbackRiskScore(findings: ExportFinding[]) {
  if (findings.length === 0) return 0
  return Math.max(...findings.map((finding) => Number(finding.score ?? 0)))
}

function fallbackRiskBand(score: number) {
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

function averageConfidence(findings: ExportFinding[]) {
  if (findings.length === 0) return 0
  const values = findings.map((finding) => normalizeConfidence(finding.provenance?.parserConfidence))
  return Math.round(values.reduce((sum, value) => sum + value, 0) / values.length)
}

function percent(part: number, total: number) {
  if (total === 0) return 0
  return Math.round((part / total) * 100)
}

function exportReadinessScore(findings: ExportFinding[], riskRecord: ExportRiskRecord | null, summaryRecord: ExportSummaryRecord | null) {
  if (findings.length === 0) return 0

  const withEvidence = findings.filter((finding) => hasUsefulValue(finding.evidence)).length
  const withRemediation = findings.filter((finding) => hasUsefulValue(finding.remediation)).length
  const confidence = averageConfidence(findings)
  const riskBonus = riskRecord ? 10 : 0
  const summaryBonus = summaryRecord ? 10 : 0

  return Math.min(
    100,
    Math.round(
      (withEvidence / findings.length) * 30 +
        (withRemediation / findings.length) * 30 +
        confidence * 0.2 +
        riskBonus +
        summaryBonus
    )
  )
}

function latestSummaryForReport(snapshot: ExportSnapshot | null, reportId: string) {
  return (snapshot?.summaries ?? []).find((item) => item.reportId === reportId) ?? null
}

function latestRiskForReport(snapshot: ExportSnapshot | null, reportId: string) {
  return (snapshot?.riskScores ?? []).find((item) => item.reportId === reportId) ?? null
}

function deriveRecommendation(finding: ExportFinding): Recommendation {
  const severity = normalizeSeverity(finding.severity)
  const score = Number(finding.score ?? 0)
  const title = `${finding.title} ${finding.summary ?? ''} ${finding.impact ?? ''} ${finding.cve ?? ''}`.toLowerCase()
  const hasCve = hasUsefulValue(finding.cve)
  const reportedFix = clean(finding.remediation, '')

  let category = 'Configuration hardening'
  let standard = 'Configuration baseline'
  let fix = reportedFix

  if (title.includes('xss') || title.includes('cross-site')) {
    category = 'Secure coding practice'
    standard = 'OWASP input validation / output encoding'
    fix ||= 'Apply context-aware output encoding, validate user-controlled input, and enforce a restrictive Content Security Policy.'
  } else if (title.includes('sql') || title.includes('injection')) {
    category = 'Secure coding practice'
    standard = 'OWASP injection mitigation'
    fix ||= 'Replace dynamic queries with parameterized queries, validate inputs, and review database permissions.'
  } else if (hasCve || title.includes('cve')) {
    category = 'Patch management'
    standard = 'Vendor advisory / CVE remediation'
    fix ||= 'Prioritize vendor patch validation, schedule emergency remediation for exposed assets, and verify the CVE is no longer exploitable.'
  } else if (title.includes('tls') || title.includes('ssl') || title.includes('config')) {
    category = 'Configuration hardening'
    standard = 'Secure configuration baseline'
    fix ||= 'Harden the affected service configuration, remove weak options, and validate the change with a follow-up security scan.'
  } else {
    fix ||= 'Review the affected asset, validate exploitability, apply the recommended control, and re-test the finding before closure.'
  }

  return {
    findingId: finding.id,
    title: finding.title,
    priority: severity === 'Critical' || score >= 90 ? 'Immediate' : severity === 'High' || score >= 70 ? 'High' : severity === 'Medium' ? 'Medium' : 'Low',
    category,
    fix,
    source: reportedFix ? 'Reported remediation' : 'Derived from finding evidence',
    effort: severity === 'Critical' || severity === 'High' ? 'Medium / urgent' : 'Low to medium',
    impactReduction: severity === 'Critical' || severity === 'High' ? 'High' : 'Moderate',
    standard,
  }
}

function buildRecommendations(findings: ExportFinding[]) {
  return findings
    .slice()
    .sort((a, b) => Number(b.score ?? 0) - Number(a.score ?? 0))
    .map(deriveRecommendation)
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
    ['Report ID', 'Report Name', 'Finding ID', 'Title', 'Severity', 'Score', 'Asset', 'CVE', 'Status', 'Confidence', 'Summary', 'Impact', 'Evidence', 'Remediation'],
    ...findings.map((finding) => [
      report.id,
      report.name,
      finding.id,
      finding.title,
      normalizeSeverity(finding.severity),
      finding.score ?? '',
      finding.asset ?? '',
      finding.cve ?? '',
      finding.status ?? '',
      `${normalizeConfidence(finding.provenance?.parserConfidence)}%`,
      finding.summary ?? '',
      finding.impact ?? '',
      finding.evidence ?? '',
      finding.remediation ?? '',
    ]),
  ]

  return rows.map((row) => row.map(csvEscape).join(',')).join('\r\n')
}

function buildJson(input: {
  report: ExportReport
  findings: ExportFinding[]
  summaryRecord: ExportSummaryRecord | null
  riskRecord: ExportRiskRecord | null
  recommendations: Recommendation[]
  attackPaths: AttackPathPrediction[]
  metrics: Record<string, unknown>
}) {
  return JSON.stringify(
    {
      generatedAtIso: new Date().toISOString(),
      report: input.report,
      metrics: input.metrics,
      summary: input.summaryRecord,
      risk: input.riskRecord,
      recommendations: input.recommendations,
      attackPaths: input.attackPaths,
      findings: input.findings,
    },
    null,
    2
  )
}

function buildHtmlDocument(input: {
  report: ExportReport
  findings: ExportFinding[]
  summaryRecord: ExportSummaryRecord | null
  riskRecord: ExportRiskRecord | null
  recommendations: Recommendation[]
  attackPaths: AttackPathPrediction[]
  metrics: {
    riskScore: number
    riskBand: string
    readiness: number
    avgConfidence: number
    counts: Record<string, number>
  }
}) {
  const { report, findings, summaryRecord, riskRecord, recommendations, attackPaths, metrics } = input
  const topFindings = findings.slice(0, 10)
  const assets = topAssets(findings)
  const executiveSummary = summaryRecord?.summary?.executiveSummary || report.summary || 'No executive summary available.'

  const findingRows = topFindings
    .map(
      (finding) => `
        <tr>
          <td>${escapeHtml(finding.id)}</td>
          <td>${escapeHtml(finding.title)}</td>
          <td>${escapeHtml(normalizeSeverity(finding.severity))}</td>
          <td>${escapeHtml(finding.score ?? '-')}</td>
          <td>${escapeHtml(finding.asset ?? '-')}</td>
          <td>${escapeHtml(finding.cve ?? '-')}</td>
          <td>${normalizeConfidence(finding.provenance?.parserConfidence)}%</td>
        </tr>`
    )
    .join('')

  const recommendationRows = recommendations
    .slice(0, 10)
    .map(
      (item) => `
        <li>
          <strong>${escapeHtml(item.priority)} - ${escapeHtml(item.title)}</strong>
          <span>${escapeHtml(item.category)} / ${escapeHtml(item.standard)}</span>
          <p>${escapeHtml(item.fix)}</p>
        </li>`
    )
    .join('')

  const attackPathRows = attackPaths
    .slice(0, 8)
    .map(
      (path) => `
        <li>
          <strong>${escapeHtml(path.findingTitle)}</strong>
          <span>Likelihood: ${escapeHtml(path.exploitLikelihood ?? 'Unknown')} | Path score: ${escapeHtml(path.attackPathScore ?? '-')} | Confidence: ${escapeHtml(path.confidence ?? '-')}%</span>
          <p>${escapeHtml(path.predictedOutcome ?? 'No predicted outcome returned.')}</p>
        </li>`
    )
    .join('')

  const riskRationaleRows = (riskRecord?.risk?.rationale ?? [])
    .slice(0, 8)
    .map((line) => `<li>${escapeHtml(line)}</li>`)
    .join('')

  const assetRows = assets.map((item) => `<li>${escapeHtml(item.asset)} <strong>${item.count}</strong></li>`).join('')

  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>${escapeHtml(report.id)} - AI CTIX Final Export</title>
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
      <div class="kicker">AI CTIX Final Export Package</div>
      <h1>${escapeHtml(report.name)}</h1>
      <p class="summary">${escapeHtml(executiveSummary)}</p>
    </section>

    <section class="grid">
      <div class="card"><div class="label">Report ID</div><div class="value">${escapeHtml(report.id)}</div></div>
      <div class="card"><div class="label">Risk Band</div><div class="value">${escapeHtml(metrics.riskBand)}</div></div>
      <div class="card"><div class="label">Risk Score</div><div class="value">${metrics.riskScore}/100</div></div>
      <div class="card"><div class="label">Readiness</div><div class="value">${metrics.readiness}%</div></div>
    </section>

    <h2>Report Metadata</h2>
    <table>
      <tr><th>Type</th><td>${escapeHtml(report.type ?? '-')}</td></tr>
      <tr><th>Status</th><td>${escapeHtml(report.status ?? '-')}</td></tr>
      <tr><th>Uploaded At</th><td>${escapeHtml(formatDate(report.uploadedAt))}</td></tr>
      <tr><th>Source File</th><td>${escapeHtml(report.sourceFileName ?? '-')}</td></tr>
    </table>

    <h2>Severity Breakdown</h2>
    <table><tr><th>Critical</th><th>High</th><th>Medium</th><th>Low</th></tr><tr><td>${metrics.counts.Critical}</td><td>${metrics.counts.High}</td><td>${metrics.counts.Medium}</td><td>${metrics.counts.Low}</td></tr></table>

    <h2>Risk Rationale</h2>
    <ul>${riskRationaleRows || '<li>No saved risk rationale available.</li>'}</ul>

    <h2>Top Affected Assets</h2>
    <ul>${assetRows || '<li>No affected assets available.</li>'}</ul>

    <h2>Defense Recommendations</h2>
    <ol>${recommendationRows || '<li>No recommendations available.</li>'}</ol>

    <h2>Attack Path Predictions</h2>
    <ol>${attackPathRows || '<li>No attack paths available in this export.</li>'}</ol>

    <h2>Top Risk Findings</h2>
    <table><thead><tr><th>ID</th><th>Finding</th><th>Severity</th><th>Score</th><th>Asset</th><th>CVE</th><th>Confidence</th></tr></thead><tbody>${findingRows || '<tr><td colspan="7">No findings available.</td></tr>'}</tbody></table>

    <section class="footer">Generated from AI CTIX Extractor - ${escapeHtml(new Date().toISOString())}</section>
  </main>
</body>
</html>`
}

function buildPowerPointHtml(input: {
  report: ExportReport
  findings: ExportFinding[]
  recommendations: Recommendation[]
  attackPaths: AttackPathPrediction[]
  metrics: {
    riskScore: number
    riskBand: string
    readiness: number
    counts: Record<string, number>
  }
}) {
  const { report, findings, recommendations, attackPaths, metrics } = input
  const topFindings = findings.slice(0, 6)

  const findingRows = topFindings
    .map(
      (finding) => `<tr><td>${escapeHtml(finding.title)}</td><td>${escapeHtml(normalizeSeverity(finding.severity))}</td><td>${escapeHtml(finding.score ?? '-')}</td><td>${escapeHtml(finding.asset ?? '-')}</td></tr>`
    )
    .join('')

  const recRows = recommendations
    .slice(0, 5)
    .map((item) => `<li>${escapeHtml(item.priority)}: ${escapeHtml(item.fix)}</li>`)
    .join('')

  const pathRows = attackPaths
    .slice(0, 5)
    .map((item) => `<li>${escapeHtml(item.findingTitle)} - ${escapeHtml(item.exploitLikelihood ?? 'Unknown')}</li>`)
    .join('')

  return `<!doctype html>
<html xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:p="urn:schemas-microsoft-com:office:powerpoint" xmlns="http://www.w3.org/TR/REC-html40">
<head>
  <meta charset="utf-8" />
  <meta name="ProgId" content="PowerPoint.Slide" />
  <title>${escapeHtml(report.name)} - AI CTIX Briefing</title>
  <style>
    body { margin: 0; background: #fbfefd; color: #0d2217; font-family: Arial, Helvetica, sans-serif; }
    .slide { width: 960px; height: 540px; padding: 42px; box-sizing: border-box; page-break-after: always; background: linear-gradient(135deg, #fbfefd 0%, #ffffff 58%, #edfdf3 100%); border-top: 10px solid #087a3a; position: relative; }
    .kicker { color: #087a3a; font-size: 12px; letter-spacing: 0.16em; text-transform: uppercase; font-weight: 700; margin-bottom: 14px; }
    h1 { font-size: 38px; line-height: 1.08; margin: 0 0 18px; max-width: 760px; }
    h2 { font-size: 30px; line-height: 1.1; margin: 0 0 18px; }
    p, li { font-size: 17px; line-height: 1.5; color: #173128; }
    .metrics { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-top: 36px; }
    .metric { background: #ffffff; border: 1px solid #dceee3; border-radius: 18px; padding: 18px; }
    .label { color: #5a7668; font-size: 11px; text-transform: uppercase; letter-spacing: 0.1em; font-weight: 700; }
    .value { margin-top: 8px; font-size: 26px; font-weight: 700; color: #0d2217; }
    table { width: 100%; border-collapse: collapse; margin-top: 24px; font-size: 14px; background: white; }
    th { text-align: left; background: #edfdf3; color: #173128; padding: 12px; border: 1px solid #dceee3; }
    td { padding: 12px; border: 1px solid #dceee3; color: #173128; vertical-align: top; }
    .footer { position: absolute; bottom: 24px; left: 42px; right: 42px; color: #7a8d83; font-size: 11px; border-top: 1px solid #dceee3; padding-top: 10px; }
  </style>
</head>
<body>
  <section class="slide"><div class="kicker">AI CTIX Final Briefing</div><h1>${escapeHtml(report.name)}</h1><p>${escapeHtml(clean(report.summary, 'Generated security intelligence export briefing.'))}</p><div class="metrics"><div class="metric"><div class="label">Risk</div><div class="value">${escapeHtml(metrics.riskBand)}</div></div><div class="metric"><div class="label">Score</div><div class="value">${metrics.riskScore}/100</div></div><div class="metric"><div class="label">Findings</div><div class="value">${findings.length}</div></div><div class="metric"><div class="label">Readiness</div><div class="value">${metrics.readiness}%</div></div></div><div class="footer">AI CTIX Export Briefing</div></section>
  <section class="slide"><div class="kicker">Executive Summary</div><h2>Severity distribution</h2><div class="metrics"><div class="metric"><div class="label">Critical</div><div class="value">${metrics.counts.Critical}</div></div><div class="metric"><div class="label">High</div><div class="value">${metrics.counts.High}</div></div><div class="metric"><div class="label">Medium</div><div class="value">${metrics.counts.Medium}</div></div><div class="metric"><div class="label">Low</div><div class="value">${metrics.counts.Low}</div></div></div><div class="footer">AI CTIX Export Briefing</div></section>
  <section class="slide"><div class="kicker">Priority Findings</div><h2>Top risk findings</h2><table><thead><tr><th>Finding</th><th>Severity</th><th>Score</th><th>Asset</th></tr></thead><tbody>${findingRows || '<tr><td colspan="4">No findings available.</td></tr>'}</tbody></table><div class="footer">AI CTIX Export Briefing</div></section>
  <section class="slide"><div class="kicker">Defense</div><h2>Recommended next actions</h2><ul>${recRows || '<li>No recommendations available.</li>'}</ul><div class="footer">AI CTIX Export Briefing</div></section>
  <section class="slide"><div class="kicker">Attack Paths</div><h2>Predicted attack paths</h2><ul>${pathRows || '<li>No attack path data available.</li>'}</ul><div class="footer">AI CTIX Export Briefing</div></section>
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
  const searchParams = useSearchParams()
  const requestedReportId = searchParams.get('reportId')?.trim() ?? ''

  const [snapshot, setSnapshot] = useState<ExportSnapshot | null>(null)
  const [attackPaths, setAttackPaths] = useState<AttackPathPrediction[]>([])
  const [loading, setLoading] = useState(true)
  const [loadingPaths, setLoadingPaths] = useState(false)
  const [error, setError] = useState('')
  const [pathError, setPathError] = useState('')

  useEffect(() => {
    let cancelled = false

    async function loadExportData() {
      try {
        setLoading(true)
        setError('')
        const exportUrl = requestedReportId
          ? `/api/export?reportId=${encodeURIComponent(requestedReportId)}`
          : '/api/export?mode=list'

        const response = await fetch(exportUrl, { cache: 'no-store' })
        const payload: ExportSnapshot = await response.json().catch(() => ({}))
        if (!response.ok) throw new Error('Failed to load export snapshot.')
        if (!cancelled) setSnapshot(payload)
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : 'Export page failed to load.')
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    void loadExportData()
    return () => {
      cancelled = true
    }
  }, [requestedReportId])

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

  const summaryRecord = useMemo(
    () => (selectedReport ? latestSummaryForReport(snapshot, selectedReport.id) : null),
    [selectedReport, snapshot]
  )

  const riskRecord = useMemo(
    () => (selectedReport ? latestRiskForReport(snapshot, selectedReport.id) : null),
    [selectedReport, snapshot]
  )

  useEffect(() => {
    let cancelled = false

    async function loadAttackPaths(reportId: string) {
      try {
        setLoadingPaths(true)
        setPathError('')
        setAttackPaths([])

        const response = await fetch(`/api/attack-paths/${encodeURIComponent(reportId)}?limit=12`, {
          cache: 'no-store',
        })
        const payload: AttackPathsResponse = await response.json().catch(() => ({}))

        if (!response.ok) {
          throw new Error(payload.details || payload.error || `Attack paths unavailable: ${response.status}`)
        }

        if (!cancelled) setAttackPaths(payload.paths ?? [])
      } catch (err) {
        if (!cancelled) {
          setAttackPaths([])
          setPathError(err instanceof Error ? err.message : 'Attack paths unavailable for this export.')
        }
      } finally {
        if (!cancelled) setLoadingPaths(false)
      }
    }

    if (selectedReport?.id) {
      void loadAttackPaths(selectedReport.id)
    } else {
      setAttackPaths([])
      setPathError('')
    }

    return () => {
      cancelled = true
    }
  }, [selectedReport?.id])

  const counts = useMemo(() => severityCounts(reportFindings), [reportFindings])
  const savedRiskScore = Number(riskRecord?.overallRiskScore ?? riskRecord?.risk?.overallRiskScore ?? Number.NaN)
  const riskScore = Number.isFinite(savedRiskScore) ? savedRiskScore : fallbackRiskScore(reportFindings)
  const riskBand = clean(riskRecord?.overallRiskBand ?? riskRecord?.risk?.overallRiskBand, fallbackRiskBand(riskScore))
  const readiness = exportReadinessScore(reportFindings, riskRecord, summaryRecord)
  const avgConfidence = averageConfidence(reportFindings)
  const recommendations = useMemo(() => buildRecommendations(reportFindings), [reportFindings])
  const assets = useMemo(() => topAssets(reportFindings), [reportFindings])
  const topFindings = reportFindings.slice(0, 8)

  const findingsWithEvidence = reportFindings.filter((finding) => hasUsefulValue(finding.evidence)).length
  const findingsWithRemediation = reportFindings.filter((finding) => hasUsefulValue(finding.remediation)).length
  const highPriorityRecommendations = recommendations.filter((item) => item.priority === 'Immediate' || item.priority === 'High').length

  const metrics = {
    riskScore,
    riskBand,
    readiness,
    avgConfidence,
    counts,
    totalFindings: reportFindings.length,
    recommendations: recommendations.length,
    attackPaths: attackPaths.length,
    highPriorityRecommendations,
  }

  async function downloadServerExport(format: 'pdf' | 'word') {
    if (!selectedReport) return

    const extension = format === 'pdf' ? 'pdf' : 'doc'
    const fallbackName = `${safeFileName(selectedReport.id)}-ai-ctix-final-report.${extension}`

    try {
      const response = await fetch(`/api/export?reportId=${encodeURIComponent(selectedReport.id)}&format=${format}`, { cache: 'no-store' })
      if (!response.ok) {
        const payload = await response.json().catch(() => null)
        throw new Error(payload?.error || `Failed to export ${format.toUpperCase()} file.`)
      }

      const blob = await response.blob()
      const disposition = response.headers.get('content-disposition') ?? ''
      const fileName = disposition.match(/filename=\"?([^\";]+)\"?/i)?.[1] ?? fallbackName
      downloadBlob(blob, fileName)
    } catch (err) {
      window.alert(err instanceof Error ? err.message : `Failed to export ${format.toUpperCase()} file.`)
    }
  }

  function downloadPdfReport() {
    void downloadServerExport('pdf')
  }

  function downloadWordReport() {
    void downloadServerExport('word')
  }

  function printReport() {
    window.print()
  }

  function downloadHtmlReport() {
    if (!selectedReport) return
    const html = buildHtmlDocument({
      report: selectedReport,
      findings: reportFindings,
      summaryRecord,
      riskRecord,
      recommendations,
      attackPaths,
      metrics,
    })
    downloadBlob(new Blob([html], { type: 'text/html;charset=utf-8' }), `${safeFileName(selectedReport.id)}-ai-ctix-final-report.html`)
  }

  function downloadJsonReport() {
    if (!selectedReport) return
    const json = buildJson({
      report: selectedReport,
      findings: reportFindings,
      summaryRecord,
      riskRecord,
      recommendations,
      attackPaths,
      metrics,
    })
    downloadBlob(new Blob([json], { type: 'application/json;charset=utf-8' }), `${safeFileName(selectedReport.id)}-ai-ctix-final-package.json`)
  }

  function downloadCsvReport() {
    if (!selectedReport) return
    const csv = buildCsv(selectedReport, reportFindings)
    downloadBlob(new Blob([csv], { type: 'text/csv;charset=utf-8' }), `${safeFileName(selectedReport.id)}-ai-ctix-findings.csv`)
  }

  function downloadPptReport() {
    downloadWordReport()
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
            title="Export final CTI packages"
            description="Choose a report and generate a final package with findings, saved risk score, summary, derived recommendations, and attack-path predictions."
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
                const findingCount = allFindings.filter((finding) => finding.reportId === report.id).length || Number(report.findings ?? 0)
                const reportRisk = latestRiskForReport(snapshot, report.id)
                const reportSummary = latestSummaryForReport(snapshot, report.id)

                return (
                  <Link
                    key={report.id}
                    href={`/export?reportId=${encodeURIComponent(report.id)}`}
                    className="group rounded-[28px] border border-[#dceee3] bg-white/95 p-5 shadow-[0_22px_60px_rgba(15,43,29,0.05)] transition hover:-translate-y-1 hover:border-[#b7ddc4] hover:shadow-[0_30px_80px_rgba(15,43,29,0.09)]"
                  >
                    <div className="flex items-center justify-between gap-3">
                      <Badge className="border-[#c4e3cf] bg-[#f6fff9] text-[#173128]">{report.id}</Badge>
                      <Badge className={statusClass[report.status ?? ''] ?? 'border-[#dceee3] bg-white text-[#44554b]'}>{report.status ?? 'Unknown'}</Badge>
                    </div>
                    <h2 className="mt-4 text-xl font-semibold text-[#0d2217]">{report.name}</h2>
                    <p className="mt-2 text-sm leading-6 text-[#5a7668]">{report.summary ?? 'No summary available.'}</p>
                    <div className="mt-4 grid grid-cols-3 gap-2 text-center text-xs">
                      <span className="rounded-2xl bg-[#f8fffa] px-2 py-2 font-semibold text-[#087a3a]">{findingCount} findings</span>
                      <span className="rounded-2xl bg-[#f8fffa] px-2 py-2 font-semibold text-[#087a3a]">{reportRisk ? 'Risk saved' : 'Risk pending'}</span>
                      <span className="rounded-2xl bg-[#f8fffa] px-2 py-2 font-semibold text-[#087a3a]">{reportSummary ? 'Summary saved' : 'Summary pending'}</span>
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

  const exportChecks = [
    { label: 'Report selected', value: selectedReport.id, ready: true },
    { label: 'Findings available', value: String(reportFindings.length), ready: reportFindings.length > 0 },
    { label: 'Saved risk score', value: riskRecord ? 'Available' : 'Using findings fallback', ready: Boolean(riskRecord) },
    { label: 'Saved summary', value: summaryRecord ? 'Available' : 'Using report summary', ready: Boolean(summaryRecord) },
    { label: 'Evidence coverage', value: `${findingsWithEvidence}/${reportFindings.length}`, ready: reportFindings.length > 0 && findingsWithEvidence === reportFindings.length },
    { label: 'Remediation coverage', value: `${findingsWithRemediation}/${reportFindings.length}`, ready: reportFindings.length > 0 && findingsWithRemediation === reportFindings.length },
    { label: 'Attack paths', value: loadingPaths ? 'Loading' : pathError ? 'Unavailable' : String(attackPaths.length), ready: attackPaths.length > 0 },
  ]

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
      `}</style>

      <main className="relative min-h-screen overflow-hidden bg-[#fbfefd] text-[#111827]">
        <Background />
        <section className="print-page relative mx-auto max-w-[1480px] px-6 pb-16 pt-10 lg:px-8">
          <div className="no-print">
            <ExportHero
              title="Final CTI export package"
              description="Generate a polished package with report metadata, saved summary, saved risk scoring, findings, recommendations, and attack-path predictions."
              primaryAction={<button onClick={downloadPdfReport} className="rounded-2xl bg-[#087a3a] px-5 py-3 text-sm font-semibold text-white shadow-[0_16px_32px_rgba(8,122,58,0.18)] transition hover:-translate-y-0.5 hover:bg-[#066b33]">PDF</button>}
            />
          </div>

          <section className="no-print mt-6 grid gap-4 md:grid-cols-2 xl:grid-cols-5">
            <ExportOption title="PDF" description="Download a real PDF file generated from the saved report data." action={downloadPdfReport} primary />
            <ExportOption title="CSV" description="Download findings rows for Excel or Sheets." action={downloadCsvReport} />
            <ExportOption title="JSON" description="Download final package with risk, summary, recommendations, attack paths, and findings." action={downloadJsonReport} />
            <ExportOption title="HTML" description="Download a standalone readable final report." action={downloadHtmlReport} />
            <ExportOption title="WORD" description="Download a Word-compatible final report file." action={downloadWordReport} />
          </section>

          <section className="no-print mt-6 grid gap-4 md:grid-cols-2 xl:grid-cols-5">
            <MetricCard label="Risk band" value={riskBand} helper={riskRecord ? 'Saved risk result' : 'Finding fallback'} />
            <MetricCard label="Risk score" value={`${riskScore}/100`} helper="Final export score" valueClass={riskTone(riskScore)} />
            <MetricCard label="Findings" value={String(reportFindings.length)} helper="Included records" />
            <MetricCard label="Recommendations" value={String(recommendations.length)} helper={`${highPriorityRecommendations} high priority`} />
            <MetricCard label="Attack paths" value={loadingPaths ? '…' : String(attackPaths.length)} helper={pathError ? 'Unavailable' : 'Included if available'} />
          </section>

          <section className="no-print mt-6 grid gap-6 xl:grid-cols-[1fr_430px]">
            <div className="rounded-[32px] border border-[#dceee3] bg-white/95 p-6 shadow-[0_22px_60px_rgba(15,43,29,0.06)] backdrop-blur">
              <div className="flex flex-wrap items-start justify-between gap-4">
                <div>
                  <p className="text-sm font-semibold uppercase tracking-[0.18em] text-[#087a3a]">Selected report</p>
                  <h1 className="mt-2 text-3xl font-semibold tracking-[-0.035em] text-[#0d2217]">{selectedReport.name}</h1>
                  <p className="mt-3 max-w-4xl text-sm leading-7 text-[#5a7668]">
                    {summaryRecord?.summary?.executiveSummary ?? selectedReport.summary ?? 'No executive summary available.'}
                  </p>
                </div>
                <Badge className={statusClass[selectedReport.status ?? ''] ?? 'border-[#dceee3] bg-white text-[#44554b]'}>{selectedReport.status ?? 'Unknown'}</Badge>
              </div>

              <div className="mt-5 flex flex-wrap gap-3">
                <ActionLink href="/export">Choose Report</ActionLink>
                <ActionLink href={`/reports/${encodeURIComponent(selectedReport.id)}`}>Report Details</ActionLink>
                <ActionLink href={`/results?reportId=${encodeURIComponent(selectedReport.id)}`}>Findings</ActionLink>
                <ActionLink href={`/risk-scoring?reportId=${encodeURIComponent(selectedReport.id)}`}>Risk</ActionLink>
                <ActionLink href={`/recommendations?reportId=${encodeURIComponent(selectedReport.id)}`}>Recommendations</ActionLink>
                <ActionLink href={`/attack-paths?reportId=${encodeURIComponent(selectedReport.id)}`}>Attack Paths</ActionLink>
                <ActionLink href={`/graph?reportId=${encodeURIComponent(selectedReport.id)}`}>Graph</ActionLink>
              </div>
            </div>

            <SidePanel title="Export readiness">
              <div className="mb-5">
                <Badge className={readiness >= 80 ? 'border-emerald-200 bg-emerald-50 text-emerald-700' : 'border-yellow-200 bg-yellow-50 text-yellow-700'}>
                  {readiness >= 80 ? 'Ready for export' : 'Needs analyst review'}
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
                      <span className={`text-xs font-semibold ${check.ready ? 'text-[#087a3a]' : 'text-yellow-700'}`}>{check.ready ? 'Ready' : 'Review'}</span>
                    </div>
                  </div>
                ))}
              </div>
              {pathError ? <p className="mt-4 rounded-2xl border border-yellow-200 bg-yellow-50 p-3 text-xs leading-5 text-yellow-700">{pathError}</p> : null}
            </SidePanel>
          </section>

          <article className="print-card mt-6 overflow-hidden rounded-[34px] border border-[#dceee3] bg-white shadow-[0_24px_80px_rgba(15,43,29,0.07)]">
            <section className="print-section relative overflow-hidden border-b border-[#dcefe2] bg-[#fbfffd] p-8">
              <div className="relative grid gap-8 xl:grid-cols-[1fr_340px]">
                <div>
                  <p className="text-xs font-bold uppercase tracking-[0.24em] text-[#087a3a]">AI CTIX Final Export Report</p>
                  <h1 className="mt-4 max-w-4xl text-4xl font-semibold tracking-[-0.04em] text-[#0d2217] md:text-5xl">{selectedReport.name}</h1>
                  <p className="mt-4 max-w-5xl text-base leading-8 text-[#5a7668]">
                    {summaryRecord?.summary?.executiveSummary ?? selectedReport.summary ?? 'No executive summary available.'}
                  </p>
                  <div className="mt-6 flex flex-wrap gap-3">
                    <Badge className="border-[#c4e3cf] bg-white text-[#173128]">Report {selectedReport.id}</Badge>
                    <Badge className={statusClass[selectedReport.status ?? ''] ?? 'border-[#dceee3] bg-white text-[#44554b]'}>{selectedReport.status ?? 'Unknown'}</Badge>
                    <Badge className="border-[#c4e3cf] bg-white text-[#087a3a]">Generated {formatDate(new Date().toISOString())}</Badge>
                  </div>
                </div>

                <div className="rounded-[28px] border border-[#dceee3] bg-white/92 p-6 shadow-[0_20px_60px_rgba(15,43,29,0.06)]">
                  <p className="text-xs font-semibold uppercase tracking-[0.18em] text-[#5a7668]">Final scorecard</p>
                  <div className="mt-5 grid gap-4">
                    <div>
                      <p className="text-sm text-[#5a7668]">Risk band</p>
                      <p className={`mt-1 text-4xl font-semibold ${riskTone(riskScore)}`}>{riskBand}</p>
                    </div>
                    <div className="h-2 overflow-hidden rounded-full bg-[#e6f5eb]">
                      <div className="h-full rounded-full bg-[#087a3a]" style={{ width: `${Math.max(6, Math.min(100, riskScore))}%` }} />
                    </div>
                    <div className="grid grid-cols-2 gap-3"><MiniStat label="Score" value={`${riskScore}/100`} /><MiniStat label="Readiness" value={`${readiness}%`} /></div>
                  </div>
                </div>
              </div>
            </section>

            <section className="print-section p-8">
              <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-5">
                <MetricCard label="Risk Band" value={riskBand} helper={riskRecord ? 'Saved risk scoring' : 'Findings fallback'} />
                <MetricCard label="Risk Score" value={`${riskScore}/100`} helper="Final score" valueClass={riskTone(riskScore)} />
                <MetricCard label="Findings" value={String(reportFindings.length)} helper="Included records" />
                <MetricCard label="Recommendations" value={String(recommendations.length)} helper="Defense actions" />
                <MetricCard label="Attack Paths" value={String(attackPaths.length)} helper="Predicted paths" />
              </div>
            </section>

            <section className="print-section px-8 pb-8">
              <div className="grid gap-6 xl:grid-cols-[1fr_430px]">
                <div className="rounded-[28px] border border-[#dceee3] bg-[#fbfffd] p-6">
                  <p className="text-sm font-semibold uppercase tracking-[0.18em] text-[#087a3a]">Executive narrative</p>
                  <h2 className="mt-2 text-2xl font-semibold text-[#0d2217]">Security posture summary</h2>
                  <p className="mt-4 text-base leading-8 text-[#173128]">
                    {summaryRecord?.summary?.executiveSummary ?? `${selectedReport.name} is classified as ${riskBand} with a final risk score of ${riskScore}/100 based on ${reportFindings.length} extracted finding records.`}
                  </p>
                  {summaryRecord?.summary?.technicalSummary ? <p className="mt-4 text-sm leading-7 text-[#5a7668]">{summaryRecord.summary.technicalSummary}</p> : null}
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
                <Panel title="Severity distribution">
                  <div className="grid gap-4">
                    {severityOrder.map((severity) => {
                      const value = counts[severity]
                      const width = percent(value, reportFindings.length)
                      return (
                        <div key={severity}>
                          <div className="mb-2 flex items-center justify-between gap-3 text-sm"><Badge className={severityBadgeClass[severity]}>{severity}</Badge><span className="font-semibold text-[#173128]">{value} findings ({width}%)</span></div>
                          <div className="h-2 overflow-hidden rounded-full bg-[#e6f5eb]"><div className="h-full rounded-full bg-[#087a3a]" style={{ width: `${width}%` }} /></div>
                        </div>
                      )
                    })}
                  </div>
                </Panel>

                <Panel title="Top affected assets">
                  <div className="grid gap-3">
                    {assets.length > 0 ? assets.map((item) => (
                      <div key={item.asset} className="rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] p-4">
                        <div className="flex items-center justify-between gap-4"><span className="break-words text-sm font-semibold text-[#173128]">{item.asset}</span><span className="rounded-full bg-white px-3 py-1 text-xs font-bold text-[#087a3a]">{item.count}</span></div>
                      </div>
                    )) : <p className="rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] p-4 text-sm text-[#5a7668]">No affected assets available.</p>}
                  </div>
                </Panel>
              </div>
            </section>

            <section className="print-section px-8 pb-8">
              <Panel title="Risk rationale">
                <div className="grid gap-3">
                  {(riskRecord?.risk?.rationale ?? []).length > 0 ? riskRecord?.risk?.rationale?.slice(0, 8).map((line, index) => (
                    <p key={`${line}-${index}`} className="rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] p-4 text-sm leading-7 text-[#173128]">{line}</p>
                  )) : <p className="rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] p-4 text-sm text-[#5a7668]">No saved risk rationale available. Generate risk scoring first for a stronger final export.</p>}
                </div>
              </Panel>
            </section>

            <section className="print-section px-8 pb-8">
              <Panel title="Defense recommendations">
                <div className="grid gap-4">
                  {recommendations.slice(0, 10).map((item) => (
                    <article key={item.findingId} className="rounded-[24px] border border-[#dcefe2] bg-[#fbfffc] p-5">
                      <div className="flex flex-wrap items-center justify-between gap-3"><Badge className="border-[#c4e3cf] bg-white text-[#173128]">{item.priority}</Badge><Badge className="border-[#c4e3cf] bg-white text-[#087a3a]">{item.source}</Badge></div>
                      <h3 className="mt-3 text-lg font-semibold text-[#0d2217]">{item.title}</h3>
                      <p className="mt-2 text-sm leading-7 text-[#173128]">{item.fix}</p>
                      <div className="mt-4 grid gap-3 md:grid-cols-3"><InfoLine label="Category" value={item.category} /><InfoLine label="Standard" value={item.standard} /><InfoLine label="Impact reduction" value={item.impactReduction} /></div>
                    </article>
                  ))}
                </div>
              </Panel>
            </section>

            <section className="print-section px-8 pb-8">
              <Panel title="Attack path predictions">
                {loadingPaths ? <p className="rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] p-4 text-sm text-[#5a7668]">Loading attack paths...</p> : null}
                {!loadingPaths && attackPaths.length === 0 ? <p className="rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] p-4 text-sm text-[#5a7668]">No attack path predictions available for this export.</p> : null}
                <div className="grid gap-4">
                  {attackPaths.slice(0, 8).map((path) => (
                    <article key={path.findingId} className="rounded-[24px] border border-[#dcefe2] bg-[#fbfffc] p-5">
                      <div className="flex flex-wrap items-center justify-between gap-3"><Badge className="border-[#c4e3cf] bg-white text-[#173128]">{path.exploitLikelihood ?? 'Unknown'}</Badge><span className="text-sm font-semibold text-[#087a3a]">Path {path.attackPathScore ?? '-'} / Risk {path.riskScore ?? '-'}</span></div>
                      <h3 className="mt-3 text-lg font-semibold text-[#0d2217]">{path.findingTitle}</h3>
                      {path.predictedOutcome ? <p className="mt-2 text-sm leading-7 text-[#173128]">{path.predictedOutcome}</p> : null}
                      {(path.reasoning ?? []).length > 0 ? <ul className="mt-3 list-disc space-y-1 pl-5 text-sm leading-6 text-[#5a7668]">{path.reasoning?.slice(0, 4).map((line, index) => <li key={`${line}-${index}`}>{line}</li>)}</ul> : null}
                    </article>
                  ))}
                </div>
              </Panel>
            </section>

            <section className="print-section px-8 pb-8">
              <Panel title="Top risk findings">
                <div className="mt-1 grid gap-5">
                  {topFindings.length > 0 ? topFindings.map((finding, index) => (
                    <div key={finding.id} className="rounded-[26px] border border-[#dcefe2] bg-[#fbfffc] p-5">
                      <div className="flex flex-wrap items-center justify-between gap-3"><div className="flex flex-wrap items-center gap-2"><Badge className="border-[#c4e3cf] bg-white text-[#173128]">Priority {index + 1}</Badge><Badge className="border-[#c4e3cf] bg-white text-[#173128]">{finding.id}</Badge><Badge className={severityBadgeClass[normalizeSeverity(finding.severity)]}>{normalizeSeverity(finding.severity)}</Badge></div><span className={`text-lg font-semibold ${riskTone(Number(finding.score ?? 0))}`}>{finding.score ?? '-'}/100</span></div>
                      <h3 className="mt-4 text-xl font-semibold text-[#0d2217]">{finding.title}</h3>
                      <p className="mt-2 text-sm leading-7 text-[#5a7668]">{finding.summary ?? finding.impact ?? 'No summary available.'}</p>
                      <div className="mt-4 grid gap-3 md:grid-cols-3"><InfoLine label="Asset" value={finding.asset ?? '-'} /><InfoLine label="CVE" value={finding.cve ?? '-'} /><InfoLine label="Confidence" value={`${normalizeConfidence(finding.provenance?.parserConfidence)}%`} /></div>
                    </div>
                  )) : <p className="rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] p-4 text-sm text-[#5a7668]">No findings available for this report.</p>}
                </div>
              </Panel>
            </section>

            <section className="print-section px-8 pb-8">
              <Panel title="All findings appendix">
                <div className="print-table-wrapper mt-4 overflow-x-auto rounded-[22px] border border-[#dcefe2]">
                  <table className="min-w-full divide-y divide-[#dcefe2] text-left text-sm">
                    <thead className="bg-[#edfdf3] text-xs uppercase tracking-wide text-[#173128]"><tr><th className="px-4 py-3">ID</th><th className="px-4 py-3">Finding</th><th className="px-4 py-3">Severity</th><th className="px-4 py-3">Score</th><th className="px-4 py-3">Asset</th><th className="px-4 py-3">CVE</th><th className="px-4 py-3">Confidence</th></tr></thead>
                    <tbody className="divide-y divide-[#e4f2e9] bg-white">
                      {reportFindings.length > 0 ? reportFindings.map((finding) => (
                        <tr key={finding.id}><td className="whitespace-nowrap px-4 py-3 font-semibold text-[#173128]">{finding.id}</td><td className="min-w-[260px] px-4 py-3 text-[#173128]">{finding.title}</td><td className="whitespace-nowrap px-4 py-3"><Badge className={severityBadgeClass[normalizeSeverity(finding.severity)]}>{normalizeSeverity(finding.severity)}</Badge></td><td className="whitespace-nowrap px-4 py-3 font-semibold text-[#173128]">{finding.score ?? '-'}</td><td className="min-w-[180px] px-4 py-3 text-[#5a7668]">{finding.asset ?? '-'}</td><td className="whitespace-nowrap px-4 py-3 text-[#5a7668]">{finding.cve ?? '-'}</td><td className="whitespace-nowrap px-4 py-3 text-[#5a7668]">{normalizeConfidence(finding.provenance?.parserConfidence)}%</td></tr>
                      )) : <tr><td colSpan={7} className="px-4 py-6 text-center text-[#5a7668]">No findings available.</td></tr>}
                    </tbody>
                  </table>
                </div>
              </Panel>
            </section>

            <section className="px-8 pb-8 text-xs leading-6 text-[#5a7668]"><div className="border-t border-[#dcefe2] pt-5">Generated from AI CTIX Extractor - {new Date().toISOString()}</div></section>
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

function ExportHero({ title, description, primaryAction }: { title: string; description: string; primaryAction?: ReactNode }) {
  return (
    <header className="relative overflow-hidden rounded-[34px] border border-[#dceee3] bg-white/92 p-7 shadow-[0_24px_80px_rgba(15,43,29,0.07)] backdrop-blur">
      <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(135deg,rgba(8,122,58,0.05),transparent_42%),radial-gradient(circle_at_86%_24%,rgba(22,163,74,0.12),transparent_28%)]" />
      <div className="relative grid gap-8 lg:grid-cols-[1fr_0.72fr]"><div><p className="text-xs font-semibold uppercase tracking-[0.22em] text-[#087a3a]">Export Center</p><h1 className="mt-4 max-w-4xl text-4xl font-semibold tracking-[-0.04em] text-[#111827] md:text-5xl">{title}</h1><p className="mt-4 max-w-3xl text-base leading-8 text-[#5f6f66]">{description}</p><div className="mt-7 flex flex-wrap gap-3"><ActionLink href="/dashboard">Dashboard</ActionLink><ActionLink href="/reports">All Reports</ActionLink><ActionLink href="/results">All Findings</ActionLink>{primaryAction}</div></div><div className="rounded-[28px] border border-[#dceee3] bg-white/78 p-5 shadow-[0_20px_60px_rgba(15,43,29,0.07)] backdrop-blur"><p className="text-xs font-semibold uppercase tracking-[0.18em] text-[#087a3a]">Final package</p><div className="mt-5 grid gap-3 sm:grid-cols-2"><MiniStat label="PDF" value="File" /><MiniStat label="CSV" value="Rows" /><MiniStat label="JSON" value="Full" /><MiniStat label="WORD" value="Report" /></div></div></div>
    </header>
  )
}

function ExportOption({ title, description, action, primary = false }: { title: string; description: string; action: () => void; primary?: boolean }) {
  return (
    <button type="button" onClick={action} className={primary ? 'rounded-[26px] border border-[#087a3a] bg-[#087a3a] p-5 text-left text-white shadow-[0_18px_40px_rgba(8,122,58,0.18)] transition hover:-translate-y-1 hover:bg-[#066b33]' : 'rounded-[26px] border border-[#dceee3] bg-white p-5 text-left shadow-[0_22px_60px_rgba(15,43,29,0.05)] transition hover:-translate-y-1 hover:border-[#b7ddc4] hover:shadow-[0_30px_80px_rgba(15,43,29,0.09)]'}>
      <p className={primary ? 'text-2xl font-semibold text-white' : 'text-2xl font-semibold text-[#0d2217]'}>{title}</p>
      <p className={primary ? 'mt-2 text-sm leading-6 text-white/85' : 'mt-2 text-sm leading-6 text-[#5a7668]'}>{description}</p>
    </button>
  )
}

function ActionLink({ href, children, primary = false }: { href: string; children: ReactNode; primary?: boolean }) {
  return <Link href={href} className={primary ? 'inline-flex items-center justify-center rounded-2xl bg-[#087a3a] px-5 py-3 text-sm font-semibold text-white shadow-[0_16px_32px_rgba(8,122,58,0.18)] transition hover:-translate-y-0.5 hover:bg-[#066b33]' : 'inline-flex items-center justify-center rounded-2xl border border-[#c4e3cf] bg-white px-5 py-3 text-sm font-semibold text-[#173128] transition hover:-translate-y-0.5 hover:bg-[#f4fff7]'}>{children}</Link>
}

function MiniStat({ label, value }: { label: string; value: string }) {
  return <div className="rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] p-4"><p className="text-xs font-semibold uppercase tracking-wide text-[#5a7668]">{label}</p><p className="mt-2 text-xl font-semibold text-[#0d2217]">{value}</p></div>
}

function MetricCard({ label, value, helper, valueClass }: { label: string; value: ReactNode; helper?: string; valueClass?: string }) {
  return <div className="rounded-[26px] border border-[#dceee3] bg-white p-5 shadow-[0_22px_60px_rgba(15,43,29,0.05)] transition hover:-translate-y-1 hover:shadow-[0_30px_80px_rgba(15,43,29,0.09)]"><p className="text-sm font-medium text-[#5a7668]">{label}</p><div className={`mt-3 text-3xl font-semibold tracking-tight ${valueClass ?? 'text-[#0d2217]'}`}>{value}</div>{helper ? <p className="mt-2 text-sm leading-6 text-[#5a7668]">{helper}</p> : null}</div>
}

function InfoLine({ label, value }: { label: string; value: ReactNode }) {
  return <div className="rounded-2xl border border-[#e4f2e9] bg-white p-3"><p className="text-xs font-semibold uppercase tracking-wide text-[#5a7668]">{label}</p><div className="mt-1 break-words text-sm font-semibold text-[#173128]">{value}</div></div>
}

function SidePanel({ title, children }: { title: string; children: ReactNode }) {
  return <section className="rounded-[28px] border border-[#dceee3] bg-white/95 p-6 shadow-[0_22px_60px_rgba(15,43,29,0.06)] backdrop-blur"><h2 className="mb-5 text-xl font-semibold text-[#0d2217]">{title}</h2>{children}</section>
}

function Panel({ title, children }: { title: string; children: ReactNode }) {
  return <section className="rounded-[28px] border border-[#dceee3] bg-white p-6"><h2 className="mb-5 text-2xl font-semibold text-[#0d2217]">{title}</h2>{children}</section>
}

function Badge({ className, children }: { className: string; children: ReactNode }) {
  return <span className={`inline-flex rounded-full border px-3 py-1 text-xs font-semibold ${className}`}>{children}</span>
}
