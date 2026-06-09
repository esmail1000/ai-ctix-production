import {
  getAnalysisFindingsByReportIdForUser,
  getAnalysisReportForUser,
  getLatestAnalysisRiskScoreForUser,
  getLatestAnalysisSummaryForUser,
  listAnalysisReportsForUser,
} from '@/lib/server/analysis-repository'
import { getCurrentSessionFromCookies } from '@/lib/server/current-session'
import { NextRequest, NextResponse } from 'next/server'

export const dynamic = 'force-dynamic'
export const runtime = 'nodejs'

type ExportPayload = {
  report: any
  findings: any[]
  summaryRecord: any | null
  riskRecord: any | null
}

const severityOrder = ['Critical', 'High', 'Medium', 'Low']

function errorResponse(message: string, status: number) {
  return NextResponse.json({ error: message }, { status })
}

function clean(value: unknown, fallback = '-') {
  const text = String(value ?? '').trim()
  if (!text || text.toLowerCase() === 'undefined' || text.toLowerCase() === 'null') return fallback
  return text
}

function safeFileName(value: string) {
  return clean(value, 'report')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/gi, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '') || 'report'
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

function normalizeSeverity(value: unknown) {
  const severity = clean(value, 'Low')
  return severityOrder.includes(severity) ? severity : 'Low'
}

function severityCounts(findings: any[]) {
  const counts: Record<string, number> = { Critical: 0, High: 0, Medium: 0, Low: 0 }
  for (const finding of findings) {
    counts[normalizeSeverity(finding?.severity)] += 1
  }
  return counts
}

function normalizeConfidence(value: unknown) {
  const numeric = Number(value ?? 0)
  if (!Number.isFinite(numeric) || numeric <= 0) return 0
  const percentage = numeric <= 1 ? numeric * 100 : numeric
  return Math.max(0, Math.min(100, Math.round(percentage)))
}

function averageConfidence(findings: any[]) {
  if (findings.length === 0) return 0
  const values = findings.map((finding) => normalizeConfidence(finding?.provenance?.parserConfidence))
  return Math.round(values.reduce((sum, value) => sum + value, 0) / values.length)
}

function fallbackRiskScore(findings: any[]) {
  if (findings.length === 0) return 0
  return Math.max(...findings.map((finding) => Number(finding?.finalRiskScore ?? finding?.score ?? 0)))
}

function fallbackRiskBand(score: number) {
  if (score >= 90) return 'Critical'
  if (score >= 70) return 'High'
  if (score >= 40) return 'Medium'
  return 'Low'
}

function getRiskScore(riskRecord: any | null, findings: any[]) {
  const nestedScore = riskRecord?.risk?.overallRiskScore
  const directScore = riskRecord?.overallRiskScore
  const score = typeof nestedScore === 'number' ? nestedScore : typeof directScore === 'number' ? directScore : fallbackRiskScore(findings)
  return Math.max(0, Math.min(100, Math.round(score)))
}

function getRiskBand(riskRecord: any | null, score: number) {
  const nestedBand = riskRecord?.risk?.overallRiskBand
  const directBand = riskRecord?.overallRiskBand
  return clean(typeof nestedBand === 'string' ? nestedBand : typeof directBand === 'string' ? directBand : fallbackRiskBand(score), fallbackRiskBand(score))
}

function getExecutiveSummary(summaryRecord: any | null, report: any) {
  const summary = summaryRecord?.summary
  if (typeof summary?.executiveSummary === 'string' && summary.executiveSummary.trim()) return summary.executiveSummary
  if (typeof summary?.narrativeSummary === 'string' && summary.narrativeSummary.trim()) return summary.narrativeSummary
  if (typeof summary?.technicalSummary === 'string' && summary.technicalSummary.trim()) return summary.technicalSummary
  return clean(report?.summary, 'No executive summary is available for this report.')
}

function buildRecommendations(findings: any[]) {
  return findings
    .slice()
    .sort((a, b) => Number(b?.finalRiskScore ?? b?.score ?? 0) - Number(a?.finalRiskScore ?? a?.score ?? 0))
    .map((finding) => ({
      findingId: clean(finding?.id),
      title: clean(finding?.title, 'Untitled finding'),
      priority: normalizeSeverity(finding?.severity),
      fix: clean(finding?.remediation, 'Review the finding evidence, apply the appropriate control, and retest the affected asset.'),
      source: clean(Array.isArray(finding?.recommendationSources) ? finding.recommendationSources.join(', ') : 'reported-remediation'),
    }))
}

async function getReportExportPayload(userId: string, reportId: string): Promise<ExportPayload | null> {
  const report = await getAnalysisReportForUser(userId, reportId)

  if (!report) return null

  const [findings, summaryRecord, riskRecord] = await Promise.all([
    getAnalysisFindingsByReportIdForUser(userId, reportId),
    getLatestAnalysisSummaryForUser(userId, reportId),
    getLatestAnalysisRiskScoreForUser(userId, reportId),
  ])

  return {
    report,
    findings,
    summaryRecord,
    riskRecord,
  }
}

function toPdfText(value: unknown) {
  return clean(value, '')
    .normalize('NFKD')
    .replace(/[^\x20-\x7E]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
}

function escapePdfString(value: unknown) {
  return toPdfText(value).replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)')
}

function wrapText(value: unknown, maxChars: number) {
  const words = toPdfText(value).split(/\s+/).filter(Boolean)
  const lines: string[] = []
  let current = ''

  for (const word of words) {
    if (!current) {
      current = word
      continue
    }

    if (`${current} ${word}`.length > maxChars) {
      lines.push(current)
      current = word
    } else {
      current += ` ${word}`
    }
  }

  if (current) lines.push(current)
  return lines.length > 0 ? lines : ['-']
}

function truncate(value: unknown, maxLength: number) {
  const text = clean(value, '')
  if (text.length <= maxLength) return text
  return `${text.slice(0, maxLength).trim()}...`
}

type PdfColor = [number, number, number]

function pdfColor(color: PdfColor) {
  return color.map((value) => (Math.max(0, Math.min(255, value)) / 255).toFixed(3)).join(' ')
}

function normalizePdfValue(value: unknown, fallback = '-') {
  return toPdfText(clean(value, fallback)) || fallback
}

function riskBandColor(band: string): PdfColor {
  if (/critical/i.test(band)) return [185, 28, 28]
  if (/high/i.test(band)) return [194, 65, 12]
  if (/medium/i.test(band)) return [161, 98, 7]
  return [21, 128, 61]
}

function severityColor(severity: unknown): PdfColor {
  const normalized = normalizeSeverity(severity)
  if (normalized === 'Critical') return [185, 28, 28]
  if (normalized === 'High') return [194, 65, 12]
  if (normalized === 'Medium') return [161, 98, 7]
  return [21, 128, 61]
}

function splitPdfLines(value: unknown, maxChars: number, maxLines = 999) {
  const words = normalizePdfValue(value).split(/\s+/).filter(Boolean)
  const lines: string[] = []
  let current = ''

  for (const word of words) {
    const candidate = current ? `${current} ${word}` : word
    if (candidate.length > maxChars && current) {
      lines.push(current)
      current = word
      if (lines.length >= maxLines) break
    } else {
      current = candidate
    }
  }

  if (lines.length < maxLines && current) lines.push(current)
  if (words.length > 0 && lines.length >= maxLines) {
    lines[maxLines - 1] = truncate(lines[maxLines - 1], Math.max(8, lines[maxLines - 1].length - 3))
  }
  return lines.length > 0 ? lines : ['-']
}

function buildPdfBytes(payload: ExportPayload) {
  const { report, findings, summaryRecord, riskRecord } = payload
  const counts = severityCounts(findings)
  const riskScore = getRiskScore(riskRecord, findings)
  const riskBand = getRiskBand(riskRecord, riskScore)
  const recommendations = buildRecommendations(findings)
  const executiveSummary = getExecutiveSummary(summaryRecord, report)
  const topFindings = findings
    .slice()
    .sort((a, b) => Number(b?.finalRiskScore ?? b?.score ?? 0) - Number(a?.finalRiskScore ?? a?.score ?? 0))

  const pageWidth = 595.28
  const pageHeight = 841.89
  const marginX = 44
  const contentWidth = pageWidth - marginX * 2
  const topY = 718
  const bottomY = 56
  const pages: string[][] = []
  let y = topY

  const colors = {
    ink: [15, 35, 25] as PdfColor,
    muted: [83, 105, 92] as PdfColor,
    faint: [238, 249, 242] as PdfColor,
    soft: [248, 254, 250] as PdfColor,
    green: [5, 122, 63] as PdfColor,
    darkGreen: [9, 70, 43] as PdfColor,
    border: [196, 226, 208] as PdfColor,
    amber: [161, 98, 7] as PdfColor,
    red: [185, 28, 28] as PdfColor,
    white: [255, 255, 255] as PdfColor,
  }

  function currentPage() {
    if (pages.length === 0) pages.push([])
    return pages[pages.length - 1]
  }

  function cmd(value: string) {
    currentPage().push(value)
  }

  function rect(x: number, bottom: number, width: number, height: number, options: { fill?: PdfColor; stroke?: PdfColor; lineWidth?: number } = {}) {
    const pieces = ['q']
    if (options.fill) pieces.push(`${pdfColor(options.fill)} rg`)
    if (options.stroke) pieces.push(`${pdfColor(options.stroke)} RG ${(options.lineWidth ?? 1).toFixed(2)} w`)
    pieces.push(`${x.toFixed(2)} ${bottom.toFixed(2)} ${width.toFixed(2)} ${height.toFixed(2)} re`)
    if (options.fill && options.stroke) pieces.push('B')
    else if (options.fill) pieces.push('f')
    else pieces.push('S')
    pieces.push('Q')
    cmd(pieces.join(' '))
  }

  function line(x1: number, y1: number, x2: number, y2: number, color: PdfColor = colors.border, lineWidth = 1) {
    cmd(`q ${pdfColor(color)} RG ${lineWidth.toFixed(2)} w ${x1.toFixed(2)} ${y1.toFixed(2)} m ${x2.toFixed(2)} ${y2.toFixed(2)} l S Q`)
  }

  function text(value: unknown, x: number, baseline: number, size = 10, options: { bold?: boolean; color?: PdfColor; align?: 'left' | 'right' | 'center' } = {}) {
    const safe = truncate(normalizePdfValue(value, ''), 420)
    const font = options.bold ? 'F2' : 'F1'
    const color = options.color ?? colors.ink
    const approximateWidth = safe.length * size * 0.52
    let tx = x
    if (options.align === 'right') tx = x - approximateWidth
    if (options.align === 'center') tx = x - approximateWidth / 2
    cmd(`BT /${font} ${size} Tf ${pdfColor(color)} rg ${tx.toFixed(2)} ${baseline.toFixed(2)} Td (${escapePdfString(safe)}) Tj ET`)
  }

  function wrappedText(value: unknown, x: number, baseline: number, width: number, size = 10, lineHeight = 13, options: { bold?: boolean; color?: PdfColor; maxLines?: number } = {}) {
    const maxChars = Math.max(24, Math.floor(width / (size * 0.53)))
    const lines = splitPdfLines(value, maxChars, options.maxLines ?? 999)
    lines.forEach((item, index) => text(item, x, baseline - index * lineHeight, size, { bold: options.bold && index === 0, color: options.color }))
    return lines.length * lineHeight
  }

  function newPage(title = 'AI CTIX Intelligence Report') {
    pages.push([])
    y = topY
    rect(0, pageHeight - 88, pageWidth, 88, { fill: colors.faint })
    rect(0, pageHeight - 90, pageWidth, 2, { fill: colors.green })
    text('AI CTIX', marginX, pageHeight - 42, 13, { bold: true, color: colors.darkGreen })
    text(title, marginX, pageHeight - 62, 9, { color: colors.muted })
    text(normalizePdfValue(report?.id), pageWidth - marginX, pageHeight - 42, 9, { color: colors.muted, align: 'right' })
    line(marginX, pageHeight - 92, pageWidth - marginX, pageHeight - 92, colors.border, 0.7)
  }

  function ensure(space: number, title?: string) {
    if (y - space < bottomY) newPage(title)
  }

  function section(titleValue: string, subtitle?: string) {
    ensure(subtitle ? 62 : 42)
    y -= 8
    rect(marginX, y - 24, 4, 24, { fill: colors.green })
    text(titleValue, marginX + 14, y - 18, 17, { bold: true, color: colors.darkGreen })
    y -= 34
    if (subtitle) {
      y -= wrappedText(subtitle, marginX + 14, y, contentWidth - 14, 9, 12, { color: colors.muted, maxLines: 3 })
      y -= 8
    }
  }

  function metricCard(x: number, top: number, width: number, label: string, value: string, detail: string, accent: PdfColor = colors.green) {
    rect(x, top - 72, width, 72, { fill: colors.white, stroke: colors.border, lineWidth: 0.8 })
    rect(x, top - 72, 4, 72, { fill: accent })
    text(label.toUpperCase(), x + 13, top - 20, 7, { bold: true, color: colors.muted })
    text(value, x + 13, top - 44, 18, { bold: true, color: accent })
    text(detail, x + 13, top - 61, 8, { color: colors.muted })
  }

  function severityBadge(value: unknown, x: number, baseline: number) {
    const severity = normalizeSeverity(value)
    const color = severityColor(severity)
    rect(x, baseline - 7, 58, 15, { fill: [255, 255, 255], stroke: color, lineWidth: 0.8 })
    text(severity, x + 29, baseline - 2, 7.5, { bold: true, color, align: 'center' })
  }

  function keyValue(label: string, value: unknown, x: number, baseline: number, width: number) {
    text(label.toUpperCase(), x, baseline, 7.5, { bold: true, color: colors.muted })
    wrappedText(value, x, baseline - 13, width, 9.5, 12, { color: colors.ink, maxLines: 2 })
  }

  function estimateLines(value: unknown, width: number, size = 9.5, maxLines = 6) {
    const maxChars = Math.max(24, Math.floor(width / (size * 0.53)))
    return splitPdfLines(value, maxChars, maxLines)
  }

  function severityDistributionChart() {
    const total = Math.max(1, findings.length)
    const rows: Array<[string, number, PdfColor]> = [
      ['Critical', counts.Critical, severityColor('Critical')],
      ['High', counts.High, severityColor('High')],
      ['Medium', counts.Medium, severityColor('Medium')],
      ['Low', counts.Low, severityColor('Low')],
    ]
    const boxTop = y
    const boxHeight = 112
    rect(marginX, boxTop - boxHeight, contentWidth, boxHeight, { fill: colors.white, stroke: colors.border, lineWidth: 0.8 })
    text('Severity Distribution', marginX + 16, boxTop - 22, 12, { bold: true, color: colors.darkGreen })
    rows.forEach(([label, value, color], index) => {
      const rowY = boxTop - 44 - index * 17
      text(label, marginX + 18, rowY, 8.5, { color: colors.ink })
      rect(marginX + 84, rowY - 5, 335, 8, { fill: [239, 246, 242] })
      rect(marginX + 84, rowY - 5, 335 * (value / total), 8, { fill: color })
      text(String(value), marginX + 438, rowY, 8.5, { bold: true, color, align: 'right' })
    })
    y -= boxHeight + 16
  }

  function topFindingsTable() {
    ensure(170, 'Priority Findings')
    const tableTop = y
    const rowHeight = 28
    const rows = topFindings.slice(0, 6)
    const tableHeight = 34 + Math.max(1, rows.length) * rowHeight
    rect(marginX, tableTop - tableHeight, contentWidth, tableHeight, { fill: colors.white, stroke: colors.border, lineWidth: 0.8 })
    rect(marginX, tableTop - 28, contentWidth, 28, { fill: colors.faint })
    text('Top Priority Findings', marginX + 14, tableTop - 18, 12, { bold: true, color: colors.darkGreen })
    line(marginX, tableTop - 34, pageWidth - marginX, tableTop - 34, colors.border, 0.7)
    rows.forEach((finding, index) => {
      const rowTop = tableTop - 42 - index * rowHeight
      severityBadge(finding?.severity, marginX + 14, rowTop - 7)
      wrappedText(finding?.title, marginX + 84, rowTop, 270, 8.5, 10, { bold: true, color: colors.ink, maxLines: 2 })
      text(clean(finding?.asset, '-'), marginX + 365, rowTop - 1, 8, { color: colors.muted })
      text(`${clean(finding?.finalRiskScore ?? finding?.score ?? '-')}/100`, pageWidth - marginX - 14, rowTop - 1, 9, { bold: true, color: severityColor(finding?.severity), align: 'right' })
      if (index < rows.length - 1) line(marginX + 12, rowTop - 19, pageWidth - marginX - 12, rowTop - 19, [230, 241, 234], 0.5)
    })
    y -= tableHeight + 18
  }

  function findingCard(finding: any, index: number) {
    const impactLines = estimateLines(finding?.impact, contentWidth - 38, 9, 4)
    const evidenceLines = estimateLines(finding?.evidence, contentWidth - 38, 8.3, 5)
    const remediationLines = estimateLines(finding?.remediation, contentWidth - 38, 9, 4)
    const riskFactors: unknown[] = Array.isArray(finding?.riskFactors) ? finding.riskFactors.slice(0, 4) : []
    const riskFactorLines: string[] = riskFactors.flatMap((factor: unknown) => estimateLines(`- ${factor}`, contentWidth - 52, 8.2, 2))
    const riskFactorHeight = riskFactorLines.length > 0 ? 18 + riskFactorLines.length * 10 : 0
    const cardHeight = 170 + impactLines.length * 11 + evidenceLines.length * 10 + remediationLines.length * 11 + riskFactorHeight

    ensure(cardHeight + 12, 'Detailed Findings')
    const cardTop = y
    rect(marginX, cardTop - cardHeight, contentWidth, cardHeight, { fill: colors.white, stroke: colors.border, lineWidth: 0.8 })
    rect(marginX, cardTop - 30, contentWidth, 30, { fill: colors.faint })
    rect(marginX, cardTop - cardHeight, 4, cardHeight, { fill: severityColor(finding?.severity) })

    text(`Finding ${index + 1}`, marginX + 14, cardTop - 18, 8, { bold: true, color: colors.muted })
    wrappedText(finding?.title, marginX + 80, cardTop - 16, 260, 10.2, 11, { bold: true, color: colors.darkGreen, maxLines: 2 })
    severityBadge(finding?.severity, pageWidth - marginX - 146, cardTop - 18)
    text(`${clean(finding?.finalRiskScore ?? finding?.score ?? '-')}/100`, pageWidth - marginX - 14, cardTop - 20, 10, { bold: true, color: severityColor(finding?.severity), align: 'right' })

    let localY = cardTop - 48
    keyValue('Asset', finding?.asset, marginX + 16, localY, 184)
    keyValue('CVE', finding?.cve, marginX + 220, localY, 95)
    keyValue('Attack Vector', finding?.attackVector ?? '-', marginX + 335, localY, 115)
    localY -= 42

    text('Impact', marginX + 16, localY, 8, { bold: true, color: colors.muted })
    impactLines.forEach((item, lineIndex) => text(item, marginX + 16, localY - 13 - lineIndex * 11, 8.8, { color: colors.ink }))
    localY -= 19 + impactLines.length * 11

    text('Evidence', marginX + 16, localY, 8, { bold: true, color: colors.muted })
    evidenceLines.forEach((item, lineIndex) => text(item, marginX + 16, localY - 12 - lineIndex * 10, 8, { color: colors.muted }))
    localY -= 18 + evidenceLines.length * 10

    text('Remediation', marginX + 16, localY, 8, { bold: true, color: colors.muted })
    remediationLines.forEach((item, lineIndex) => text(item, marginX + 16, localY - 13 - lineIndex * 11, 8.8, { bold: lineIndex === 0, color: colors.darkGreen }))
    localY -= 18 + remediationLines.length * 11

    if (riskFactorLines.length > 0) {
      text('Risk Factors', marginX + 16, localY, 8, { bold: true, color: colors.muted })
      riskFactorLines.forEach((item: string, lineIndex: number) => text(item, marginX + 28, localY - 12 - lineIndex * 10, 7.8, { color: colors.muted }))
    }

    y -= cardHeight + 13
  }

  function recommendationCard(item: ReturnType<typeof buildRecommendations>[number], index: number) {
    const fixLines = estimateLines(item.fix, contentWidth - 42, 9, 5)
    const cardHeight = 58 + fixLines.length * 11
    ensure(cardHeight + 12, 'Recommended Actions')
    const cardTop = y
    rect(marginX, cardTop - cardHeight, contentWidth, cardHeight, { fill: colors.white, stroke: colors.border, lineWidth: 0.8 })
    rect(marginX, cardTop - cardHeight, 4, cardHeight, { fill: severityColor(item.priority) })
    text(`Action ${index + 1}`, marginX + 15, cardTop - 19, 8, { bold: true, color: colors.muted })
    severityBadge(item.priority, pageWidth - marginX - 74, cardTop - 18)
    wrappedText(item.title, marginX + 78, cardTop - 17, 350, 9.2, 10, { bold: true, color: colors.darkGreen, maxLines: 2 })
    text('Fix', marginX + 15, cardTop - 48, 8, { bold: true, color: colors.muted })
    fixLines.forEach((lineValue, lineIndex) => text(lineValue, marginX + 38, cardTop - 48 - lineIndex * 11, 8.7, { color: colors.ink }))
    y -= cardHeight + 12
  }

  // Cover page
  pages.push([])
  rect(0, 0, pageWidth, pageHeight, { fill: [251, 254, 252] })
  rect(0, pageHeight - 164, pageWidth, 164, { fill: colors.faint })
  rect(0, pageHeight - 166, pageWidth, 3, { fill: colors.green })
  text('AI CTIX', marginX, pageHeight - 58, 14, { bold: true, color: colors.darkGreen })
  text('CYBER THREAT INTELLIGENCE EXTRACTOR', marginX, pageHeight - 78, 8, { bold: true, color: colors.green })
  wrappedText('Final Intelligence PDF Report', marginX, pageHeight - 118, contentWidth, 27, 30, { bold: true, color: colors.ink, maxLines: 2 })
  wrappedText(report?.name ?? report?.id, marginX, pageHeight - 176, contentWidth, 15, 18, { color: colors.muted, maxLines: 2 })

  const metaTop = 612
  rect(marginX, metaTop - 72, contentWidth, 72, { fill: colors.white, stroke: colors.border, lineWidth: 0.8 })
  keyValue('Report ID', report?.id, marginX + 16, metaTop - 22, 145)
  keyValue('Source File', report?.sourceFileName ?? report?.name, marginX + 180, metaTop - 22, 180)
  keyValue('Generated', new Date().toISOString(), marginX + 390, metaTop - 22, 110)

  const cardGap = 12
  const cardWidth = (contentWidth - cardGap * 3) / 4
  metricCard(marginX, 500, cardWidth, 'Risk Band', riskBand, 'Overall posture', riskBandColor(riskBand))
  metricCard(marginX + (cardWidth + cardGap), 500, cardWidth, 'Risk Score', `${riskScore}/100`, 'Threat-aware score', riskBandColor(riskBand))
  metricCard(marginX + (cardWidth + cardGap) * 2, 500, cardWidth, 'Findings', String(findings.length), `${counts.Critical + counts.High} urgent`, colors.green)
  metricCard(marginX + (cardWidth + cardGap) * 3, 500, cardWidth, 'Confidence', `${averageConfidence(findings)}%`, 'Parser average', colors.green)

  y = 394
  section('Executive Summary')
  rect(marginX, y - 156, contentWidth, 156, { fill: colors.white, stroke: colors.border, lineWidth: 0.8 })
  wrappedText(executiveSummary, marginX + 16, y - 22, contentWidth - 32, 10.5, 14, { color: colors.ink, maxLines: 9 })
  y -= 176
  severityDistributionChart()

  // Overview page
  newPage('Executive Overview')
  section('Risk Overview', 'A concise view of report risk, severity distribution, confidence, and highest-priority findings.')
  const overviewCardWidth = (contentWidth - 20) / 2
  metricCard(marginX, y, overviewCardWidth, 'Overall Risk', riskBand, `${riskScore}/100`, riskBandColor(riskBand))
  metricCard(marginX + overviewCardWidth + 20, y, overviewCardWidth, 'Finding Coverage', `${findings.length}`, `Critical ${counts.Critical} / High ${counts.High}`, colors.green)
  y -= 92
  severityDistributionChart()
  const rationale = Array.isArray(riskRecord?.risk?.rationale) ? riskRecord.risk.rationale : []
  if (rationale.length > 0) {
    section('Risk Rationale')
    for (const item of rationale.slice(0, 6)) {
      ensure(34, 'Risk Rationale')
      rect(marginX, y - 30, contentWidth, 30, { fill: colors.white, stroke: colors.border, lineWidth: 0.6 })
      wrappedText(item, marginX + 16, y - 12, contentWidth - 32, 8.8, 10, { color: colors.ink, maxLines: 2 })
      y -= 36
    }
  }
  section('Priority Matrix')
  topFindingsTable()

  // Findings pages
  newPage('Detailed Findings')
  section('Detailed Findings', 'Each card is grounded in the extracted report content and keeps evidence, impact, and remediation together for easier review.')
  findings.forEach((finding, index) => findingCard(finding, index))

  // Recommendations pages
  newPage('Recommended Actions')
  section('Recommended Actions', 'Prioritized remediation guidance based on the report findings and deterministic risk model outputs.')
  recommendations.slice(0, 16).forEach((recommendation, index) => recommendationCard(recommendation, index))

  // Footer on every page
  const totalPages = pages.length
  pages.forEach((page, index) => {
    page.push(`q ${pdfColor(colors.border)} RG 0.70 w ${marginX.toFixed(2)} 38.00 m ${(pageWidth - marginX).toFixed(2)} 38.00 l S Q`)
    page.push(`BT /F1 7.5 Tf ${pdfColor(colors.muted)} rg ${marginX.toFixed(2)} 24.00 Td (${escapePdfString('AI CTIX - Final Intelligence Report')}) Tj ET`)
    page.push(`BT /F1 7.5 Tf ${pdfColor(colors.muted)} rg ${(pageWidth - marginX - 70).toFixed(2)} 24.00 Td (${escapePdfString(`Page ${index + 1} of ${totalPages}`)}) Tj ET`)
  })

  const objects: string[] = []
  const pageRefs: number[] = []

  objects.push('<< /Type /Catalog /Pages 2 0 R >>')
  objects.push('')
  objects.push('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>')
  objects.push('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>')

  for (const page of pages) {
    const pageObjectNumber = objects.length + 1
    const contentObjectNumber = objects.length + 2
    pageRefs.push(pageObjectNumber)
    const stream = page.join('\n')
    objects.push(`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${pageWidth} ${pageHeight}] /Resources << /ProcSet [/PDF /Text] /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents ${contentObjectNumber} 0 R >>`)
    objects.push(`<< /Length ${Buffer.byteLength(stream, 'ascii')} >>\nstream\n${stream}\nendstream`)
  }

  objects[1] = `<< /Type /Pages /Kids [${pageRefs.map((ref) => `${ref} 0 R`).join(' ')}] /Count ${pageRefs.length} >>`

  let pdf = '%PDF-1.4\n% AI CTIX Professional PDF Report\n'
  const offsets = [0]

  objects.forEach((object, index) => {
    offsets.push(Buffer.byteLength(pdf, 'ascii'))
    pdf += `${index + 1} 0 obj\n${object}\nendobj\n`
  })

  const xrefOffset = Buffer.byteLength(pdf, 'ascii')
  pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`
  for (let index = 1; index <= objects.length; index += 1) {
    pdf += `${String(offsets[index]).padStart(10, '0')} 00000 n \n`
  }
  pdf += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefOffset}\n%%EOF`

  return Buffer.from(pdf, 'ascii')
}

function buildWordHtml(payload: ExportPayload) {
  const { report, findings, summaryRecord, riskRecord } = payload
  const counts = severityCounts(findings)
  const riskScore = getRiskScore(riskRecord, findings)
  const riskBand = getRiskBand(riskRecord, riskScore)
  const recommendations = buildRecommendations(findings)

  const findingRows = findings
    .map(
      (finding) => `
        <tr>
          <td>${escapeHtml(finding?.id)}</td>
          <td>${escapeHtml(finding?.title)}</td>
          <td>${escapeHtml(normalizeSeverity(finding?.severity))}</td>
          <td>${escapeHtml(finding?.finalRiskScore ?? finding?.score ?? '-')}</td>
          <td>${escapeHtml(finding?.asset ?? '-')}</td>
          <td>${escapeHtml(finding?.cve ?? '-')}</td>
          <td>${escapeHtml(finding?.impact ?? '-')}</td>
          <td>${escapeHtml(finding?.remediation ?? '-')}</td>
        </tr>`
    )
    .join('')

  const recommendationRows = recommendations
    .map(
      (item) => `
        <li><strong>${escapeHtml(item.priority)} - ${escapeHtml(item.title)}</strong><br />${escapeHtml(item.fix)}</li>`
    )
    .join('')

  return `<!doctype html>
<html xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:w="urn:schemas-microsoft-com:office:word" xmlns="http://www.w3.org/TR/REC-html40">
<head>
  <meta charset="utf-8" />
  <title>${escapeHtml(report?.id)} - AI CTIX Word Report</title>
  <style>
    body { font-family: Arial, Helvetica, sans-serif; color: #0d2217; line-height: 1.55; }
    h1 { color: #0d2217; font-size: 28pt; margin-bottom: 8pt; }
    h2 { color: #087a3a; border-bottom: 1px solid #cfe7d8; padding-bottom: 6pt; margin-top: 22pt; }
    .kicker { color: #087a3a; font-size: 9pt; letter-spacing: 1.5pt; text-transform: uppercase; font-weight: bold; }
    .summary { color: #3f5f4e; }
    .metrics { display: table; width: 100%; margin: 14pt 0; }
    .metric { display: table-cell; border: 1px solid #dceee3; background: #f8fffa; padding: 10pt; width: 25%; }
    .label { font-size: 8pt; color: #5a7668; text-transform: uppercase; font-weight: bold; }
    .value { font-size: 16pt; font-weight: bold; margin-top: 4pt; }
    table { border-collapse: collapse; width: 100%; font-size: 8.5pt; }
    th { background: #edfdf3; border: 1px solid #cfe7d8; padding: 6pt; text-align: left; }
    td { border: 1px solid #dceee3; padding: 6pt; vertical-align: top; }
    li { margin-bottom: 8pt; }
  </style>
</head>
<body>
  <p class="kicker">AI CTIX Final Word Report</p>
  <h1>${escapeHtml(report?.name ?? report?.id)}</h1>
  <p class="summary"><strong>Report ID:</strong> ${escapeHtml(report?.id)}<br />
  <strong>Generated:</strong> ${escapeHtml(new Date().toISOString())}<br />
  <strong>Source file:</strong> ${escapeHtml(report?.sourceFileName ?? report?.name ?? '-')}</p>

  <div class="metrics">
    <div class="metric"><div class="label">Risk</div><div class="value">${escapeHtml(riskBand)}</div></div>
    <div class="metric"><div class="label">Score</div><div class="value">${riskScore}/100</div></div>
    <div class="metric"><div class="label">Findings</div><div class="value">${findings.length}</div></div>
    <div class="metric"><div class="label">Confidence</div><div class="value">${averageConfidence(findings)}%</div></div>
  </div>

  <h2>Executive Summary</h2>
  <p>${escapeHtml(getExecutiveSummary(summaryRecord, report))}</p>

  <h2>Severity Distribution</h2>
  <p>Critical: <strong>${counts.Critical}</strong> | High: <strong>${counts.High}</strong> | Medium: <strong>${counts.Medium}</strong> | Low: <strong>${counts.Low}</strong></p>

  <h2>Findings</h2>
  <table>
    <thead><tr><th>ID</th><th>Finding</th><th>Severity</th><th>Score</th><th>Asset</th><th>CVE</th><th>Impact</th><th>Remediation</th></tr></thead>
    <tbody>${findingRows || '<tr><td colspan="8">No findings available.</td></tr>'}</tbody>
  </table>

  <h2>Recommendations</h2>
  <ol>${recommendationRows || '<li>No recommendations available.</li>'}</ol>
</body>
</html>`
}

function attachmentHeaders(contentType: string, fileName: string, byteLength: number) {
  return {
    'Content-Type': contentType,
    'Content-Disposition': `attachment; filename="${fileName}"`,
    'Content-Length': String(byteLength),
    'Cache-Control': 'no-store',
  }
}

export async function GET(request: NextRequest) {
  const session = await getCurrentSessionFromCookies()

  if (!session) {
    return errorResponse('Authentication required.', 401)
  }

  const reportId = request.nextUrl.searchParams.get('reportId')?.trim() ?? ''
  const mode = request.nextUrl.searchParams.get('mode')?.trim() ?? ''
  const format = request.nextUrl.searchParams.get('format')?.trim().toLowerCase() ?? ''

  if (format && !['pdf', 'word'].includes(format)) {
    return errorResponse('Unsupported export format.', 400)
  }

  if (format && !reportId) {
    return errorResponse('A reportId is required for file export.', 400)
  }

  if (reportId) {
    const payload = await getReportExportPayload(session.userId, reportId)

    if (!payload) {
      return errorResponse('Report not found.', 404)
    }

    if (format === 'pdf') {
      const pdf = buildPdfBytes(payload)
      return new NextResponse(pdf, {
        status: 200,
        headers: attachmentHeaders('application/pdf', `${safeFileName(reportId)}-ai-ctix-final-report.pdf`, pdf.length),
      })
    }

    if (format === 'word') {
      const html = buildWordHtml(payload)
      const body = Buffer.from(`\ufeff${html}`, 'utf8')
      return new NextResponse(body, {
        status: 200,
        headers: attachmentHeaders('application/msword; charset=utf-8', `${safeFileName(reportId)}-ai-ctix-final-report.doc`, body.length),
      })
    }

    const { report, findings, summaryRecord, riskRecord } = payload

    return NextResponse.json({
      version: 1,
      mode: 'report',
      initializedAtIso: new Date().toISOString(),
      user: {
        id: session.userId,
        username: session.username,
      },
      reports: [report],
      findings,
      runs: [],
      summaries: summaryRecord
        ? [
            {
              id: summaryRecord.id,
              reportId,
              summary: summaryRecord.summary,
              summaryMeta: summaryRecord.summaryMeta,
              generatedAtIso: summaryRecord.generatedAtIso,
              updatedAtIso: summaryRecord.updatedAtIso,
            },
          ]
        : [],
      riskScores: riskRecord
        ? [
            {
              id: riskRecord.id,
              reportId,
              overallRiskScore:
                typeof riskRecord.risk?.overallRiskScore === 'number'
                  ? riskRecord.risk.overallRiskScore
                  : null,
              overallRiskBand:
                typeof riskRecord.risk?.overallRiskBand === 'string'
                  ? riskRecord.risk.overallRiskBand
                  : null,
              risk: riskRecord.risk,
              riskMeta: riskRecord.riskMeta,
              generatedAtIso: riskRecord.generatedAtIso,
              updatedAtIso: riskRecord.updatedAtIso,
            },
          ]
        : [],
    })
  }

  const reports = await listAnalysisReportsForUser(session.userId)

  return NextResponse.json({
    version: 1,
    mode: mode || 'list',
    initializedAtIso: new Date().toISOString(),
    user: {
      id: session.userId,
      username: session.username,
    },
    reports,
    findings: [],
    runs: [],
    summaries: [],
    riskScores: [],
  })
}
