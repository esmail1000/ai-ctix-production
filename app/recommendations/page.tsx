import Link from 'next/link'
import type { ReactNode } from 'react'
import { redirect } from 'next/navigation'

import {
  getAnalysisFindingsByReportIdForUser,
  listAnalysisFindingsForUser,
  listAnalysisReportsForUser,
} from '@/lib/server/analysis-repository'
import { getCurrentSessionFromCookies } from '@/lib/server/current-session'
import type { StoredFinding } from '@/lib/server/types'

export const dynamic = 'force-dynamic'

type PageProps = {
  searchParams?: Promise<Record<string, string | string[] | undefined>>
}

type RecommendationCategory =
  | 'Patch Management'
  | 'Configuration Hardening'
  | 'Secure Coding'
  | 'Access Control'
  | 'Monitoring & Detection'
  | 'Network Protection'
  | 'Validation & Testing'

type DefenseRecommendation = {
  id: string
  finding: StoredFinding
  priority: 'Critical' | 'High' | 'Medium' | 'Low'
  category: RecommendationCategory
  title: string
  recommendedFix: string
  whyItMatters: string
  implementationSteps: string[]
  owaspMapping: string
  mitreMapping: string
  effort: 'Low' | 'Medium' | 'High'
  impactReduction: 'Low' | 'Medium' | 'High'
  source: 'reported-remediation' | 'backend-risk-engine' | 'derived-from-finding'
  sourceDetail: string
  backendRecommendations: string[]
  recommendationSources: string[]
}

const CATEGORY_ORDER: RecommendationCategory[] = [
  'Patch Management',
  'Configuration Hardening',
  'Secure Coding',
  'Access Control',
  'Network Protection',
  'Monitoring & Detection',
  'Validation & Testing',
]

function getParamValue(
  params: Record<string, string | string[] | undefined>,
  key: string
) {
  const value = params[key]
  return Array.isArray(value) ? value[0] ?? '' : value ?? ''
}

function safeText(value: string | undefined | null, fallback = 'Not reported') {
  const text = String(value ?? '').trim()
  return text.length > 0 ? text : fallback
}

function normalizedText(finding: StoredFinding) {
  return [
    finding.title,
    finding.summary,
    finding.impact,
    finding.evidence,
    finding.remediation,
    finding.cve,
    finding.asset,
  ]
    .join(' ')
    .toLowerCase()
}

type StoredFindingWithRecommendations = StoredFinding & {
  recommendations?: string[]
  recommendationSources?: string[]
}

function backendRecommendations(finding: StoredFinding) {
  return ((finding as StoredFindingWithRecommendations).recommendations ?? [])
    .map((item) => String(item ?? '').trim())
    .filter(Boolean)
}

function backendRecommendationSources(finding: StoredFinding) {
  return ((finding as StoredFindingWithRecommendations).recommendationSources ?? [])
    .map((item) => String(item ?? '').trim())
    .filter(Boolean)
}

function severityPriority(finding: StoredFinding): DefenseRecommendation['priority'] {
  const severity = String(finding.severity ?? '').toLowerCase()
  const score = Number(finding.score ?? 0)

  if (severity.includes('critical') || score >= 90) return 'Critical'
  if (severity.includes('high') || score >= 70) return 'High'
  if (severity.includes('medium') || score >= 40) return 'Medium'
  return 'Low'
}

function inferCategory(finding: StoredFinding): RecommendationCategory {
  const text = normalizedText(finding)

  if (finding.cve || /cve-\d{4}-\d+/i.test(text)) return 'Patch Management'
  if (/sql|xss|injection|csrf|deserial|template|input|sanitize|validation/.test(text)) {
    return 'Secure Coding'
  }
  if (/auth|password|credential|session|token|privilege|access|permission|login/.test(text)) {
    return 'Access Control'
  }
  if (/tls|ssl|cipher|header|cors|config|misconfig|exposed|open port|directory listing/.test(text)) {
    return 'Configuration Hardening'
  }
  if (/firewall|network|port|service|vpn|dns|ip|subnet|segmentation/.test(text)) {
    return 'Network Protection'
  }
  if (/log|monitor|alert|detect|waf|rate limit|brute force|dos|ddos/.test(text)) {
    return 'Monitoring & Detection'
  }

  return 'Validation & Testing'
}

function inferOwaspMapping(finding: StoredFinding) {
  const text = normalizedText(finding)

  if (/broken access|idor|access control|privilege|permission/.test(text)) return 'OWASP A01: Broken Access Control'
  if (/crypto|tls|ssl|secret|password|credential|token/.test(text)) return 'OWASP A02: Cryptographic Failures'
  if (/sql|xss|injection|command injection|template injection|ldap/.test(text)) return 'OWASP A03: Injection'
  if (/design|workflow|business logic/.test(text)) return 'OWASP A04: Insecure Design'
  if (/misconfig|header|cors|directory listing|debug|default/.test(text)) return 'OWASP A05: Security Misconfiguration'
  if (/cve-|outdated|dependency|component|library|version/.test(text)) return 'OWASP A06: Vulnerable and Outdated Components'
  if (/auth|login|session|mfa|brute force/.test(text)) return 'OWASP A07: Identification and Authentication Failures'
  if (/integrity|deserial|supply chain|ci\/cd|pipeline/.test(text)) return 'OWASP A08: Software and Data Integrity Failures'
  if (/log|monitor|alert|detect|incident/.test(text)) return 'OWASP A09: Security Logging and Monitoring Failures'
  if (/ssrf|server-side request/.test(text)) return 'OWASP A10: Server-Side Request Forgery'

  return 'OWASP mapping requires manual validation'
}

function inferMitreMapping(finding: StoredFinding) {
  const text = normalizedText(finding)

  if (/public-facing|web|rce|remote code|exploit/.test(text)) return 'MITRE ATT&CK T1190: Exploit Public-Facing Application'
  if (/credential|password|token|secret/.test(text)) return 'MITRE ATT&CK TA0006: Credential Access'
  if (/privilege|admin|permission|access control/.test(text)) return 'MITRE ATT&CK TA0004: Privilege Escalation'
  if (/lateral|network|vpn|internal/.test(text)) return 'MITRE ATT&CK TA0008: Lateral Movement'
  if (/dos|ddos|denial of service/.test(text)) return 'MITRE ATT&CK T1499: Endpoint Denial of Service'
  if (/exfil|leak|sensitive data/.test(text)) return 'MITRE ATT&CK TA0010: Exfiltration'

  return 'MITRE mapping requires manual validation'
}

function buildFixTitle(category: RecommendationCategory, finding: StoredFinding) {
  if (finding.cve) return `Patch or mitigate ${finding.cve}`

  switch (category) {
    case 'Patch Management':
      return 'Patch vulnerable component'
    case 'Configuration Hardening':
      return 'Harden vulnerable configuration'
    case 'Secure Coding':
      return 'Fix vulnerable application logic'
    case 'Access Control':
      return 'Enforce access-control protections'
    case 'Network Protection':
      return 'Reduce network exposure'
    case 'Monitoring & Detection':
      return 'Add detection and blocking controls'
    case 'Validation & Testing':
      return 'Validate fix and prevent regression'
    default:
      return 'Apply defensive control'
  }
}

function buildDerivedFix(category: RecommendationCategory, finding: StoredFinding) {
  const asset = safeText(finding.asset, 'the affected asset')
  const cve = safeText(finding.cve, '')

  switch (category) {
    case 'Patch Management':
      return cve
        ? `Prioritize vendor patching or compensating controls for ${cve} on ${asset}.`
        : `Update the affected component on ${asset} and verify the vulnerable version is no longer present.`
    case 'Configuration Hardening':
      return `Apply a secure baseline to ${asset}, remove unsafe defaults, restrict exposed settings, and verify the configuration after deployment.`
    case 'Secure Coding':
      return `Fix the vulnerable code path, validate all untrusted input, encode output where needed, and add regression tests for this weakness.`
    case 'Access Control':
      return `Enforce least privilege on ${asset}, validate authorization server-side, and add checks that prevent unauthorized access paths.`
    case 'Network Protection':
      return `Reduce exposure for ${asset} with network segmentation, service restriction, firewall rules, and allow-listing where possible.`
    case 'Monitoring & Detection':
      return `Add detection rules, rate limits, WAF or SIEM alerts, and response playbook entries for this finding pattern.`
    case 'Validation & Testing':
      return `Re-test the affected control, document evidence of remediation, and add this scenario to the recurring validation checklist.`
    default:
      return `Review and remediate ${finding.title}.`
  }
}

function buildSteps(category: RecommendationCategory, finding: StoredFinding) {
  const asset = safeText(finding.asset, 'affected asset')
  const cve = safeText(finding.cve, '')

  if (finding.remediation?.trim()) {
    return [
      'Review the remediation guidance extracted from the source report.',
      `Apply the fix on ${asset}.`,
      'Re-test the finding and attach validation evidence.',
      'Move the finding status to resolved only after verification.',
    ]
  }

  if (category === 'Patch Management') {
    return [
      cve ? `Confirm whether ${cve} applies to the affected component.` : 'Identify the affected component and vulnerable version.',
      'Apply vendor patch or supported upgrade path.',
      'Deploy temporary compensating controls if patching is delayed.',
      'Run validation scan and compare results with the original evidence.',
    ]
  }

  if (category === 'Secure Coding') {
    return [
      'Locate the vulnerable input, processing, or output path.',
      'Add server-side validation and safe handling for untrusted data.',
      'Add unit/security tests that reproduce the finding.',
      'Deploy and verify the finding can no longer be reproduced.',
    ]
  }

  if (category === 'Access Control') {
    return [
      'Map the affected role, endpoint, object, or privilege boundary.',
      'Add explicit authorization checks on the server side.',
      'Test denied and allowed flows for all impacted roles.',
      'Monitor logs for repeated unauthorized attempts after deployment.',
    ]
  }

  if (category === 'Configuration Hardening') {
    return [
      'Compare the current configuration against the secure baseline.',
      'Disable risky defaults and remove unnecessary exposure.',
      'Apply configuration change through controlled deployment.',
      'Verify headers, service settings, permissions, and externally visible behavior.',
    ]
  }

  if (category === 'Network Protection') {
    return [
      'Confirm whether the service needs to be reachable from the current network scope.',
      'Restrict access using firewall rules, segmentation, or allow-lists.',
      'Disable unnecessary services and ports.',
      'Validate external exposure after the change.',
    ]
  }

  return [
    'Create a remediation ticket tied to this finding.',
    'Assign owner and due date according to priority.',
    'Implement the control and document changed evidence.',
    'Re-test before closing the finding.',
  ]
}

function estimateEffort(category: RecommendationCategory, finding: StoredFinding): DefenseRecommendation['effort'] {
  if (finding.remediation?.trim()) return 'Medium'
  if (category === 'Secure Coding' || category === 'Access Control') return 'High'
  if (category === 'Patch Management') return finding.cve ? 'Medium' : 'High'
  if (category === 'Monitoring & Detection') return 'Low'
  return 'Medium'
}

function estimateImpactReduction(priority: DefenseRecommendation['priority']) {
  if (priority === 'Critical' || priority === 'High') return 'High'
  if (priority === 'Medium') return 'Medium'
  return 'Low'
}

function toRecommendation(finding: StoredFinding): DefenseRecommendation {
  const category = inferCategory(finding)
  const priority = severityPriority(finding)
  const reportedRemediation = safeText(finding.remediation, '')
  const recommendations = backendRecommendations(finding)
  const recommendationSources = backendRecommendationSources(finding)
  const firstSource = recommendationSources[0] ?? ''
  const hasBackendRecommendation = recommendations.length > 0
  const hasReportedRemediation = Boolean(reportedRemediation)

  const source: DefenseRecommendation['source'] = hasBackendRecommendation
    ? firstSource === 'reported-remediation'
      ? 'reported-remediation'
      : 'backend-risk-engine'
    : hasReportedRemediation
      ? 'reported-remediation'
      : 'derived-from-finding'

  const recommendedFix = hasBackendRecommendation
    ? recommendations[0]
    : hasReportedRemediation
      ? reportedRemediation
      : buildDerivedFix(category, finding)

  return {
    id: `rec-${finding.id}`,
    finding,
    priority,
    category,
    title: buildFixTitle(category, finding),
    recommendedFix,
    whyItMatters: safeText(
      finding.impact || finding.summary,
      'This recommendation is prioritized from the finding severity, affected asset, evidence, and extracted risk context.'
    ),
    implementationSteps: hasBackendRecommendation
      ? recommendations.slice(0, 5)
      : buildSteps(category, finding),
    owaspMapping: inferOwaspMapping(finding),
    mitreMapping: inferMitreMapping(finding),
    effort: estimateEffort(category, finding),
    impactReduction: estimateImpactReduction(priority),
    source,
    sourceDetail: firstSource || (hasReportedRemediation ? 'reported-remediation' : 'ui-derived-fallback'),
    backendRecommendations: recommendations,
    recommendationSources,
  }
}

function priorityRank(priority: DefenseRecommendation['priority']) {
  if (priority === 'Critical') return 4
  if (priority === 'High') return 3
  if (priority === 'Medium') return 2
  return 1
}

function priorityClass(priority: DefenseRecommendation['priority']) {
  if (priority === 'Critical') return 'border-red-200 bg-red-50 text-red-700'
  if (priority === 'High') return 'border-orange-200 bg-orange-50 text-orange-700'
  if (priority === 'Medium') return 'border-yellow-200 bg-yellow-50 text-yellow-700'
  return 'border-emerald-200 bg-emerald-50 text-emerald-700'
}

function sourceLabel(source: DefenseRecommendation['source']) {
  if (source === 'reported-remediation') return 'From report remediation'
  if (source === 'backend-risk-engine') return 'From backend risk engine'
  return 'Derived fallback'
}

function groupByCategory(recommendations: DefenseRecommendation[]) {
  return CATEGORY_ORDER.map((category) => ({
    category,
    items: recommendations.filter((item) => item.category === category),
  })).filter((group) => group.items.length > 0)
}

export default async function RecommendationsPage({ searchParams }: PageProps) {
  const session = await getCurrentSessionFromCookies()

  if (!session) {
    redirect('/login?next=/recommendations')
  }

  const resolvedParams = searchParams ? await searchParams : {}
  const requestedReportId = getParamValue(resolvedParams, 'reportId').trim()

  const reports = await listAnalysisReportsForUser(session.userId)
  const selectedReport = requestedReportId
    ? reports.find((report) => report.id === requestedReportId) ?? null
    : reports[0] ?? null

  const findings = selectedReport
    ? await getAnalysisFindingsByReportIdForUser(session.userId, selectedReport.id)
    : await listAnalysisFindingsForUser(session.userId)

  const recommendations = findings
    .map(toRecommendation)
    .sort((a, b) => {
      const priorityDelta = priorityRank(b.priority) - priorityRank(a.priority)
      if (priorityDelta !== 0) return priorityDelta
      return Number(b.finding.score ?? 0) - Number(a.finding.score ?? 0)
    })

  const categoryGroups = groupByCategory(recommendations)
  const criticalCount = recommendations.filter((item) => item.priority === 'Critical').length
  const highCount = recommendations.filter((item) => item.priority === 'High').length
  const patchCount = recommendations.filter((item) => item.category === 'Patch Management').length
  const secureCodingCount = recommendations.filter((item) => item.category === 'Secure Coding').length
  const backendCount = recommendations.filter((item) => item.source !== 'derived-from-finding').length
  const derivedCount = recommendations.filter((item) => item.source === 'derived-from-finding').length
  const encodedReportId = selectedReport ? encodeURIComponent(selectedReport.id) : ''

  return (
    <main className="relative min-h-screen overflow-hidden bg-[#fbfefd] text-[#111827]">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_18%_10%,rgba(34,197,94,0.10),transparent_30%),radial-gradient(circle_at_86%_18%,rgba(8,122,58,0.08),transparent_34%)]" />
      <div className="pointer-events-none absolute right-0 top-24 h-[420px] w-[560px] rounded-full bg-[#dcf7e7]/60 blur-3xl" />
      <div className="pointer-events-none absolute left-0 top-[540px] h-[320px] w-[520px] rounded-full bg-[#eefaf3] blur-3xl" />

      <section className="relative mx-auto max-w-[1480px] px-6 pb-16 pt-10 lg:px-8">
        <header className="relative overflow-hidden rounded-[34px] border border-[#dceee3] bg-white/92 p-7 shadow-[0_24px_80px_rgba(15,43,29,0.07)] backdrop-blur">
          <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(135deg,rgba(8,122,58,0.05),transparent_42%),radial-gradient(circle_at_86%_24%,rgba(22,163,74,0.12),transparent_28%)]" />
          <div className="pointer-events-none absolute right-[180px] bottom-8 h-20 w-52 rounded-[50%] border border-[#bfe6cc] bg-gradient-to-b from-white to-[#e5f8ec] shadow-[0_24px_60px_rgba(8,122,58,0.12)]" />
          <div className="pointer-events-none absolute right-20 top-12 h-24 w-24 rounded-full bg-gradient-to-br from-[#dff7e8] to-[#7ddf9b] shadow-[0_22px_55px_rgba(8,122,58,0.14)]" />
          <div className="relative grid gap-8 lg:grid-cols-[1fr_0.82fr]">
            <div className="max-w-4xl">
              <p className="text-xs font-bold uppercase tracking-[0.22em] text-[#087a3a]">
                AI Defense Recommendation Center
              </p>
              <h1 className="mt-3 text-3xl font-semibold tracking-tight text-[#0d2217] sm:text-4xl">
                Evidence-backed remediation and hardening plan
              </h1>
              <p className="mt-3 text-sm leading-7 text-[#5a7668]">
                Backend recommendations and reported remediation are displayed first. Any fallback control is clearly marked
                as derived from finding evidence, CVEs, affected assets, impact, severity, and report-scoped context.
                No placeholder recommendations are shown when findings are unavailable.
              </p>
            </div>

            <div className="w-full rounded-[28px] border border-[#dceee3] bg-white/78 p-5 shadow-[0_20px_60px_rgba(15,43,29,0.07)] backdrop-blur xl:max-w-[520px]">
              <p className="text-xs font-bold uppercase tracking-[0.16em] text-[#5a7668]">
                Report scope
              </p>
              <form className="mt-3 grid gap-3 sm:grid-cols-[1fr_auto]" action="/recommendations">
                <select
                  name="reportId"
                  defaultValue={selectedReport?.id ?? ''}
                  className="h-12 rounded-2xl border border-[#c4e3cf] bg-white px-4 text-sm font-bold text-[#173128] outline-none focus:border-[#087a3a]"
                >
                  {reports.length === 0 ? (
                    <option value="">No reports available</option>
                  ) : (
                    reports.map((report) => (
                      <option key={report.id} value={report.id}>
                        {report.name} - {report.id}
                      </option>
                    ))
                  )}
                </select>
                <button
                  type="submit"
                  className="h-12 rounded-2xl bg-[#087a3a] px-5 text-sm font-semibold text-white shadow-[0_16px_32px_rgba(8,122,58,0.18)] transition hover:-translate-y-0.5 hover:bg-[#066b33]"
                >
                  Load
                </button>
              </form>

              {selectedReport ? (
                <div className="mt-4 flex flex-wrap gap-2">
                  <ActionLink href={`/reports/${encodedReportId}`}>Open Report</ActionLink>
                  <ActionLink href={`/results?reportId=${encodedReportId}`}>Findings</ActionLink>
                  <ActionLink href={`/risk-scoring?reportId=${encodedReportId}`}>Risk Scoring</ActionLink>
                  <ActionLink href={`/graph?reportId=${encodedReportId}`}>Graph</ActionLink>
                  <ActionLink href={`/export?reportId=${encodedReportId}`} primary>
                    Export
                  </ActionLink>
                </div>
              ) : null}
            </div>
          </div>
        </header>

        {selectedReport ? (
          <section className="mt-5 rounded-[28px] border border-[#dceee3] bg-white p-5 shadow-[0_22px_60px_rgba(15,43,29,0.05)]">
            <div className="flex flex-wrap items-center gap-2">
              <Pill>{selectedReport.id}</Pill>
              <Pill>{selectedReport.type ?? 'Report'}</Pill>
              <Pill>{selectedReport.status ?? 'Ready'}</Pill>
              <Pill>{findings.length} findings</Pill>
            </div>
            <h2 className="mt-3 text-2xl font-semibold text-[#0d2217]">{selectedReport.name}</h2>
            {selectedReport.summary ? (
              <p className="mt-2 max-w-6xl text-sm leading-7 text-[#5a7668]">
                {selectedReport.summary}
              </p>
            ) : null}
          </section>
        ) : null}

        <section className="mt-5 grid gap-3 md:grid-cols-2 xl:grid-cols-6">
          <MetricCard label="Recommendations" value={String(recommendations.length)} helper="From stored findings" />
          <MetricCard label="Critical / High" value={`${criticalCount}/${highCount}`} helper="Prioritized first" />
          <MetricCard label="Patch required" value={String(patchCount)} helper="CVE/component driven" />
          <MetricCard label="Backend-backed" value={String(backendCount)} helper="Report/risk-engine sourced" />
          <MetricCard label="Secure coding" value={String(secureCodingCount)} helper="Application fixes" />
          <MetricCard label="Derived fallback" value={String(derivedCount)} helper="Clearly marked UI fallback" />
        </section>

        {recommendations.length === 0 ? (
          <section className="mt-5 rounded-[32px] border border-dashed border-[#b9dcc7] bg-[#f8fffa] p-8 text-center">
            <h2 className="text-2xl font-semibold text-[#0d2217]">No findings available for recommendations</h2>
            <p className="mx-auto mt-3 max-w-2xl text-sm leading-7 text-[#5a7668]">
              Analyze a report first so the system can extract findings, assets, CVEs,
              impact, evidence, and remediation data before generating recommendations.
            </p>
            <div className="mt-5 flex justify-center">
              <ActionLink href="/analyzer" primary>Analyze Report</ActionLink>
            </div>
          </section>
        ) : (
          <section className="mt-5 grid gap-5 xl:grid-cols-[330px_1fr]">
            <aside className="space-y-4 xl:sticky xl:top-24 xl:self-start">
              <Panel title="Recommendation groups">
                <div className="space-y-2">
                  {categoryGroups.map((group) => (
                    <a
                      key={group.category}
                      href={`#${group.category.replace(/[^a-z0-9]+/gi, '-').toLowerCase()}`}
                      className="flex items-center justify-between rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] px-3 py-2 text-xs font-bold text-[#173128] transition hover:border-[#b6e3c6] hover:bg-[#effbf3]"
                    >
                      <span>{group.category}</span>
                      <span className="rounded-full bg-white px-2 py-0.5 text-[#087a3a]">{group.items.length}</span>
                    </a>
                  ))}
                </div>
              </Panel>

              <Panel title="Defense coverage">
                <div className="space-y-3 text-sm leading-6 text-[#5a7668]">
                  <p>
                    Critical and high findings are promoted first, then sorted by extracted risk score.
                  </p>
                  <p>
                    Backend recommendation arrays and reported remediation text are preferred. UI fallback controls are only shown when no backend recommendation is available and are labeled clearly.
                  </p>
                  <p>
                    OWASP and MITRE labels on this page are marked as UI rule-based mappings and should be validated during final review.
                  </p>
                </div>
              </Panel>
            </aside>

            <div className="space-y-5">
              {categoryGroups.map((group) => (
                <section
                  key={group.category}
                  id={group.category.replace(/[^a-z0-9]+/gi, '-').toLowerCase()}
                  className="rounded-[32px] border border-[#dceee3] bg-white p-5 shadow-[0_22px_60px_rgba(15,43,29,0.06)]"
                >
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div>
                      <p className="text-xs font-bold uppercase tracking-[0.18em] text-[#087a3a]">Defense category</p>
                      <h2 className="mt-1 text-2xl font-semibold text-[#0d2217]">{group.category}</h2>
                    </div>
                    <Pill>{group.items.length} recommendations</Pill>
                  </div>

                  <div className="mt-5 grid gap-4">
                    {group.items.map((recommendation) => (
                      <RecommendationCard
                        key={recommendation.id}
                        recommendation={recommendation}
                        reportId={selectedReport?.id ?? recommendation.finding.reportId}
                      />
                    ))}
                  </div>
                </section>
              ))}
            </div>
          </section>
        )}
      </section>
    </main>
  )
}

function RecommendationCard({
  recommendation,
  reportId,
}: {
  recommendation: DefenseRecommendation
  reportId: string
}) {
  const finding = recommendation.finding
  const encodedReportId = encodeURIComponent(reportId)
  const encodedFindingId = encodeURIComponent(finding.id)

  return (
    <article className="rounded-[28px] border border-[#e4f2e9] bg-[#fbfffc] p-5">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div className="min-w-0">
          <div className="flex flex-wrap gap-2">
            <span className={`rounded-full border px-3 py-1 text-xs font-semibold ${priorityClass(recommendation.priority)}`}>
              {recommendation.priority}
            </span>
            <Pill>{recommendation.category}</Pill>
            <Pill>{sourceLabel(recommendation.source)}</Pill>
            <Pill>Source: {recommendation.sourceDetail}</Pill>
            {finding.cve ? <Pill>{finding.cve}</Pill> : null}
          </div>

          <h3 className="mt-3 text-xl font-semibold leading-7 text-[#0d2217]">
            {recommendation.title}
          </h3>
          <p className="mt-1 text-sm font-semibold text-[#173128]">
            {finding.title}
          </p>
          <p className="mt-2 text-sm leading-7 text-[#5a7668]">
            Asset: <strong>{safeText(finding.asset)}</strong> · Severity: <strong>{finding.severity}</strong> · Score: <strong>{finding.score ?? 0}/100</strong>
          </p>
        </div>

        <div className="flex flex-wrap gap-2 lg:justify-end">
          <ActionLink href={`/results/${encodedFindingId}`}>Open Finding</ActionLink>
          <ActionLink href={`/reports/${encodedReportId}`}>Report</ActionLink>
          <ActionLink href={`/graph?reportId=${encodedReportId}`}>Graph</ActionLink>
        </div>
      </div>

      <div className="mt-5 grid gap-4 lg:grid-cols-[1.1fr_0.9fr]">
        <div className="rounded-2xl border border-[#e4f2e9] bg-white p-4">
          <p className="text-xs font-semibold uppercase tracking-[0.16em] text-[#087a3a]">Recommended fix</p>
          <p className="mt-2 text-sm leading-7 text-[#173128]">{recommendation.recommendedFix}</p>
        </div>

        <div className="rounded-2xl border border-[#e4f2e9] bg-white p-4">
          <p className="text-xs font-semibold uppercase tracking-[0.16em] text-[#087a3a]">Why this matters</p>
          <p className="mt-2 text-sm leading-7 text-[#173128]">{recommendation.whyItMatters}</p>
        </div>
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-[1fr_330px]">
        <div className="rounded-2xl border border-[#e4f2e9] bg-white p-4">
          <p className="text-xs font-semibold uppercase tracking-[0.16em] text-[#087a3a]">Implementation steps</p>
          <ol className="mt-3 space-y-2">
            {recommendation.implementationSteps.map((step, index) => (
              <li key={`${recommendation.id}-step-${index}`} className="flex gap-3 text-sm leading-6 text-[#173128]">
                <span className="grid h-6 w-6 shrink-0 place-items-center rounded-full bg-[#e8f8ee] text-xs font-semibold text-[#087a3a]">
                  {index + 1}
                </span>
                <span>{step}</span>
              </li>
            ))}
          </ol>
        </div>

        <div className="grid gap-3">
          <MiniMetric label="Effort" value={recommendation.effort} />
          <MiniMetric label="Impact reduction" value={recommendation.impactReduction} />
          <MiniMetric label="OWASP UI mapping" value={recommendation.owaspMapping} />
          <MiniMetric label="MITRE UI mapping" value={recommendation.mitreMapping} />
        </div>
      </div>

      {recommendation.recommendationSources.length > 0 ? (
        <div className="mt-4 rounded-2xl border border-[#e4f2e9] bg-white p-4">
          <p className="text-xs font-semibold uppercase tracking-[0.16em] text-[#087a3a]">Backend recommendation sources</p>
          <div className="mt-3 flex flex-wrap gap-2">
            {recommendation.recommendationSources.map((source, index) => (
              <Pill key={`${recommendation.id}-source-${index}`}>{source}</Pill>
            ))}
          </div>
        </div>
      ) : null}

      {finding.evidence ? (
        <div className="mt-4 rounded-2xl border border-[#e4f2e9] bg-[#f8fffa] p-4">
          <p className="text-xs font-semibold uppercase tracking-[0.16em] text-[#087a3a]">Evidence</p>
          <p className="mt-2 text-xs leading-6 text-[#5a7668]">{finding.evidence}</p>
        </div>
      ) : null}
    </article>
  )
}

function ActionLink({ href, children, primary }: { href: string; children: ReactNode; primary?: boolean }) {
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

function Pill({ children }: { children: ReactNode }) {
  return (
    <span className="rounded-full border border-[#c4e3cf] bg-[#f6fff9] px-3 py-1 text-xs font-bold text-[#173128]">
      {children}
    </span>
  )
}

function MetricCard({ label, value, helper }: { label: string; value: string; helper: string }) {
  return (
    <div className="rounded-[26px] border border-[#dceee3] bg-white/95 p-5 shadow-[0_22px_60px_rgba(15,43,29,0.05)]">
      <p className="text-xs font-bold uppercase tracking-[0.12em] text-[#5a7668]">{label}</p>
      <p className="mt-2 text-2xl font-semibold text-[#0d2217]">{value}</p>
      <p className="mt-1 text-xs leading-5 text-[#5a7668]">{helper}</p>
    </div>
  )
}

function Panel({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="rounded-[28px] border border-[#dceee3] bg-white/95 p-5 shadow-[0_22px_60px_rgba(15,43,29,0.05)]">
      <h2 className="mb-3 text-base font-semibold text-[#0d2217]">{title}</h2>
      {children}
    </section>
  )
}

function MiniMetric({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-2xl border border-[#e4f2e9] bg-white p-3">
      <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-[#5a7668]">{label}</p>
      <p className="mt-1 break-words text-xs font-bold leading-5 text-[#173128]">{value}</p>
    </div>
  )
}
