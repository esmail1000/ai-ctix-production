'use client'

import { useEffect, useMemo, useState } from 'react'

type BlockedIp = {
  ip: string
  blockedAt: number | null
  expiry: number | null
  reason: string
  secondsLeft: number | null
  expired: boolean
}

type WafIncident = {
  id: string
  timestamp?: string
  source_ip?: string
  attack_type?: string
  target_path?: string
  evidence?: string
  action_taken?: string
  success?: string
  tenant_id?: string
  tenant_name?: string
  tenant_email?: string
  mitigation_recommendations?: string[]
  severity: 'High' | 'Medium' | 'Low'
  owasp: string
  mitre: string
  evidenceHash: string
  hasPdf: boolean
}

type WafSummary = {
  status: string
  generatedAt: string
  paths: {
    blockedIpsFile: string
    reportsDir: string
    pdfReportsDir: string
  }
  metrics: {
    totalIncidents: number
    incidentsLast24h: number
    blockedIps: number
    highSeverity: number
    lastAttackTime: string | null
  }
  blockedIps: BlockedIp[]
  incidents: WafIncident[]
}

type DemoCase = {
  id: string
  label: string
  description: string
  method: 'GET' | 'POST'
  path: string
  body?: Record<string, unknown>
  malicious: boolean
}

const demoCases: DemoCase[] = [
  {
    id: 'xss',
    label: 'Test XSS',
    description: 'Injects a script tag in a query parameter.',
    method: 'GET',
    path: '/login?next=%3Cscript%3Ealert(1)%3C%2Fscript%3E',
    malicious: true,
  },
  {
    id: 'sqli',
    label: 'Test SQLi',
    description: 'Submits a classic SQL injection login payload.',
    method: 'POST',
    path: '/api/auth/login',
    body: { email: "' OR '1'='1' --", password: 'demo' },
    malicious: true,
  },
  {
    id: 'traversal',
    label: 'Test Path Traversal',
    description: 'Attempts to access a protected filesystem path.',
    method: 'GET',
    path: '/download?file=..%2F..%2F..%2Fetc%2Fpasswd',
    malicious: true,
  },
  {
    id: 'rce',
    label: 'Test RCE',
    description: 'Sends a command-execution style parameter.',
    method: 'GET',
    path: '/?cmd=cat%20%2Fetc%2Fpasswd%3Bid',
    malicious: true,
  },
  {
    id: 'normal',
    label: 'Normal Request',
    description: 'Verifies that clean traffic still passes normally.',
    method: 'GET',
    path: '/api/auth/me',
    malicious: false,
  },
]

function formatUnix(seconds: number | null) {
  if (!seconds) return '—'
  return new Date(seconds * 1000).toLocaleString()
}

function formatSeconds(seconds: number | null) {
  if (seconds === null) return '—'
  if (seconds <= 0) return 'expired'
  const m = Math.floor(seconds / 60)
  const s = seconds % 60
  return `${m}m ${s.toString().padStart(2, '0')}s`
}

function severityClasses(severity: string) {
  if (severity === 'High') return 'border-red-200 bg-red-50 text-red-700'
  if (severity === 'Medium') return 'border-amber-200 bg-amber-50 text-amber-700'
  return 'border-emerald-200 bg-emerald-50 text-emerald-700'
}

function MetricCard({ label, value, hint, tone = 'default' }: { label: string; value: string | number; hint?: string; tone?: 'default' | 'danger' | 'success' }) {
  const toneClass = tone === 'danger' ? 'border-red-100 bg-red-50/40' : tone === 'success' ? 'border-emerald-200 bg-emerald-50/40' : 'border-emerald-100 bg-white'
  return (
    <div className={`rounded-3xl border ${toneClass} p-6 shadow-sm`}>
      <p className="text-sm font-medium text-[#5a7668]">{label}</p>
      <p className="mt-3 text-3xl font-semibold tracking-tight text-[#0f2b1d]">{value}</p>
      {hint ? <p className="mt-2 text-xs leading-5 text-[#6b8277]">{hint}</p> : null}
    </div>
  )
}

function EmptyRow({ colSpan, children }: { colSpan: number; children: string }) {
  return (
    <tr>
      <td colSpan={colSpan} className="py-10 text-center text-[#6b8277]">
        {children}
      </td>
    </tr>
  )
}

export default function WafCenterPage() {
  const [token, setToken] = useState('')
  const [summary, setSummary] = useState<WafSummary | null>(null)
  const [selectedIncident, setSelectedIncident] = useState<WafIncident | null>(null)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [loading, setLoading] = useState(false)
  const [demoLoading, setDemoLoading] = useState<string | null>(null)
  const [savedToken, setSavedToken] = useState(false)

  useEffect(() => {
    const stored = window.localStorage.getItem('waf_admin_token') || ''
    if (stored) {
      setToken(stored)
      setSavedToken(true)
      loadSummary(stored)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const headers = useMemo(() => ({ 'x-waf-admin-token': token }), [token])

  async function loadSummary(nextToken = token) {
    if (!nextToken) {
      setError('Enter the WAF admin token first.')
      return
    }

    setLoading(true)
    setError('')
    setNotice('')

    try {
      const res = await fetch('/api/admin/waf/summary', {
        cache: 'no-store',
        headers: { 'x-waf-admin-token': nextToken },
      })
      const data = await res.json()

      if (!res.ok) throw new Error(data.error || 'Failed to load WAF summary.')

      setSummary(data)
      window.localStorage.setItem('waf_admin_token', nextToken)
      setSavedToken(true)
    } catch (err: any) {
      setError(err.message || 'Failed to load WAF summary.')
    } finally {
      setLoading(false)
    }
  }

  async function unblockIp(ip: string) {
    if (!confirm(`Unblock ${ip}?`)) return

    setLoading(true)
    setError('')
    setNotice('')

    try {
      const res = await fetch('/api/admin/waf/unblock', {
        method: 'POST',
        headers: { ...headers, 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip }),
      })
      const data = await res.json().catch(() => ({}))
      if (!res.ok) throw new Error(data.error || 'Failed to unblock IP.')
      setNotice(`Released ${ip} from quarantine.`)
      await loadSummary()
    } catch (err: any) {
      setError(err.message || 'Failed to unblock IP.')
    } finally {
      setLoading(false)
    }
  }

  async function unblockAll() {
    if (!confirm('Unblock all currently quarantined IPs?')) return

    setLoading(true)
    setError('')
    setNotice('')

    try {
      const res = await fetch('/api/admin/waf/unblock', {
        method: 'POST',
        headers: { ...headers, 'Content-Type': 'application/json' },
        body: JSON.stringify({ all: true }),
      })
      const data = await res.json().catch(() => ({}))
      if (!res.ok) throw new Error(data.error || 'Failed to unblock all IPs.')
      setNotice('All quarantined IPs were released.')
      await loadSummary()
    } catch (err: any) {
      setError(err.message || 'Failed to unblock all IPs.')
    } finally {
      setLoading(false)
    }
  }

  async function openPdf(incidentId: string, tenantId = 'default_tenant') {
    setError('')
    setNotice('')

    try {
      const res = await fetch('/api/admin/waf/pdf', {
        method: 'POST',
        headers: { ...headers, 'Content-Type': 'application/json' },
        body: JSON.stringify({ incidentId, tenantId }),
      })

      if (!res.ok) {
        const data = await res.json().catch(() => ({}))
        throw new Error(data.error || 'PDF report not found.')
      }

      const blob = await res.blob()
      const url = window.URL.createObjectURL(blob)
      window.open(url, '_blank', 'noopener,noreferrer')
      setTimeout(() => window.URL.revokeObjectURL(url), 60_000)
    } catch (err: any) {
      setError(err.message || 'Failed to open PDF.')
    }
  }

  async function runDemo(testCase: DemoCase) {
    if (!summary && !token) {
      setError('Enter the WAF admin token first so you can refresh data and unblock yourself after testing.')
      return
    }

    const dangerous = testCase.malicious
      ? 'This will intentionally trigger the WAF and may quarantine your IP. Admin APIs are bypassed so you can release it from this page after the test.'
      : 'This sends a clean request and should not generate a WAF incident.'

    if (!confirm(`${testCase.label}\n\n${dangerous}\n\nContinue?`)) return

    setDemoLoading(testCase.id)
    setError('')
    setNotice('')

    try {
      const url = `${testCase.path}${testCase.path.includes('?') ? '&' : '?'}wafDemo=${Date.now()}`
      const res = await fetch(url, {
        method: testCase.method,
        cache: 'no-store',
        headers: testCase.body ? { 'Content-Type': 'application/json' } : undefined,
        body: testCase.body ? JSON.stringify(testCase.body) : undefined,
      })

      if (testCase.malicious) {
        setNotice(`${testCase.label} sent. Response status: ${res.status}. Refreshing WAF data now. If your normal pages are blocked, use Unblock All from this panel.`)
      } else {
        setNotice(`Normal request completed with status ${res.status}. No block should be created.`)
      }

      await loadSummary()
    } catch (err: any) {
      setNotice(`${testCase.label} request was interrupted. This can happen when the WAF redirects to /blocked. Refreshing WAF data now.`)
      await loadSummary().catch(() => undefined)
    } finally {
      setDemoLoading(null)
    }
  }

  return (
    <main className="min-h-screen bg-[#f7fbf8] px-6 py-8 text-[#0d2217] lg:px-10">
      <section className="mx-auto max-w-7xl space-y-8">
        <div className="overflow-hidden rounded-[2rem] border border-emerald-100 bg-white shadow-sm">
          <div className="grid gap-0 lg:grid-cols-[1fr_410px]">
            <div className="p-7 lg:p-8">
              <p className="text-sm font-semibold uppercase tracking-[0.2em] text-emerald-700">Admin Security Center</p>
              <h1 className="mt-2 text-3xl font-semibold tracking-tight text-[#0f2b1d] lg:text-5xl">AI-CTIX WAF Center</h1>
              <p className="mt-3 max-w-3xl text-sm leading-6 text-[#5a7668]">
                Monitor live WAF incidents, review blocked IPs, inspect evidence, open PDF reports, run safe demo tests, and release quarantined users without entering the Render shell.
              </p>
              <div className="mt-5 flex flex-wrap gap-2 text-xs font-semibold">
                <span className="rounded-full border border-emerald-200 bg-emerald-50 px-3 py-1 text-emerald-800">Gateway active</span>
                <span className="rounded-full border border-slate-200 bg-slate-50 px-3 py-1 text-slate-700">Owner-only UX</span>
                <span className="rounded-full border border-red-200 bg-red-50 px-3 py-1 text-red-700">Quarantine control</span>
              </div>
            </div>

            <div className="border-t border-emerald-100 bg-[#f7fbf8] p-5 lg:border-l lg:border-t-0">
              <label className="text-xs font-semibold uppercase tracking-[0.16em] text-[#5a7668]">WAF Admin Token</label>
              <input
                value={token}
                onChange={(event) => setToken(event.target.value)}
                type="password"
                placeholder="Paste WAF_ADMIN_TOKEN"
                className="mt-3 w-full rounded-xl border border-[#cbe8d6] bg-white px-4 py-3 text-sm outline-none focus:border-emerald-500 focus:ring-2 focus:ring-emerald-100"
              />
              <div className="mt-3 flex flex-wrap gap-2">
                <button
                  onClick={() => loadSummary()}
                  disabled={loading}
                  className="rounded-xl bg-[#15803d] px-4 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-[#166534] disabled:opacity-60"
                >
                  {loading ? 'Loading...' : savedToken ? 'Refresh WAF Data' : 'Unlock Dashboard'}
                </button>
                <button
                  onClick={() => {
                    window.localStorage.removeItem('waf_admin_token')
                    setToken('')
                    setSummary(null)
                    setSavedToken(false)
                    setNotice('')
                    setError('')
                  }}
                  className="rounded-xl border border-[#cbe8d6] bg-white px-4 py-2 text-sm font-semibold text-[#173128] hover:bg-[#edfdf3]"
                >
                  Clear
                </button>
              </div>
              <p className="mt-3 text-xs leading-5 text-[#6b8277]">Tip: keep this page open during demos. Admin WAF APIs are bypassed by the WAF so you can release your own IP after a block test.</p>
            </div>
          </div>
        </div>

        {error ? <div className="rounded-2xl border border-red-200 bg-red-50 px-5 py-4 text-sm font-medium text-red-700">{error}</div> : null}
        {notice ? <div className="rounded-2xl border border-emerald-200 bg-emerald-50 px-5 py-4 text-sm font-medium text-emerald-800">{notice}</div> : null}

        {summary ? (
          <>
            <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
              <MetricCard label="WAF Status" value={summary.status === 'active' ? 'Active' : summary.status} hint={`Updated ${new Date(summary.generatedAt).toLocaleString()}`} tone="success" />
              <MetricCard label="Total Incidents" value={summary.metrics.totalIncidents} hint={`${summary.metrics.incidentsLast24h} in last 24h`} />
              <MetricCard label="Blocked IPs" value={summary.metrics.blockedIps} hint="Currently in quarantine file" tone={summary.metrics.blockedIps ? 'danger' : 'default'} />
              <MetricCard label="High Severity" value={summary.metrics.highSeverity} hint={summary.metrics.lastAttackTime ? `Last: ${summary.metrics.lastAttackTime}` : 'No attacks yet'} tone={summary.metrics.highSeverity ? 'danger' : 'default'} />
            </div>

            <section className="rounded-[2rem] border border-emerald-100 bg-white p-6 shadow-sm">
              <div className="mb-5 flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                <div>
                  <p className="text-xs font-semibold uppercase tracking-[0.16em] text-emerald-700">Demo lab</p>
                  <h2 className="mt-1 text-xl font-semibold text-[#0f2b1d]">Attack Simulator</h2>
                  <p className="mt-1 max-w-3xl text-sm leading-6 text-[#5a7668]">
                    Trigger one controlled request at a time to prove that the WAF blocks malicious traffic, creates JSON evidence, generates a PDF incident, and quarantines the source IP.
                  </p>
                </div>
                <button onClick={unblockAll} className="rounded-xl border border-red-200 bg-red-50 px-4 py-2 text-sm font-semibold text-red-600 hover:bg-red-100">
                  Emergency Unblock All
                </button>
              </div>

              <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-5">
                {demoCases.map((testCase) => (
                  <button
                    key={testCase.id}
                    onClick={() => runDemo(testCase)}
                    disabled={Boolean(demoLoading)}
                    className={`rounded-2xl border p-4 text-left transition hover:-translate-y-0.5 hover:shadow-sm disabled:cursor-wait disabled:opacity-70 ${testCase.malicious ? 'border-red-100 bg-red-50/40 hover:bg-red-50' : 'border-emerald-100 bg-emerald-50/50 hover:bg-emerald-50'}`}
                  >
                    <span className={`inline-flex rounded-full px-2.5 py-1 text-xs font-semibold ${testCase.malicious ? 'bg-red-100 text-red-700' : 'bg-emerald-100 text-emerald-800'}`}>
                      {testCase.method}
                    </span>
                    <p className="mt-3 font-semibold text-[#0f2b1d]">{demoLoading === testCase.id ? 'Running...' : testCase.label}</p>
                    <p className="mt-2 text-xs leading-5 text-[#5a7668]">{testCase.description}</p>
                  </button>
                ))}
              </div>
            </section>

            <section className="rounded-[2rem] border border-emerald-100 bg-white p-6 shadow-sm">
              <div className="mb-5 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <h2 className="text-xl font-semibold text-[#0f2b1d]">Blocked IP Manager</h2>
                  <p className="mt-1 text-sm text-[#5a7668]">Release false positives, expired blocks, or your own test quarantine from the UI.</p>
                </div>
                <button onClick={unblockAll} className="rounded-xl border border-red-200 bg-red-50 px-4 py-2 text-sm font-semibold text-red-600 hover:bg-red-100">
                  Unblock All
                </button>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full min-w-[860px] text-left text-sm">
                  <thead className="border-b border-emerald-100 text-xs uppercase tracking-[0.12em] text-[#6b8277]">
                    <tr>
                      <th className="py-3 pr-4">IP</th>
                      <th className="py-3 pr-4">Reason</th>
                      <th className="py-3 pr-4">Blocked At</th>
                      <th className="py-3 pr-4">Expires</th>
                      <th className="py-3 pr-4">Status</th>
                      <th className="py-3 pr-4">Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {summary.blockedIps.length ? (
                      summary.blockedIps.map((record) => (
                        <tr key={record.ip} className="border-b border-emerald-50 align-top">
                          <td className="py-4 pr-4 font-mono text-[#0f2b1d]">{record.ip}</td>
                          <td className="py-4 pr-4 text-[#48665a]">{record.reason}</td>
                          <td className="py-4 pr-4 text-[#48665a]">{formatUnix(record.blockedAt)}</td>
                          <td className="py-4 pr-4 text-[#48665a]">{formatSeconds(record.secondsLeft)}</td>
                          <td className="py-4 pr-4">
                            <span className={`rounded-full border px-3 py-1 text-xs font-semibold ${record.expired ? 'border-amber-200 bg-amber-50 text-amber-700' : 'border-red-200 bg-red-50 text-red-700'}`}>
                              {record.expired ? 'Expired' : 'Quarantined'}
                            </span>
                          </td>
                          <td className="py-4 pr-4">
                            <button onClick={() => unblockIp(record.ip)} className="rounded-lg bg-[#15803d] px-3 py-2 text-xs font-semibold text-white hover:bg-[#166534]">
                              Unblock
                            </button>
                          </td>
                        </tr>
                      ))
                    ) : (
                      <EmptyRow colSpan={6}>No blocked IPs right now.</EmptyRow>
                    )}
                  </tbody>
                </table>
              </div>
            </section>

            <section className="rounded-[2rem] border border-emerald-100 bg-white p-6 shadow-sm">
              <div className="mb-5 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <h2 className="text-xl font-semibold text-[#0f2b1d]">Recent WAF Incidents</h2>
                  <p className="mt-1 text-sm text-[#5a7668]">Latest JSON incidents generated by the WAF engine. Open details for MITRE/OWASP mapping, evidence, and recommendations.</p>
                </div>
                <button onClick={() => loadSummary()} disabled={loading} className="rounded-xl border border-[#cbe8d6] bg-white px-4 py-2 text-sm font-semibold text-[#173128] hover:bg-[#edfdf3] disabled:opacity-60">
                  Refresh
                </button>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full min-w-[1120px] text-left text-sm">
                  <thead className="border-b border-emerald-100 text-xs uppercase tracking-[0.12em] text-[#6b8277]">
                    <tr>
                      <th className="py-3 pr-4">Incident</th>
                      <th className="py-3 pr-4">Attack</th>
                      <th className="py-3 pr-4">Source IP</th>
                      <th className="py-3 pr-4">Target</th>
                      <th className="py-3 pr-4">Severity</th>
                      <th className="py-3 pr-4">Time</th>
                      <th className="py-3 pr-4">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {summary.incidents.length ? (
                      summary.incidents.map((incident) => (
                        <tr key={incident.id} className="border-b border-emerald-50 align-top">
                          <td className="py-4 pr-4 font-mono text-xs text-[#0f2b1d]">{incident.id}</td>
                          <td className="py-4 pr-4 text-[#48665a]">{incident.attack_type || 'Unknown'}</td>
                          <td className="py-4 pr-4 font-mono text-xs text-[#48665a]">{incident.source_ip || '—'}</td>
                          <td className="max-w-[300px] truncate py-4 pr-4 font-mono text-xs text-[#48665a]" title={incident.target_path || ''}>{incident.target_path || '—'}</td>
                          <td className="py-4 pr-4">
                            <span className={`rounded-full border px-3 py-1 text-xs font-semibold ${severityClasses(incident.severity)}`}>
                              {incident.severity}
                            </span>
                          </td>
                          <td className="py-4 pr-4 text-[#48665a]">{incident.timestamp || '—'}</td>
                          <td className="py-4 pr-4">
                            <div className="flex flex-wrap gap-2">
                              <button onClick={() => setSelectedIncident(incident)} className="rounded-lg border border-[#cbe8d6] bg-white px-3 py-2 text-xs font-semibold text-[#173128] hover:bg-[#edfdf3]">
                                Details
                              </button>
                              <button
                                disabled={!incident.hasPdf}
                                onClick={() => openPdf(incident.id, incident.tenant_id)}
                                className="rounded-lg border border-[#cbe8d6] bg-white px-3 py-2 text-xs font-semibold text-[#173128] hover:bg-[#edfdf3] disabled:cursor-not-allowed disabled:opacity-50"
                              >
                                {incident.hasPdf ? 'Open PDF' : 'No PDF'}
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))
                    ) : (
                      <EmptyRow colSpan={7}>No WAF incidents found yet.</EmptyRow>
                    )}
                  </tbody>
                </table>
              </div>
            </section>
          </>
        ) : (
          <div className="rounded-[2rem] border border-dashed border-emerald-200 bg-white p-10 text-center text-[#5a7668]">
            Enter your admin token to view live WAF incidents, run controlled demos, inspect evidence, and release blocked IPs.
          </div>
        )}
      </section>

      {selectedIncident ? (
        <div className="fixed inset-0 z-[80] flex items-center justify-center bg-slate-950/50 px-4 py-8 backdrop-blur-sm" role="dialog" aria-modal="true">
          <div className="max-h-[90vh] w-full max-w-4xl overflow-y-auto rounded-[2rem] border border-emerald-100 bg-white shadow-2xl">
            <div className="sticky top-0 flex items-start justify-between gap-4 border-b border-emerald-100 bg-white/95 p-6 backdrop-blur">
              <div>
                <p className="text-xs font-semibold uppercase tracking-[0.16em] text-emerald-700">Incident Details</p>
                <h3 className="mt-1 text-2xl font-semibold text-[#0f2b1d]">{selectedIncident.id}</h3>
              </div>
              <button onClick={() => setSelectedIncident(null)} className="rounded-xl border border-[#cbe8d6] bg-white px-3 py-2 text-sm font-semibold text-[#173128] hover:bg-[#edfdf3]">Close</button>
            </div>

            <div className="space-y-6 p-6">
              <div className="grid gap-4 md:grid-cols-2">
                {[
                  ['Attack Type', selectedIncident.attack_type || 'Unknown'],
                  ['Severity', selectedIncident.severity],
                  ['Source IP', selectedIncident.source_ip || '—'],
                  ['Target Path', selectedIncident.target_path || '—'],
                  ['Tenant', selectedIncident.tenant_name || selectedIncident.tenant_id || 'default_tenant'],
                  ['Action Taken', selectedIncident.action_taken || 'Blocked & Logged'],
                  ['OWASP', selectedIncident.owasp],
                  ['MITRE ATT&CK', selectedIncident.mitre],
                ].map(([label, value]) => (
                  <div key={label} className="rounded-2xl border border-emerald-100 bg-[#f7fbf8] p-4">
                    <p className="text-xs font-semibold uppercase tracking-[0.14em] text-[#6b8277]">{label}</p>
                    <p className="mt-2 break-words text-sm font-medium text-[#0f2b1d]">{value}</p>
                  </div>
                ))}
              </div>

              <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                <p className="text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">Evidence</p>
                <pre className="mt-3 max-h-52 overflow-auto whitespace-pre-wrap break-words rounded-xl bg-white p-4 text-xs leading-5 text-slate-700">{selectedIncident.evidence || 'No evidence text stored.'}</pre>
                <p className="mt-3 font-mono text-xs text-slate-500">SHA-256: {selectedIncident.evidenceHash || '—'}</p>
              </div>

              <div className="rounded-2xl border border-emerald-100 bg-emerald-50/40 p-4">
                <p className="text-xs font-semibold uppercase tracking-[0.14em] text-emerald-700">Recommended Mitigation</p>
                {selectedIncident.mitigation_recommendations?.length ? (
                  <ol className="mt-3 list-decimal space-y-2 pl-5 text-sm leading-6 text-[#173128]">
                    {selectedIncident.mitigation_recommendations.map((item, index) => (
                      <li key={`${item}-${index}`}>{item}</li>
                    ))}
                  </ol>
                ) : (
                  <p className="mt-3 text-sm text-[#5a7668]">No mitigation recommendations were stored for this incident.</p>
                )}
              </div>

              <div className="flex flex-wrap gap-2">
                <button
                  disabled={!selectedIncident.hasPdf}
                  onClick={() => openPdf(selectedIncident.id, selectedIncident.tenant_id)}
                  className="rounded-xl bg-[#15803d] px-4 py-2 text-sm font-semibold text-white hover:bg-[#166534] disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {selectedIncident.hasPdf ? 'Open PDF Evidence Report' : 'PDF Not Available'}
                </button>
                {selectedIncident.source_ip ? (
                  <button onClick={() => unblockIp(selectedIncident.source_ip as string)} className="rounded-xl border border-red-200 bg-red-50 px-4 py-2 text-sm font-semibold text-red-600 hover:bg-red-100">
                    Unblock Source IP
                  </button>
                ) : null}
              </div>
            </div>
          </div>
        </div>
      ) : null}
    </main>
  )
}
