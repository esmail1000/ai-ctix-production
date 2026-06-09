import { promises as fs } from 'fs'
import crypto from 'crypto'
import path from 'path'
import { NextRequest, NextResponse } from 'next/server'
import { BLOCKED_IPS_FILE, PDF_REPORTS_DIR, REPORTS_DIR, requireWafAdmin, safeTenant } from '../_shared'

export const dynamic = 'force-dynamic'

type BlockedIpRecord = {
  blocked_at?: number
  expiry?: number
  reason?: string
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
}

async function readJsonFile<T>(filePath: string, fallback: T): Promise<T> {
  try {
    const raw = await fs.readFile(filePath, 'utf8')
    return JSON.parse(raw) as T
  } catch {
    return fallback
  }
}

async function listIncidentFiles(dir: string): Promise<string[]> {
  try {
    const entries = await fs.readdir(dir, { withFileTypes: true })
    const files: string[] = []

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name)
      if (entry.isDirectory()) {
        files.push(...(await listIncidentFiles(fullPath)))
      } else if (entry.isFile() && entry.name.toLowerCase().endsWith('.json')) {
        files.push(fullPath)
      }
    }

    return files
  } catch {
    return []
  }
}

async function pdfExists(tenantId: string, incidentId: string) {
  try {
    await fs.access(path.join(PDF_REPORTS_DIR, safeTenant(tenantId), `${incidentId}.pdf`))
    return true
  } catch {
    return false
  }
}

function severityFor(attackType = ''): 'High' | 'Medium' | 'Low' {
  const name = attackType.toLowerCase()
  if (
    name.includes('xss') ||
    name.includes('script') ||
    name.includes('sensitive') ||
    name.includes('rce') ||
    name.includes('command') ||
    name.includes('xxe') ||
    name.includes('dos')
  ) {
    return 'High'
  }
  if (name.includes('sql') || name.includes('path') || name.includes('traversal') || name.includes('jwt') || name.includes('access')) return 'Medium'
  return 'Low'
}

function mappingsFor(attackType = '') {
  const name = attackType.toLowerCase()

  if (name.includes('xss') || name.includes('script')) {
    return {
      owasp: 'OWASP A03:2025 - Injection (XSS)',
      mitre: 'MITRE T1189 - Drive-by Compromise',
    }
  }

  if (name.includes('sql')) {
    return {
      owasp: 'OWASP A03:2025 - Injection (SQLi)',
      mitre: 'MITRE T1190 - Exploit Public-Facing Application',
    }
  }

  if (name.includes('path') || name.includes('traversal')) {
    return {
      owasp: 'OWASP A01:2025 - Broken Access Control',
      mitre: 'MITRE T1083 - File and Directory Discovery',
    }
  }

  if (name.includes('command') || name.includes('rce')) {
    return {
      owasp: 'OWASP A03:2025 - Injection (Command Execution)',
      mitre: 'MITRE T1059 - Command and Scripting Interpreter',
    }
  }

  if (name.includes('jwt') || name.includes('crypto')) {
    return {
      owasp: 'OWASP A02:2025 - Cryptographic Failures',
      mitre: 'MITRE T1552 - Unsecured Credentials',
    }
  }

  if (name.includes('dos')) {
    return {
      owasp: 'OWASP A05:2025 - Security Misconfiguration / Availability Risk',
      mitre: 'MITRE T1499 - Endpoint Denial of Service',
    }
  }

  return {
    owasp: 'OWASP Web Application Security Control',
    mitre: 'MITRE ATT&CK - Application Layer Activity',
  }
}

function evidenceHash(evidence = '') {
  return crypto.createHash('sha256').update(String(evidence)).digest('hex')
}

function timestampToMs(timestamp?: string) {
  if (!timestamp) return 0
  const parsed = Date.parse(timestamp)
  if (Number.isFinite(parsed)) return parsed

  // WAF currently emits timestamps like "2026-06-06 03:07:28".
  const normalized = Date.parse(timestamp.replace(' ', 'T'))
  return Number.isFinite(normalized) ? normalized : 0
}

export async function GET(request: NextRequest) {
  const authError = requireWafAdmin(request)
  if (authError) return authError

  const now = Math.floor(Date.now() / 1000)
  const blockedIps = await readJsonFile<Record<string, BlockedIpRecord>>(BLOCKED_IPS_FILE, {})
  const incidentFiles = await listIncidentFiles(REPORTS_DIR)

  const incidents: Array<WafIncident & { severity: 'High' | 'Medium' | 'Low'; owasp: string; mitre: string; evidenceHash: string; hasPdf: boolean }> = []

  for (const filePath of incidentFiles) {
    const incident = await readJsonFile<WafIncident | null>(filePath, null)
    if (!incident?.id) continue

    const tenantId = incident.tenant_id || 'default_tenant'
    const mappings = mappingsFor(incident.attack_type)

    incidents.push({
      ...incident,
      severity: severityFor(incident.attack_type),
      ...mappings,
      evidenceHash: evidenceHash(incident.evidence),
      hasPdf: await pdfExists(tenantId, incident.id),
    })
  }

  incidents.sort((a, b) => timestampToMs(b.timestamp) - timestampToMs(a.timestamp))

  const activeBlockedIps = Object.entries(blockedIps)
    .map(([ip, record]) => ({
      ip,
      blockedAt: record.blocked_at || null,
      expiry: record.expiry || null,
      reason: record.reason || 'WAF Security Policy Block',
      secondsLeft: record.expiry ? Math.max(0, Math.floor(record.expiry - now)) : null,
      expired: record.expiry ? record.expiry <= now : false,
    }))
    .sort((a, b) => (b.blockedAt || 0) - (a.blockedAt || 0))

  const last24h = Date.now() - 24 * 60 * 60 * 1000
  const incidentsLast24h = incidents.filter((incident) => timestampToMs(incident.timestamp) >= last24h).length
  const highSeverity = incidents.filter((incident) => incident.severity === 'High').length

  return NextResponse.json({
    status: 'active',
    generatedAt: new Date().toISOString(),
    paths: {
      blockedIpsFile: BLOCKED_IPS_FILE,
      reportsDir: REPORTS_DIR,
      pdfReportsDir: PDF_REPORTS_DIR,
    },
    metrics: {
      totalIncidents: incidents.length,
      incidentsLast24h,
      blockedIps: activeBlockedIps.length,
      highSeverity,
      lastAttackTime: incidents[0]?.timestamp || null,
    },
    blockedIps: activeBlockedIps,
    incidents: incidents.slice(0, 150),
  })
}
