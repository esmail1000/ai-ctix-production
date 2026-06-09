import { getCurrentSessionFromCookies } from '@/lib/server/current-session'
import { findCisaKev } from '@/lib/server/threat-intel/cisa-kev'
import { searchMispByCveDetailed } from '@/lib/server/threat-intel/misp'
import { fetchNvdCve } from '@/lib/server/threat-intel/nvd'
import type { ThreatIntelSourceStatus } from '@/lib/server/threat-intel/source-status'
import { sourceErrorToStatus } from '@/lib/server/threat-intel/source-status'
import { NextResponse } from 'next/server'

export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

function normalizeCve(value: string | null) {
  const cveId = String(value ?? '').trim().toUpperCase()
  return /^CVE-\d{4}-\d{4,}$/i.test(cveId) ? cveId : ''
}

export async function GET(request: Request) {
  try {
    const session = await getCurrentSessionFromCookies()

    if (!session) {
      return NextResponse.json(
        { error: 'Authentication required.' },
        { status: 401 }
      )
    }

    const url = new URL(request.url)
    const cveId = normalizeCve(url.searchParams.get('cve'))

    if (!cveId) {
      return NextResponse.json(
        { error: 'Missing or invalid CVE. Expected format: CVE-YYYY-NNNN.' },
        { status: 400 }
      )
    }

    const sourceStatuses: ThreatIntelSourceStatus[] = []
    const errors: Array<{ cveId: string; source: string; error: string }> = []

    let nvd: Awaited<ReturnType<typeof fetchNvdCve>> | null = null
    let kev: Awaited<ReturnType<typeof findCisaKev>> | null = null
    let mispMatches = 0
    let mispEnabled = false
    let mispNote: string | null = null

    try {
      nvd = await fetchNvdCve(cveId)
      sourceStatuses.push({
        source: 'NVD',
        status: nvd ? 'ok' : 'not_found',
        cveId,
        message: nvd ? 'NVD returned a CVE record.' : 'NVD returned no CVE record for this identifier.',
      })
    } catch (error) {
      const status = sourceErrorToStatus('NVD', cveId, error)
      sourceStatuses.push(status)
      errors.push({
        cveId,
        source: 'NVD',
        error: status.error ?? status.message ?? 'NVD lookup failed.',
      })
    }

    try {
      kev = await findCisaKev(cveId)
      sourceStatuses.push({
        source: 'CISA_KEV',
        status: kev ? 'ok' : 'not_found',
        cveId,
        message: kev ? 'CISA KEV listed this CVE as known exploited.' : 'CISA KEV did not list this CVE.',
      })
    } catch (error) {
      const status = sourceErrorToStatus('CISA_KEV', cveId, error)
      sourceStatuses.push(status)
      errors.push({
        cveId,
        source: 'CISA_KEV',
        error: status.error ?? status.message ?? 'CISA KEV lookup failed.',
      })
    }

    try {
      const misp = await searchMispByCveDetailed(cveId)
      mispMatches = misp.matches.length
      mispEnabled = misp.enabled
      mispNote = misp.note ?? null
      sourceStatuses.push(misp.sourceStatus)
    } catch (error) {
      const status = sourceErrorToStatus('MISP', cveId, error)
      sourceStatuses.push(status)
      errors.push({
        cveId,
        source: 'MISP',
        error: status.error ?? status.message ?? 'MISP lookup failed.',
      })
    }

    return NextResponse.json({
      ok: errors.length === 0,
      cveId,
      nvd: Boolean(nvd),
      cisaKev: Boolean(kev),
      knownExploited: Boolean(kev),
      cvssScore: nvd?.cvssScore ?? null,
      cvssSeverity: nvd?.cvssSeverity ?? null,
      cvssVector: nvd?.cvssVector ?? null,
      misp: {
        enabled: mispEnabled,
        matches: mispMatches,
        note: mispNote,
      },
      mispMatches,
      sourceStatuses,
      errors,
    })
  } catch (error) {
    console.error('Threat intel CVE lookup failed:', error)

    return NextResponse.json(
      {
        error: 'Threat intel CVE lookup failed',
        details: error instanceof Error ? error.message : String(error),
      },
      { status: 500 }
    )
  }
}
