import type { ThreatIntelSourceStatus } from './source-status'
import { envInt, fetchJsonWithTimeout } from './source-status'

export type MispIntel = {
  source: 'MISP'
  value: string
  category?: string
  type?: string
  eventId?: string
  eventInfo?: string
  tags: string[]
}

export type MispSearchResult = {
  enabled: boolean
  matches: MispIntel[]
  sourceStatus: ThreatIntelSourceStatus
  note?: string
}

export function getMispConfiguration() {
  const baseUrl = process.env.MISP_BASE_URL
  const apiKey = process.env.MISP_API_KEY

  return {
    baseUrl,
    apiKey,
    enabled: Boolean(baseUrl && apiKey),
  }
}

export async function searchMispByCveDetailed(cveId: string): Promise<MispSearchResult> {
  const normalizedCveId = String(cveId ?? '').trim().toUpperCase()
  const { baseUrl, apiKey, enabled } = getMispConfiguration()

  if (!enabled || !baseUrl || !apiKey) {
    const note = 'MISP is not configured. Set MISP_BASE_URL and MISP_API_KEY to enable MISP lookups.'

    return {
      enabled: false,
      matches: [],
      note,
      sourceStatus: {
        source: 'MISP',
        status: 'disabled',
        cveId: normalizedCveId,
        configured: false,
        message: note,
      },
    }
  }

  const { data, durationMs } = await fetchJsonWithTimeout<any>(
    'MISP',
    `${baseUrl.replace(/\/$/, '')}/attributes/restSearch`,
    {
      method: 'POST',
      headers: {
        Authorization: apiKey,
        Accept: 'application/json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        returnFormat: 'json',
        value: normalizedCveId,
        limit: 10,
        includeEventTags: true,
      }),
      cache: 'no-store',
    },
    envInt('MISP_TIMEOUT_MS', 12_000)
  )

  const attributes = data.response?.Attribute ?? data.Attribute ?? []
  const matches = attributes.map((attr: any) => ({
    source: 'MISP' as const,
    value: String(attr.value ?? normalizedCveId),
    category: attr.category,
    type: attr.type,
    eventId: attr.event_id,
    eventInfo: attr.Event?.info,
    tags: [
      ...(attr.Tag ?? []).map((tag: any) => tag.name).filter(Boolean),
      ...(attr.Event?.Tag ?? []).map((tag: any) => tag.name).filter(Boolean),
    ],
  }))

  return {
    enabled: true,
    matches,
    sourceStatus: {
      source: 'MISP',
      status: matches.length > 0 ? 'ok' : 'not_found',
      cveId: normalizedCveId,
      configured: true,
      durationMs,
      message:
        matches.length > 0
          ? `MISP returned ${matches.length} matching attribute(s).`
          : 'MISP is configured and returned no matching attributes for this CVE.',
    },
  }
}

export async function searchMispByCve(cveId: string): Promise<MispIntel[]> {
  const result = await searchMispByCveDetailed(cveId)
  return result.matches
}
