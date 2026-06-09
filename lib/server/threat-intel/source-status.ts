export type ThreatIntelSourceName = 'NVD' | 'CISA_KEV' | 'MISP' | 'GRAPH' | 'POSTGRES'

export type ThreatIntelSourceStatus = {
  source: ThreatIntelSourceName
  status: 'ok' | 'not_found' | 'disabled' | 'error'
  cveId?: string
  configured?: boolean
  durationMs?: number
  statusCode?: number
  message?: string
  error?: string
}

export class ThreatIntelSourceError extends Error {
  source: ThreatIntelSourceName
  statusCode?: number

  constructor(source: ThreatIntelSourceName, message: string, statusCode?: number) {
    super(message)
    this.name = 'ThreatIntelSourceError'
    this.source = source
    this.statusCode = statusCode
  }
}

export function envInt(name: string, fallback: number) {
  const raw = process.env[name]
  const parsed = Number(raw)
  return Number.isFinite(parsed) && parsed > 0 ? Math.floor(parsed) : fallback
}

export async function fetchJsonWithTimeout<T>(
  source: ThreatIntelSourceName,
  url: string | URL,
  init: RequestInit = {},
  timeoutMs = 12_000
): Promise<{ data: T; durationMs: number; statusCode: number }> {
  const controller = new AbortController()
  const startedAt = Date.now()
  const timeout = setTimeout(() => controller.abort(), timeoutMs)

  try {
    const response = await fetch(url, {
      ...init,
      signal: controller.signal,
    })

    const durationMs = Date.now() - startedAt

    if (!response.ok) {
      throw new ThreatIntelSourceError(
        source,
        `${source} request failed with HTTP ${response.status}`,
        response.status
      )
    }

    return {
      data: (await response.json()) as T,
      durationMs,
      statusCode: response.status,
    }
  } catch (error) {
    if (error instanceof ThreatIntelSourceError) {
      throw error
    }

    const isAbort = error instanceof Error && error.name === 'AbortError'
    const message = isAbort
      ? `${source} request timed out after ${timeoutMs}ms`
      : error instanceof Error
        ? error.message
        : String(error)

    throw new ThreatIntelSourceError(source, message)
  } finally {
    clearTimeout(timeout)
  }
}

export function sourceErrorToStatus(
  source: ThreatIntelSourceName,
  cveId: string | undefined,
  error: unknown
): ThreatIntelSourceStatus {
  if (error instanceof ThreatIntelSourceError) {
    return {
      source: error.source,
      status: 'error',
      cveId,
      statusCode: error.statusCode,
      error: error.message,
    }
  }

  return {
    source,
    status: 'error',
    cveId,
    error: error instanceof Error ? error.message : String(error),
  }
}
