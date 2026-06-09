import { envInt, fetchJsonWithTimeout } from './source-status'

export type CisaKevIntel = {
  cveId: string
  source: 'CISA_KEV'
  vendorProject?: string
  product?: string
  vulnerabilityName?: string
  dateAdded?: string
  dueDate?: string
  requiredAction?: string
  knownRansomwareCampaignUse?: string
  notes?: string
}

let kevCache:
  | {
      loadedAt: number
      byCve: Map<string, CisaKevIntel>
    }
  | null = null

const CACHE_MS = 1000 * 60 * 30

export async function fetchCisaKevCatalog() {
  const now = Date.now()

  if (kevCache && now - kevCache.loadedAt < CACHE_MS) {
    return kevCache.byCve
  }

  const { data } = await fetchJsonWithTimeout<any>(
    'CISA_KEV',
    'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    { cache: 'no-store' },
    envInt('CISA_KEV_TIMEOUT_MS', 12_000)
  )

  const byCve = new Map<string, CisaKevIntel>()

  for (const item of data.vulnerabilities ?? []) {
    const cveId = String(item.cveID ?? '').toUpperCase()

    if (!cveId) continue

    byCve.set(cveId, {
      cveId,
      source: 'CISA_KEV',
      vendorProject: item.vendorProject,
      product: item.product,
      vulnerabilityName: item.vulnerabilityName,
      dateAdded: item.dateAdded,
      dueDate: item.dueDate,
      requiredAction: item.requiredAction,
      knownRansomwareCampaignUse: item.knownRansomwareCampaignUse,
      notes: item.notes,
    })
  }

  kevCache = {
    loadedAt: now,
    byCve,
  }

  return byCve
}

export async function findCisaKev(cveId: string) {
  const catalog = await fetchCisaKevCatalog()
  return catalog.get(String(cveId ?? '').toUpperCase()) ?? null
}
