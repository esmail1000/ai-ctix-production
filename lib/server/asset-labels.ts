export function normalizeAssetLabel(asset: string): string {
  const raw = String(asset ?? '').trim()
  const lower = raw.toLowerCase()

  const map: Record<string, string> = {
    administrative: 'Administrative Access Plane',
    admin: 'Administrative Access Plane',
    application: 'Application Service',
    storage: 'Storage Service',
    'internet-facing': 'Internet-Facing Edge',
    'unknown-asset': 'Investigation Scope',
    'investigation-scope': 'Investigation Scope',
  }

  return map[lower] ?? raw
}