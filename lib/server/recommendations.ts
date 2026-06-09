import type { StoredFinding } from '@/lib/server/types'

export type RecommendationSource =
  | 'reported-remediation'
  | 'rule:sqli'
  | 'rule:rce'
  | 'rule:network-exposure'
  | 'rule:known-exploited'
  | 'rule:monitoring'
  | 'rule:default-hardening'

export type RecommendationResult = {
  recommendations: string[]
  sources: RecommendationSource[]
}

type RecommendationItem = {
  text: string
  source: RecommendationSource
}

function normalizeText(value: string | null | undefined): string {
  return String(value ?? '')
    .replace(/\s+/g, ' ')
    .replace(/^[\s•*\-]+/, '')
    .replace(/[\s,;.:]+$/, '')
    .trim()
}

function semanticKey(value: string): string {
  return normalizeText(value)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, ' ')
    .replace(/\b(the|a|an|and|or|to|of|for|with|after|before)\b/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
}

function isNearDuplicate(a: string, b: string): boolean {
  const left = semanticKey(a)
  const right = semanticKey(b)
  if (!left || !right) return false
  if (left === right) return true

  const [shorter, longer] = left.length <= right.length ? [left, right] : [right, left]
  return shorter.length >= 18 && longer.includes(shorter)
}

function dedupeItems(items: RecommendationItem[]): RecommendationItem[] {
  const output: RecommendationItem[] = []

  for (const item of items) {
    const text = normalizeText(item.text)
    if (!text) continue

    const duplicateIndex = output.findIndex((existing) => isNearDuplicate(existing.text, text))
    if (duplicateIndex >= 0) {
      const existing = output[duplicateIndex]
      const preferCurrent =
        existing.source !== 'reported-remediation' &&
        (item.source === 'reported-remediation' || text.length > existing.text.length + 20)

      if (preferCurrent) output[duplicateIndex] = { text, source: item.source }
      continue
    }

    output.push({ text, source: item.source })
  }

  return output
}

function isGenericRemediation(value: string | undefined): boolean {
  const normalized = normalizeText(value).toLowerCase()
  if (!normalized) return true

  return (
    /^patch the affected component\b/.test(normalized) ||
    /^validate the affected component\b/.test(normalized) ||
    /remove unsafe command or code execution paths/.test(normalized) ||
    /confirm remediation with a targeted retest/.test(normalized)
  )
}

function chooseReportedRemediation(finding: StoredFinding): string | undefined {
  const candidates = [finding.remediation, finding.reported?.remediation]
    .map(normalizeText)
    .filter(Boolean)

  const specific = candidates.filter((item) => !isGenericRemediation(item))
  if (specific.length > 0) {
    return specific.sort((a, b) => b.length - a.length)[0]
  }

  return candidates.sort((a, b) => b.length - a.length)[0]
}

function splitReportedRemediation(value: string | undefined): string[] {
  const normalized = normalizeText(value)
  if (!normalized) return []

  // Do not split on commas or the word "and". Remediation sentences often use
  // comma-separated control lists such as "validate input, least privilege, and WAF";
  // splitting those creates broken recommendations.
  const parts = normalized
    .split(/\n+|\r+|;|(?<=\.)\s+(?=[A-Z])/g)
    .map(normalizeText)
    .filter((item) => item.length >= 8)

  return parts.length > 0 ? parts : [normalized]
}

function findingText(finding: StoredFinding): string {
  return [
    finding.title,
    finding.cve,
    finding.asset,
    finding.summary,
    finding.impact,
    finding.evidence,
    finding.remediation,
    finding.reported?.summary,
    finding.reported?.impact,
    finding.reported?.evidence,
    finding.reported?.remediation,
  ]
    .map(normalizeText)
    .join(' ')
    .toLowerCase()
}

function push(
  items: RecommendationItem[],
  recommendation: string,
  source: RecommendationSource
) {
  const normalized = normalizeText(recommendation)
  if (!normalized) return

  const duplicateIndex = items.findIndex((item) => isNearDuplicate(item.text, normalized))
  if (duplicateIndex >= 0) {
    const existing = items[duplicateIndex]
    const preferCurrent =
      existing.source !== 'reported-remediation' &&
      (source === 'reported-remediation' || normalized.length > existing.text.length + 20)

    if (preferCurrent) items[duplicateIndex] = { text: normalized, source }
    return
  }

  items.push({ text: normalized, source })
}

export function generateFindingRecommendations(input: {
  finding: StoredFinding
  knownExploited?: boolean
  attackVector?: string | null
  exploitAvailable?: boolean
}): RecommendationResult {
  const { finding } = input
  const text = findingText(finding)
  const items: RecommendationItem[] = []

  for (const item of splitReportedRemediation(chooseReportedRemediation(finding))) {
    push(items, item, 'reported-remediation')
  }

  const isSqli = /sql injection|cwe-89|parameterized quer|database/i.test(text)
  const isRce = /remote code execution|\brce\b|cwe-94|cwe-78|ognl|command execution|arbitrary operating system commands|apache struts/i.test(text)

  if (isSqli) {
    push(
      items,
      'Use parameterized queries or prepared statements for every database operation that consumes user input',
      'rule:sqli'
    )
    push(
      items,
      'Apply allow-list input validation at the API boundary and reject malformed login parameters before query construction',
      'rule:sqli'
    )
    push(
      items,
      'Restrict database accounts used by the application to least-privilege permissions and remove write privileges where they are not required',
      'rule:sqli'
    )
  }

  if (isRce) {
    push(
      items,
      'Upgrade the affected framework or component to a vendor-supported patched version and verify the installed version after deployment',
      'rule:rce'
    )
    if (/struts|ognl|content-type|upload/i.test(text)) {
      push(
        items,
        'Block malicious upload headers and add detection for OGNL expression exploitation attempts in web and application logs',
        'rule:rce'
      )
    }
    push(
      items,
      'Restrict exposure of the affected endpoint and require authentication or network allow-listing until the patch is verified',
      'rule:rce'
    )
  }

  const attackVector = normalizeText(input.attackVector).toLowerCase()
  if (attackVector === 'network' || /network|internet|public|external|https?|api|upload/.test(text)) {
    push(
      items,
      'Prioritize remediation for network-reachable attack paths and validate that public or external access is limited to required sources',
      'rule:network-exposure'
    )
  }

  if (input.knownExploited) {
    push(
      items,
      'Treat this CVE as an emergency remediation item because threat intelligence marks it as known exploited in the wild',
      'rule:known-exploited'
    )
    push(
      items,
      'Review historical access, web, and application logs for exploitation indicators before and after patching',
      'rule:monitoring'
    )
  } else if (input.exploitAvailable) {
    push(
      items,
      'Add detection rules for the proof-of-concept behavior described in the report and retest after remediation',
      'rule:monitoring'
    )
  }

  if (items.length === 0) {
    push(
      items,
      'Validate the affected component, apply the vendor or secure-configuration fix, and retest the original evidence path',
      'rule:default-hardening'
    )
  }

  const deduped = dedupeItems(items).slice(0, 8)

  return {
    recommendations: deduped.map((item) => item.text),
    sources: deduped.map((item) => item.source),
  }
}
