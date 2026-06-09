// lib/server/knowledge-graph/mappings.ts

import type {
  GraphFindingInput,
  GraphMappingProvenance,
  MitreTechniqueInput,
  OwaspInput,
} from './types'

type Mapping = {
  cwes?: string[]
  owasp?: OwaspInput[]
  mitreTechniques?: MitreTechniqueInput[]
  impacts?: string[]
}

type KnownCveMapping = Mapping & {
  source: 'known-cve-rule'
  confidence: number
}

type KeywordMapping = Mapping & {
  pattern: RegExp
  rule: string
  confidence: number
}

const KNOWN_CVE_MAPPINGS: Record<string, KnownCveMapping> = {
  'CVE-2021-41773': {
    source: 'known-cve-rule',
    confidence: 85,
    cwes: ['CWE-22'],
    owasp: [{ id: 'A01:2021', name: 'Broken Access Control' }],
    mitreTechniques: [
      {
        id: 'T1190',
        name: 'Exploit Public-Facing Application',
        tactic: 'Initial Access',
      },
    ],
    impacts: ['Remote Code Execution', 'Information Disclosure'],
  },

  'CVE-2021-42013': {
    source: 'known-cve-rule',
    confidence: 85,
    cwes: ['CWE-22'],
    owasp: [{ id: 'A01:2021', name: 'Broken Access Control' }],
    mitreTechniques: [
      {
        id: 'T1190',
        name: 'Exploit Public-Facing Application',
        tactic: 'Initial Access',
      },
    ],
    impacts: ['Remote Code Execution'],
  },

  'CVE-2017-5638': {
    source: 'known-cve-rule',
    confidence: 90,
    cwes: ['CWE-20'],
    owasp: [{ id: 'A03:2021', name: 'Injection' }],
    mitreTechniques: [
      {
        id: 'T1190',
        name: 'Exploit Public-Facing Application',
        tactic: 'Initial Access',
      },
    ],
    impacts: ['Remote Code Execution'],
  },
}

const KEYWORD_RULES: KeywordMapping[] = [
  {
    rule: 'keyword:sqli',
    confidence: 72,
    pattern: /sql\s*injection|\bsqli\b/i,
    cwes: ['CWE-89'],
    owasp: [{ id: 'A03:2021', name: 'Injection' }],
    mitreTechniques: [
      {
        id: 'T1190',
        name: 'Exploit Public-Facing Application',
        tactic: 'Initial Access',
      },
    ],
    impacts: ['Data Leakage', 'Authentication Bypass'],
  },

  {
    rule: 'keyword:xss',
    confidence: 70,
    pattern: /xss|cross[-\s]?site scripting/i,
    cwes: ['CWE-79'],
    owasp: [{ id: 'A03:2021', name: 'Injection' }],
    mitreTechniques: [
      {
        id: 'T1059',
        name: 'Command and Scripting Interpreter',
        tactic: 'Execution',
      },
    ],
    impacts: ['Session Hijacking', 'Client-Side Code Execution'],
  },

  {
    rule: 'keyword:path-traversal',
    confidence: 72,
    pattern: /path traversal|directory traversal/i,
    cwes: ['CWE-22'],
    owasp: [{ id: 'A01:2021', name: 'Broken Access Control' }],
    mitreTechniques: [
      {
        id: 'T1190',
        name: 'Exploit Public-Facing Application',
        tactic: 'Initial Access',
      },
    ],
    impacts: ['Information Disclosure', 'Remote Code Execution'],
  },

  {
    rule: 'keyword:weak-credentials',
    confidence: 70,
    pattern: /weak password|default credential|brute force/i,
    cwes: ['CWE-521'],
    owasp: [
      {
        id: 'A07:2021',
        name: 'Identification and Authentication Failures',
      },
    ],
    mitreTechniques: [
      {
        id: 'T1110',
        name: 'Brute Force',
        tactic: 'Credential Access',
      },
    ],
    impacts: ['Account Compromise'],
  },

  {
    rule: 'keyword:rce',
    confidence: 76,
    pattern: /rce|remote code execution|command injection/i,
    cwes: ['CWE-78'],
    owasp: [{ id: 'A03:2021', name: 'Injection' }],
    mitreTechniques: [
      {
        id: 'T1059',
        name: 'Command and Scripting Interpreter',
        tactic: 'Execution',
      },
    ],
    impacts: ['Remote Code Execution', 'System Compromise'],
  },

  {
    rule: 'keyword:outdated-dependency',
    confidence: 70,
    pattern:
      /outdated dependenc|inconsistent compiler|cargo outdated|toolchain|dependency specification/i,
    cwes: ['CWE-1104'],
    owasp: [
      {
        id: 'A06:2021',
        name: 'Vulnerable and Outdated Components',
      },
    ],
    mitreTechniques: [
      {
        id: 'T1195',
        name: 'Supply Chain Compromise',
        tactic: 'Initial Access',
      },
    ],
    impacts: ['Dependency Exploitation', 'Build Instability'],
  },

  {
    rule: 'keyword:secret-exposure',
    confidence: 70,
    pattern: /secrets? in memory|memory not cleared|zeroize|stale data|core dump/i,
    cwes: ['CWE-244', 'CWE-226'],
    owasp: [{ id: 'A02:2021', name: 'Cryptographic Failures' }],
    mitreTechniques: [
      {
        id: 'T1005',
        name: 'Data from Local System',
        tactic: 'Collection',
      },
    ],
    impacts: ['Sensitive Data Exposure', 'Secret Leakage'],
  },

  {
    rule: 'keyword:weak-randomness',
    confidence: 70,
    pattern:
      /randomness generator|non-crypto randomness|entropy|fill_bytes|try_fill_bytes|getrandom/i,
    cwes: ['CWE-338', 'CWE-330'],
    owasp: [{ id: 'A02:2021', name: 'Cryptographic Failures' }],
    mitreTechniques: [
      {
        id: 'T1552',
        name: 'Unsecured Credentials',
        tactic: 'Credential Access',
      },
    ],
    impacts: ['Weak Key Generation', 'Predictable Cryptographic Material'],
  },

  {
    rule: 'keyword:input-validation',
    confidence: 70,
    pattern:
      /missing length check|length==0|validation check|deserialization|input validation/i,
    cwes: ['CWE-20', 'CWE-1284'],
    owasp: [{ id: 'A03:2021', name: 'Injection' }],
    mitreTechniques: [
      {
        id: 'T1499',
        name: 'Endpoint Denial of Service',
        tactic: 'Impact',
      },
    ],
    impacts: ['Denial of Service', 'Input Validation Failure'],
  },

  {
    rule: 'keyword:side-channel',
    confidence: 68,
    pattern:
      /constant-time|non constant-time|timing|side-channel|cache attack|microarchitectural/i,
    cwes: ['CWE-208', 'CWE-385'],
    owasp: [{ id: 'A02:2021', name: 'Cryptographic Failures' }],
    mitreTechniques: [
      {
        id: 'T1040',
        name: 'Network Sniffing',
        tactic: 'Credential Access',
      },
    ],
    impacts: ['Timing Side-Channel Leakage', 'Sensitive Data Disclosure'],
  },

  {
    rule: 'keyword:signature-forgery',
    confidence: 68,
    pattern:
      /aggregate verify|distinct messages|rogue key|aggregate signature|bls signature/i,
    cwes: ['CWE-347', 'CWE-345'],
    owasp: [{ id: 'A02:2021', name: 'Cryptographic Failures' }],
    mitreTechniques: [
      {
        id: 'T1606',
        name: 'Forge Web Credentials',
        tactic: 'Credential Access',
      },
    ],
    impacts: ['Signature Forgery', 'Authentication Bypass'],
  },
]

function uniqueStrings(values: Array<string | undefined | null>) {
  return Array.from(
    new Set(
      values
        .filter(Boolean)
        .map((value) => String(value).trim())
        .filter(Boolean)
    )
  )
}

function normalizeOwasp(item: OwaspInput): { id: string; name?: string } {
  return typeof item === 'string' ? { id: item } : item
}

function mergeOwasp(a: OwaspInput[] = [], b: OwaspInput[] = []) {
  const map = new Map<string, { id: string; name?: string }>()

  ;[...a, ...b].map(normalizeOwasp).forEach((item) => {
    if (item.id) {
      map.set(item.id, { ...map.get(item.id), ...item })
    }
  })

  return Array.from(map.values())
}

function mergeMitre(
  a: MitreTechniqueInput[] = [],
  b: MitreTechniqueInput[] = []
) {
  const map = new Map<string, MitreTechniqueInput>()

  ;[...a, ...b].forEach((item) => {
    if (item.id) {
      map.set(item.id, { ...map.get(item.id), ...item })
    }
  })

  return Array.from(map.values())
}

function addProvenance(
  list: GraphMappingProvenance[],
  entries: Array<{
    kind: GraphMappingProvenance['kind']
    id: string
    source: GraphMappingProvenance['source']
    rule?: string
    confidence: number
    inferred: boolean
  }>
) {
  for (const entry of entries) {
    const id = String(entry.id ?? '').trim()
    if (!id) continue

    const existing = list.find(
      (item) => item.kind === entry.kind && item.id === id && item.source === entry.source
    )

    if (existing) {
      existing.confidence = Math.max(existing.confidence, entry.confidence)
      continue
    }

    list.push({ ...entry, id })
  }
}

function markReportedProvenance(finding: GraphFindingInput) {
  const provenance: GraphMappingProvenance[] = [...(finding.mappingProvenance ?? [])]

  addProvenance(
    provenance,
    (finding.cwes ?? []).map((id) => ({
      kind: 'cwe' as const,
      id,
      source: 'report-extracted' as const,
      confidence: 95,
      inferred: false,
    }))
  )

  addProvenance(
    provenance,
    (finding.owasp ?? []).map((item) => {
      const normalized = normalizeOwasp(item)
      return {
        kind: 'owasp' as const,
        id: normalized.id,
        source: 'report-extracted' as const,
        confidence: 90,
        inferred: false,
      }
    })
  )

  addProvenance(
    provenance,
    (finding.mitreTechniques ?? []).map((item) => ({
      kind: 'mitre' as const,
      id: item.id,
      source: 'report-extracted' as const,
      confidence: 90,
      inferred: false,
    }))
  )

  addProvenance(
    provenance,
    (finding.impacts ?? []).map((id) => ({
      kind: 'impact' as const,
      id,
      source: 'report-extracted' as const,
      confidence: 90,
      inferred: false,
    }))
  )

  return provenance
}

export function extractCvesFromText(text: string): string[] {
  return uniqueStrings(text.match(/\bCVE-\d{4}-\d{4,7}\b/gi) ?? []).map((cve) =>
    cve.toUpperCase()
  )
}

export function enrichFinding(finding: GraphFindingInput): GraphFindingInput {
  const text = [
    finding.title,
    finding.description,
    finding.impacts?.join(' '),
    finding.remediations?.join(' '),
  ]
    .filter(Boolean)
    .join(' ')

  let cwes = finding.cwes ?? []
  let owasp = finding.owasp ?? []
  let mitreTechniques = finding.mitreTechniques ?? []
  let impacts = finding.impacts ?? []
  const mappingProvenance = markReportedProvenance(finding)

  const cves = uniqueStrings([
    ...(finding.cves ?? []),
    ...extractCvesFromText(text),
  ]).map((cve) => cve.toUpperCase())

  for (const cve of cves) {
    const mapping = KNOWN_CVE_MAPPINGS[cve]

    if (!mapping) continue

    cwes = uniqueStrings([...cwes, ...(mapping.cwes ?? [])])
    owasp = mergeOwasp(owasp, mapping.owasp ?? [])
    mitreTechniques = mergeMitre(mitreTechniques, mapping.mitreTechniques ?? [])
    impacts = uniqueStrings([...impacts, ...(mapping.impacts ?? [])])

    addProvenance(mappingProvenance, [
      ...(mapping.cwes ?? []).map((id) => ({
        kind: 'cwe' as const,
        id,
        source: mapping.source,
        rule: cve,
        confidence: mapping.confidence,
        inferred: true,
      })),
      ...(mapping.owasp ?? []).map((item) => {
        const normalized = normalizeOwasp(item)
        return {
          kind: 'owasp' as const,
          id: normalized.id,
          source: mapping.source,
          rule: cve,
          confidence: mapping.confidence,
          inferred: true,
        }
      }),
      ...(mapping.mitreTechniques ?? []).map((item) => ({
        kind: 'mitre' as const,
        id: item.id,
        source: mapping.source,
        rule: cve,
        confidence: mapping.confidence,
        inferred: true,
      })),
      ...(mapping.impacts ?? []).map((id) => ({
        kind: 'impact' as const,
        id,
        source: mapping.source,
        rule: cve,
        confidence: mapping.confidence,
        inferred: true,
      })),
    ])
  }

  for (const rule of KEYWORD_RULES) {
    if (!rule.pattern.test(text)) continue

    cwes = uniqueStrings([...cwes, ...(rule.cwes ?? [])])
    owasp = mergeOwasp(owasp, rule.owasp ?? [])
    mitreTechniques = mergeMitre(mitreTechniques, rule.mitreTechniques ?? [])
    impacts = uniqueStrings([...impacts, ...(rule.impacts ?? [])])

    addProvenance(mappingProvenance, [
      ...(rule.cwes ?? []).map((id) => ({
        kind: 'cwe' as const,
        id,
        source: 'deterministic-keyword-rule' as const,
        rule: rule.rule,
        confidence: rule.confidence,
        inferred: true,
      })),
      ...(rule.owasp ?? []).map((item) => {
        const normalized = normalizeOwasp(item)
        return {
          kind: 'owasp' as const,
          id: normalized.id,
          source: 'deterministic-keyword-rule' as const,
          rule: rule.rule,
          confidence: rule.confidence,
          inferred: true,
        }
      }),
      ...(rule.mitreTechniques ?? []).map((item) => ({
        kind: 'mitre' as const,
        id: item.id,
        source: 'deterministic-keyword-rule' as const,
        rule: rule.rule,
        confidence: rule.confidence,
        inferred: true,
      })),
      ...(rule.impacts ?? []).map((id) => ({
        kind: 'impact' as const,
        id,
        source: 'deterministic-keyword-rule' as const,
        rule: rule.rule,
        confidence: rule.confidence,
        inferred: true,
      })),
    ])
  }

  return {
    ...finding,
    cves,
    cwes,
    owasp,
    mitreTechniques,
    impacts,
    mappingProvenance,
  }
}
