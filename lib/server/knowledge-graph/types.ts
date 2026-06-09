// lib/server/knowledge-graph/types.ts

export type GraphEvidenceSource =
  | 'report-extracted'
  | 'threat-intel'
  | 'deterministic-keyword-rule'
  | 'known-cve-rule'
  | 'risk-engine'
  | 'user-supplied'
  | 'unknown'

export type GraphMappingProvenance = {
  kind: 'cwe' | 'owasp' | 'mitre' | 'impact'
  id: string
  source: GraphEvidenceSource
  rule?: string
  confidence: number
  inferred: boolean
}

export type OwaspInput =
  | string
  | {
      id: string
      name?: string
      source?: GraphEvidenceSource
      confidence?: number
      inferred?: boolean
    }

export type MitreTechniqueInput = {
  id: string
  name?: string
  tactic?: string
  source?: GraphEvidenceSource
  confidence?: number
  inferred?: boolean
}

export type GraphIndicatorInput = {
  type: 'URL' | 'Domain' | 'IP' | 'Port' | 'Service' | 'Endpoint'
  value: string
  source?: GraphEvidenceSource
  confidence?: number
}

export type GraphFindingInput = {
  id?: string
  title: string
  description?: string
  severity?: string
  riskScore?: number

  asset?: string
  assets?: string[]

  cves?: string[]
  cwes?: string[]
  owasp?: OwaspInput[]
  mitreTechniques?: MitreTechniqueInput[]

  impacts?: string[]
  remediations?: string[]
  exploits?: string[]
  indicators?: GraphIndicatorInput[]

  mappingProvenance?: GraphMappingProvenance[]
}

export type BuildGraphInput = {
  userId: string
  reportId: string
  reportName?: string
  sourceFileName?: string
  findings: GraphFindingInput[]
}
