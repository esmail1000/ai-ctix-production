export type NlpEngineMode = "auto" | "regex" | "model";

export type NlpModelQuality = {
  metrics_found?: boolean;
  eval_f1?: number | null;
  eval_precision?: number | null;
  eval_recall?: number | null;
  eval_accuracy?: number | null;
  source?: string | null;
  [key: string]: unknown;
};

export type NlpEngineMeta = {
  engine?: string;
  schema_version?: string;
  mode?: NlpEngineMode | string;
  model_loaded?: boolean;
  model_dir?: string | null;
  fallback_used?: boolean;
  regex_enrichment_used?: boolean;
  contextual_rule_enrichment_used?: boolean;
  safety_filter_used?: boolean;
  model_quality?: NlpModelQuality;
  model_quality_gate_passed?: boolean;
  min_model_f1?: number;
  min_entity_confidence?: number;
  warnings?: string[];
  error?: string;
  node_client_python_command?: string;
  stderr?: string;
  timeout_ms?: number;
  [key: string]: unknown;
};

export type NlpEngineFinding = {
  vulnerability_type?: string;
  severity?: string;
  risk_level?: string;
  impact?: string;
  remediation?: string;
  product?: string;
  vendor?: string;
  version?: string;
  affected_component?: string;
  asset?: string;
  endpoint?: string;
  service?: string;
  attack_vector?: string;
  attack_technique?: string;
  exploitability?: string;

  cve_ids?: string[];
  cwe_ids?: string[];
  cvss_scores?: string[];
  cvss_vectors?: string[];
  cpes?: string[];

  urls?: string[];
  domains?: string[];
  ips?: string[];
  ip_ranges?: string[];
  emails?: string[];
  ports?: string[];

  file_paths?: string[];
  file_names?: string[];
  md5_hashes?: string[];
  sha1_hashes?: string[];
  sha256_hashes?: string[];
  hashes?: string[];
  malware?: string[];

  attack_vectors?: string[];
  attack_techniques?: string[];
  mitre_techniques?: string[];
  threat_actors?: string[];
  exploits?: string[];
  exploit_available?: string[];

  [key: string]: unknown;
};

export type NlpEngineResult = {
  // Legacy fields used by the current dashboard bridge.
  cve_ids: string[];
  vulnerability_types: string[];
  severity: string[];
  impacts: string[];
  ips: string[];
  urls: string[];
  domains: string[];
  ports: string[];

  // Expanded CTI schema from the upgraded Python NLP engine.
  cwe_ids?: string[];
  cvss_scores?: string[];
  cvss_vectors?: string[];
  cpes?: string[];

  risk_levels?: string[];
  remediations?: string[];
  mitigations?: string[];
  patches?: string[];

  products?: string[];
  vendors?: string[];
  versions?: string[];
  affected_components?: string[];
  assets?: string[];
  endpoints?: string[];
  services?: string[];

  ip_ranges?: string[];
  emails?: string[];

  file_paths?: string[];
  file_names?: string[];
  md5_hashes?: string[];
  sha1_hashes?: string[];
  sha256_hashes?: string[];
  hashes?: string[];
  malware?: string[];

  attack_vectors?: string[];
  attack_techniques?: string[];
  mitre_techniques?: string[];
  threat_actors?: string[];
  exploits?: string[];
  exploit_available?: string[];

  exploitability?: string[];
  confidentiality_impacts?: string[];
  integrity_impacts?: string[];
  availability_impacts?: string[];

  findings?: NlpEngineFinding[];
  meta?: NlpEngineMeta;

  [key: string]: unknown;
};

export type RunNlpEngineOptions = {
  mode?: NlpEngineMode;
  timeoutMs?: number;

  // Optional overrides used by the upgraded Python CLI.
  modelDir?: string;
  minModelF1?: number;
  minEntityConfidence?: number;
  useRegexEnrichment?: boolean;
  includeMeta?: boolean;
  includeFindings?: boolean;
};
