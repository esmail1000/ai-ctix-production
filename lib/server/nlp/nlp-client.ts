import { spawn } from "child_process";
import { promises as fs } from "fs";
import os from "os";
import path from "path";
import type {
  NlpEngineFinding,
  NlpEngineMeta,
  NlpEngineMode,
  NlpEngineResult,
  RunNlpEngineOptions,
} from "./types";

const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_MODE: NlpEngineMode = "auto";
const DEFAULT_MIN_MODEL_F1 = 0.3;
const DEFAULT_MIN_ENTITY_CONFIDENCE = 0.75;
const DEFAULT_NLP_ENGINE_DIR = "nlp_engine";
const DEFAULT_MODEL_RELATIVE_DIR = "nlp_engine/models/cyberbert-ner-v5-real-aug";
const LEGACY_MODEL_RELATIVE_DIR = "nlp_engine/models/cyberbert-ner";

const STRING_ARRAY_FIELDS = [
  "cve_ids",
  "cwe_ids",
  "cvss_scores",
  "cvss_vectors",
  "cpes",
  "vulnerability_types",
  "severity",
  "risk_levels",
  "impacts",
  "remediations",
  "mitigations",
  "patches",
  "products",
  "vendors",
  "versions",
  "affected_components",
  "assets",
  "endpoints",
  "services",
  "ips",
  "ip_ranges",
  "urls",
  "domains",
  "emails",
  "ports",
  "file_paths",
  "file_names",
  "md5_hashes",
  "sha1_hashes",
  "sha256_hashes",
  "hashes",
  "malware",
  "attack_vectors",
  "attack_techniques",
  "mitre_techniques",
  "threat_actors",
  "exploits",
  "exploit_available",
  "exploitability",
  "exploitation_steps",
  "confidentiality_impacts",
  "integrity_impacts",
  "availability_impacts",
] as const;

type StringArrayField = (typeof STRING_ARRAY_FIELDS)[number];

const FINDING_STRING_FIELDS = [
  "vulnerability_type",
  "severity",
  "risk_level",
  "impact",
  "remediation",
  "product",
  "vendor",
  "version",
  "affected_component",
  "asset",
  "endpoint",
  "service",
  "attack_vector",
  "attack_technique",
  "exploitability",
] as const;

function stripQuotes(value: string | undefined | null): string {
  return String(value ?? "")
    .trim()
    .replace(/^['\"]|['\"]$/g, "")
    .trim();
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function asRecord(value: unknown): Record<string, unknown> {
  return isPlainRecord(value) ? value : {};
}

function normalizeText(value: unknown): string {
  return String(value ?? "").replace(/\s+/g, " ").trim();
}

function normalizeStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];

  const seen = new Set<string>();
  const out: string[] = [];

  for (const item of value) {
    const cleaned = normalizeText(item);
    const key = cleaned.toLowerCase();

    if (!cleaned || seen.has(key)) continue;

    seen.add(key);
    out.push(cleaned);
  }

  return out;
}

function normalizeOptionalString(value: unknown): string | undefined {
  const cleaned = normalizeText(value);
  return cleaned || undefined;
}

function parseNumberEnv(value: string | undefined, fallback: number): number {
  const cleaned = stripQuotes(value);
  if (!cleaned) return fallback;

  const parsed = Number(cleaned);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function parseBooleanEnv(value: string | undefined, fallback: boolean): boolean {
  const cleaned = stripQuotes(value).toLowerCase();
  if (!cleaned) return fallback;

  if (["1", "true", "yes", "y", "on"].includes(cleaned)) return true;
  if (["0", "false", "no", "n", "off"].includes(cleaned)) return false;

  return fallback;
}

function normalizeMode(value: unknown): NlpEngineMode {
  const cleaned = normalizeText(value).toLowerCase();

  if (cleaned === "regex" || cleaned === "model" || cleaned === "auto") {
    return cleaned;
  }

  return DEFAULT_MODE;
}

function resolveProjectPath(projectRoot: string, value: string): string {
  const cleaned = stripQuotes(value);
  if (!cleaned) return projectRoot;

  return path.isAbsolute(cleaned) ? cleaned : path.resolve(projectRoot, cleaned);
}

async function pathExists(targetPath: string): Promise<boolean> {
  try {
    await fs.access(targetPath);
    return true;
  } catch {
    return false;
  }
}

async function modelLooksUsable(modelDir: string): Promise<boolean> {
  const configExists = await pathExists(path.join(modelDir, "config.json"));
  if (!configExists) return false;

  const weightFiles = [
    "model.safetensors",
    "pytorch_model.bin",
    "tf_model.h5",
    "flax_model.msgpack",
  ];

  for (const fileName of weightFiles) {
    if (await pathExists(path.join(modelDir, fileName))) return true;
  }

  return false;
}

async function resolveModelDir(params: {
  projectRoot: string;
  optionsModelDir?: string;
}): Promise<{ modelDir: string; warnings: string[] }> {
  const warnings: string[] = [];
  const configuredRaw = stripQuotes(params.optionsModelDir ?? process.env.NLP_MODEL_DIR);

  const defaultModelDir = resolveProjectPath(params.projectRoot, DEFAULT_MODEL_RELATIVE_DIR);
  const legacyModelDir = resolveProjectPath(params.projectRoot, LEGACY_MODEL_RELATIVE_DIR);

  if (configuredRaw) {
    const configuredModelDir = resolveProjectPath(params.projectRoot, configuredRaw);

    if (await modelLooksUsable(configuredModelDir)) {
      return { modelDir: configuredModelDir, warnings };
    }

    if (await modelLooksUsable(defaultModelDir)) {
      warnings.push(
        `Configured NLP_MODEL_DIR was not usable (${configuredModelDir}); using upgraded model ${defaultModelDir}.`
      );
      return { modelDir: defaultModelDir, warnings };
    }

    return { modelDir: configuredModelDir, warnings };
  }

  if (await modelLooksUsable(defaultModelDir)) {
    return { modelDir: defaultModelDir, warnings };
  }

  if (await modelLooksUsable(legacyModelDir)) {
    warnings.push(
      `Upgraded model was not found at ${defaultModelDir}; using legacy model ${legacyModelDir}.`
    );
    return { modelDir: legacyModelDir, warnings };
  }

  return { modelDir: defaultModelDir, warnings };
}

function normalizeMeta(value: unknown, fallbackWarnings: string[] = []): NlpEngineMeta {
  const raw = asRecord(value);
  const warnings = [
    ...normalizeStringArray(raw.warnings),
    ...fallbackWarnings.map(normalizeText).filter(Boolean),
  ];

  const meta: NlpEngineMeta = {
    ...raw,
    engine: normalizeOptionalString(raw.engine) ?? "nlp-hybrid-cti",
    schema_version: normalizeOptionalString(raw.schema_version),
    mode: normalizeOptionalString(raw.mode),
    model_loaded: typeof raw.model_loaded === "boolean" ? raw.model_loaded : undefined,
    model_dir: raw.model_dir === null ? null : normalizeOptionalString(raw.model_dir) ?? undefined,
    fallback_used: typeof raw.fallback_used === "boolean" ? raw.fallback_used : undefined,
    regex_enrichment_used:
      typeof raw.regex_enrichment_used === "boolean" ? raw.regex_enrichment_used : undefined,
    contextual_rule_enrichment_used:
      typeof raw.contextual_rule_enrichment_used === "boolean"
        ? raw.contextual_rule_enrichment_used
        : undefined,
    safety_filter_used:
      typeof raw.safety_filter_used === "boolean" ? raw.safety_filter_used : undefined,
    model_quality: isPlainRecord(raw.model_quality) ? raw.model_quality : undefined,
    model_quality_gate_passed:
      typeof raw.model_quality_gate_passed === "boolean" ? raw.model_quality_gate_passed : undefined,
    min_model_f1: typeof raw.min_model_f1 === "number" ? raw.min_model_f1 : undefined,
    min_entity_confidence:
      typeof raw.min_entity_confidence === "number" ? raw.min_entity_confidence : undefined,
    error: normalizeOptionalString(raw.error),
    node_client_python_command: normalizeOptionalString(raw.node_client_python_command),
    stderr: normalizeOptionalString(raw.stderr),
    timeout_ms: typeof raw.timeout_ms === "number" ? raw.timeout_ms : undefined,
    warnings,
  };

  return meta;
}

function normalizeFinding(value: unknown): NlpEngineFinding {
  const raw = asRecord(value);
  const finding: NlpEngineFinding = { ...raw };
  const mutable = finding as Record<string, unknown>;

  for (const field of FINDING_STRING_FIELDS) {
    const cleaned = normalizeOptionalString(raw[field]);
    if (cleaned) mutable[field] = cleaned;
  }

  for (const field of STRING_ARRAY_FIELDS) {
    if (field in raw) mutable[field] = normalizeStringArray(raw[field]);
  }

  return finding;
}

function normalizeNlpResult(
  rawValue: unknown,
  fallbackWarnings: string[] = []
): NlpEngineResult {
  const raw = asRecord(rawValue);
  const result = {} as NlpEngineResult;
  const mutable = result as unknown as Record<StringArrayField, string[]>;

  for (const field of STRING_ARRAY_FIELDS) {
    mutable[field] = normalizeStringArray(raw[field]);
  }

  result.findings = Array.isArray(raw.findings)
    ? raw.findings.map(normalizeFinding).filter((finding) => Object.keys(finding).length > 0)
    : [];

  result.meta = normalizeMeta(
    raw.meta ?? {
      engine: "nlp-hybrid-cti",
      fallback_used: true,
      warnings: ["NLP result returned without meta object."],
    },
    fallbackWarnings
  );

  return result;
}

function runPythonProcess(params: {
  command: string;
  args: string[];
  cwd: string;
  timeoutMs: number;
}): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(params.command, params.args, {
      cwd: params.cwd,
      shell: false,
      windowsHide: true,
      env: {
        ...process.env,
        PYTHONIOENCODING: "utf-8",
        PYTHONUTF8: "1",
      },
    });

    let stdout = "";
    let stderr = "";
    let settled = false;

    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        child.kill("SIGKILL");
        reject(new Error(`NLP engine timed out after ${params.timeoutMs}ms`));
      }
    }, params.timeoutMs);

    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });

    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });

    child.on("error", (error) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        reject(error);
      }
    });

    child.on("close", (code) => {
      if (settled) return;

      settled = true;
      clearTimeout(timer);

      if (code !== 0) {
        reject(
          new Error(
            `NLP engine failed with exit code ${code}.\nSTDERR:\n${stderr}\nSTDOUT:\n${stdout}`
          )
        );
        return;
      }

      resolve({ stdout, stderr });
    });
  });
}

async function tryRunWithPythonCandidates(params: {
  args: string[];
  cwd: string;
  timeoutMs: number;
}): Promise<{ stdout: string; stderr: string; command: string }> {
  const envPython = stripQuotes(process.env.NLP_PYTHON);

  const candidates = [
    envPython,
    "python",
    process.platform === "win32" ? "py" : "python3",
  ].filter(Boolean) as string[];

  let lastError: unknown = null;

  for (const command of candidates) {
    try {
      const result = await runPythonProcess({
        command,
        args: params.args,
        cwd: params.cwd,
        timeoutMs: params.timeoutMs,
      });

      return {
        ...result,
        command,
      };
    } catch (error) {
      lastError = error;
    }
  }

  throw lastError instanceof Error
    ? lastError
    : new Error("Unable to run NLP engine with available Python commands.");
}

export async function runNlpEngine(
  reportText: string,
  options: RunNlpEngineOptions = {}
): Promise<NlpEngineResult> {
  const projectRoot = process.cwd();
  const nlpRoot = resolveProjectPath(
    projectRoot,
    stripQuotes(process.env.NLP_ENGINE_DIR) || DEFAULT_NLP_ENGINE_DIR
  );
  const inferencePath = path.join(nlpRoot, "inference.py");

  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ctix-nlp-"));
  const inputPath = path.join(tempDir, "input.txt");
  const outputPath = path.join(tempDir, "output.json");

  const mode = normalizeMode(options.mode ?? process.env.NLP_MODE);
  const timeoutMs = options.timeoutMs ?? parseNumberEnv(process.env.NLP_TIMEOUT_MS, DEFAULT_TIMEOUT_MS);
  const minModelF1 =
    options.minModelF1 ?? parseNumberEnv(process.env.NLP_MIN_MODEL_F1, DEFAULT_MIN_MODEL_F1);
  const minEntityConfidence =
    options.minEntityConfidence ??
    parseNumberEnv(process.env.NLP_MIN_ENTITY_CONFIDENCE, DEFAULT_MIN_ENTITY_CONFIDENCE);
  const useRegexEnrichment =
    options.useRegexEnrichment ??
    parseBooleanEnv(
      process.env.NLP_USE_REGEX_ENRICHMENT ?? process.env.NLP_REGEX_ENRICHMENT,
      true
    );
  const includeMeta = options.includeMeta ?? true;
  const includeFindings = options.includeFindings ?? true;

  const nodeWarnings: string[] = [];

  try {
    await fs.access(inferencePath);
    await fs.writeFile(inputPath, reportText || "", "utf8");

    const { modelDir, warnings } = await resolveModelDir({
      projectRoot,
      optionsModelDir: options.modelDir,
    });
    nodeWarnings.push(...warnings);

    const args = [
      inferencePath,
      "--report_text_file",
      inputPath,
      "--output_json",
      outputPath,
      "--model_dir",
      modelDir,
      "--mode",
      mode,
      "--min_model_f1",
      String(minModelF1),
      "--min_entity_confidence",
      String(minEntityConfidence),
    ];

    if (!useRegexEnrichment) args.push("--no_regex_enrichment");
    if (!includeMeta) args.push("--no_meta");
    if (!includeFindings) args.push("--no_findings");

    const processResult = await tryRunWithPythonCandidates({
      args,
      cwd: nlpRoot,
      timeoutMs,
    });

    const outputJson = await fs.readFile(outputPath, "utf8");
    const parsed = JSON.parse(outputJson) as Partial<NlpEngineResult>;
    const stderr = processResult.stderr.trim();

    return normalizeNlpResult(
      {
        ...parsed,
        meta: {
          ...(isPlainRecord(parsed.meta) ? parsed.meta : {}),
          node_client_python_command: processResult.command,
          timeout_ms: timeoutMs,
          stderr: process.env.NLP_DEBUG === "true" && stderr ? stderr : undefined,
        },
      },
      nodeWarnings
    );
  } catch (error) {
    return normalizeNlpResult({
      meta: {
        engine: "nlp-hybrid-cti",
        schema_version: "2.0",
        mode,
        model_loaded: false,
        fallback_used: false,
        regex_enrichment_used: useRegexEnrichment,
        contextual_rule_enrichment_used: useRegexEnrichment,
        timeout_ms: timeoutMs,
        error: error instanceof Error ? error.message : String(error),
        warnings: [
          ...nodeWarnings,
          "NLP engine failed; existing analyzer should continue without blocking.",
        ],
      },
    });
  } finally {
    await fs.rm(tempDir, { recursive: true, force: true }).catch(() => {});
  }
}
