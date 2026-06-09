import { promises as fs } from 'fs'
import path from 'path'
import { NextResponse } from 'next/server'

export const dynamic = 'force-dynamic'
export const runtime = 'nodejs'

function stripQuotes(value: string | undefined) {
  return String(value ?? '').trim().replace(/^["']|["']$/g, '').trim()
}

function envFlag(name: string, fallback = false) {
  const value = stripQuotes(process.env[name]).toLowerCase()

  if (!value) return fallback
  if (['1', 'true', 'yes', 'y', 'on'].includes(value)) return true
  if (['0', 'false', 'no', 'n', 'off'].includes(value)) return false

  return fallback
}

async function exists(filePath: string) {
  try {
    await fs.access(filePath)
    return true
  } catch {
    return false
  }
}

async function readJson(filePath: string) {
  try {
    return JSON.parse(await fs.readFile(filePath, 'utf8')) as Record<string, unknown>
  } catch {
    return null
  }
}

export async function GET() {
  const projectRoot = process.cwd()
  const modelDirRaw = stripQuotes(process.env.NLP_MODEL_DIR) || 'nlp_engine/models/cyberbert-ner'
  const modelDir = path.isAbsolute(modelDirRaw)
    ? modelDirRaw
    : path.resolve(projectRoot, modelDirRaw)

  const configPath = path.join(modelDir, 'config.json')
  const weightCandidates = [
    'model.safetensors',
    'pytorch_model.bin',
    'tf_model.h5',
    'flax_model.msgpack',
  ].map((file) => path.join(modelDir, file))
  const metricsPath = path.join(modelDir, 'test_metrics.json')
  const trainingConfigPath = path.join(modelDir, 'training_config.json')

  const [modelDirExists, configExists, metrics, trainingConfig] = await Promise.all([
    exists(modelDir),
    exists(configPath),
    readJson(metricsPath),
    readJson(trainingConfigPath),
  ])

  const weightResults = await Promise.all(weightCandidates.map(exists))
  const weightFile = weightCandidates.find((_, index) => weightResults[index])
  const finalMetrics = metrics ?? (trainingConfig?.final_metrics as Record<string, unknown> | undefined) ?? null
  const evalF1 = Number(finalMetrics?.eval_f1)
  const minF1 = Number(process.env.NLP_MIN_MODEL_F1 ?? 0.3)
  const metricsFound = Boolean(finalMetrics)
  const qualityGatePassed = metricsFound && Number.isFinite(evalF1) && evalF1 >= minF1

  const status = {
    ok:
      envFlag('ENABLE_NLP') &&
      modelDirExists &&
      configExists &&
      Boolean(weightFile) &&
      (!envFlag('NLP_REQUIRE_QUALITY_GATE', true) || qualityGatePassed),
    enableNlp: envFlag('ENABLE_NLP'),
    strictModel: envFlag('NLP_STRICT_MODEL'),
    requireQualityGate: envFlag('NLP_REQUIRE_QUALITY_GATE', true),
    mode: stripQuotes(process.env.NLP_MODE) || 'auto',
    modelDir,
    modelDirExists,
    configExists,
    weightFile: weightFile ? path.basename(weightFile) : null,
    metricsFound,
    evalF1: Number.isFinite(evalF1) ? evalF1 : null,
    minF1,
    qualityGatePassed,
    notes: [
      !envFlag('ENABLE_NLP') ? 'ENABLE_NLP is not true.' : '',
      !modelDirExists ? 'Model directory is missing.' : '',
      !configExists ? 'config.json is missing.' : '',
      !weightFile ? 'Model weights are missing.' : '',
      envFlag('NLP_REQUIRE_QUALITY_GATE', true) && !qualityGatePassed
        ? 'Quality gate failed or metrics are missing.'
        : '',
    ].filter(Boolean),
  }

  return NextResponse.json(status, { status: status.ok ? 200 : 503 })
}
