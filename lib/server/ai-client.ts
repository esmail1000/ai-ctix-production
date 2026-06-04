import OpenAI from 'openai'

type JsonSchema = Record<string, unknown>

let cachedClient: OpenAI | null | undefined

function getClient(): OpenAI | null {
  if (cachedClient !== undefined) return cachedClient

  const apiKey = process.env.OPENAI_API_KEY?.trim()
  if (!apiKey) {
    cachedClient = null
    return cachedClient
  }

  cachedClient = new OpenAI({ apiKey })
  return cachedClient
}

export function isAiEnabled(): boolean {
  return Boolean(process.env.OPENAI_API_KEY?.trim())
}

export async function generateStructuredObject<T>({
  model,
  name,
  schema,
  instructions,
  input,
}: {
  model: string
  name: string
  schema: JsonSchema
  instructions: string
  input: string
}): Promise<T> {
  const client = getClient()

  if (!client) {
    throw new Error('OPENAI_API_KEY is not configured.')
  }

  const response = await client.responses.create({
    model,
    instructions,
    input,
    text: {
      format: {
        type: 'json_schema',
        name,
        schema,
        strict: true,
      },
    },
  })

  const outputText = response.output_text?.trim()

  if (!outputText) {
    throw new Error(`No structured output returned for schema "${name}".`)
  }

  try {
    return JSON.parse(outputText) as T
  } catch (error) {
    throw new Error(
      `Failed to parse structured output for "${name}": ${
        error instanceof Error ? error.message : 'unknown parse error'
      }`
    )
  }
}