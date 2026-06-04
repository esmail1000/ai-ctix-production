export type SessionPayload = {
  sub: string
  username: string
  iat: number
  exp: number
}

const DEFAULT_COOKIE_NAME = 'ai_ctix_session'
const SESSION_TTL_SECONDS = 60 * 60 * 24

const encoder = new TextEncoder()
const decoder = new TextDecoder()

function getAuthSecret() {
  const secret = process.env.AUTH_SECRET?.trim()

  if (secret && secret.length >= 32 && secret !== 'change-this-long-random-secret') {
    return secret
  }

  if (process.env.NODE_ENV === 'production') {
    throw new Error('AUTH_SECRET must be set to at least 32 characters in production.')
  }

  return 'dev-only-ai-ctix-session-secret-change-before-production-32chars'
}

export function getSessionCookieName() {
  return process.env.AUTH_COOKIE_NAME || DEFAULT_COOKIE_NAME
}

export function getSessionCookieOptions() {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax' as const,
    maxAge: SESSION_TTL_SECONDS,
    path: '/',
  }
}
function bytesToBase64Url(bytes: Uint8Array) {
  let binary = ''

  for (let index = 0; index < bytes.length; index += 1) {
    binary += String.fromCharCode(bytes[index])
  }

  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '')
}
function base64UrlToBytes(value: string) {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/')
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4)
  const binary = atob(padded)

  return Uint8Array.from(binary, (char) => char.charCodeAt(0))
}

function encodeJson(value: unknown) {
  return bytesToBase64Url(encoder.encode(JSON.stringify(value)))
}

function decodeJson<T>(value: string): T {
  const bytes = base64UrlToBytes(value)
  return JSON.parse(decoder.decode(bytes)) as T
}

async function getSigningKey() {
  return crypto.subtle.importKey(
    'raw',
    encoder.encode(getAuthSecret()),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  )
}

async function sign(data: string) {
  const key = await getSigningKey()
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data))
  return bytesToBase64Url(new Uint8Array(signature))
}

async function verify(data: string, signature: string) {
  try {
    const key = await getSigningKey()
    return await crypto.subtle.verify(
      'HMAC',
      key,
      base64UrlToBytes(signature),
      encoder.encode(data)
    )
  } catch {
    return false
  }
}

export async function createSessionToken(input: {
  userId: string
  username: string
  ttlSeconds?: number
}) {
  const now = Math.floor(Date.now() / 1000)
  const ttl = input.ttlSeconds ?? SESSION_TTL_SECONDS

  const header = encodeJson({ alg: 'HS256', typ: 'JWT' })
  const payload = encodeJson({
    sub: input.userId,
    username: input.username,
    iat: now,
    exp: now + ttl,
  } satisfies SessionPayload)

  const data = `${header}.${payload}`
  const signature = await sign(data)

  return `${data}.${signature}`
}

export async function readSessionToken(token?: string | null): Promise<SessionPayload | null> {
  try {
    if (!token || token.length > 4096) return null

    const parts = token.split('.')
    if (parts.length !== 3) return null

    const [header, payload, signature] = parts
    const data = `${header}.${payload}`

    const valid = await verify(data, signature)
    if (!valid) return null

    const session = decodeJson<SessionPayload>(payload)
    const now = Math.floor(Date.now() / 1000)

    if (!session.sub || !session.username || !session.exp || session.exp <= now) {
      return null
    }

    return session
  } catch {
    return null
  }
}