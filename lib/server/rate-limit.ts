import { createHash } from 'crypto'
import { prisma } from '@/lib/server/prisma'

export type RateLimitResult = {
  allowed: boolean
  limit: number
  remaining: number
  resetAt: Date
  retryAfterSeconds: number
}

export type RateLimitInput = {
  action: string
  identifier: string
  limit: number
  windowMs: number
}

function getSecret() {
  return (
    process.env.RATE_LIMIT_SECRET ||
    process.env.AUTH_SECRET ||
    'dev-rate-limit-secret'
  )
}

function hashIdentifier(value: string) {
  return createHash('sha256')
    .update(`${getSecret()}:${value}`)
    .digest('hex')
    .slice(0, 48)
}

export function getClientIp(request: Request) {
  const forwardedFor = request.headers.get('x-forwarded-for')
  const realIp = request.headers.get('x-real-ip')

  if (forwardedFor) {
    return forwardedFor.split(',')[0]?.trim() || 'unknown'
  }

  return realIp?.trim() || 'unknown'
}

export function getRateLimitHeaders(result: RateLimitResult) {
  const headers: Record<string, string> = {
    'X-RateLimit-Limit': String(result.limit),
    'X-RateLimit-Remaining': String(result.remaining),
    'X-RateLimit-Reset': result.resetAt.toISOString(),
  }

  if (!result.allowed) {
    headers['Retry-After'] = String(result.retryAfterSeconds)
  }

  return headers
}

export async function checkRateLimit(input: RateLimitInput): Promise<RateLimitResult> {
  const now = new Date()
  const resetAt = new Date(now.getTime() + input.windowMs)
  const key = `rl:${input.action}:${hashIdentifier(input.identifier)}`

  const current = await prisma.rateLimitBucket.findUnique({
    where: { key },
  })

  if (!current || current.resetAt.getTime() <= now.getTime()) {
    await prisma.rateLimitBucket.upsert({
      where: { key },
      create: {
        key,
        count: 1,
        resetAt,
      },
      update: {
        count: 1,
        resetAt,
      },
    })

    return {
      allowed: true,
      limit: input.limit,
      remaining: Math.max(input.limit - 1, 0),
      resetAt,
      retryAfterSeconds: 0,
    }
  }

  if (current.count >= input.limit) {
    const retryAfterSeconds = Math.max(
      Math.ceil((current.resetAt.getTime() - now.getTime()) / 1000),
      1
    )

    return {
      allowed: false,
      limit: input.limit,
      remaining: 0,
      resetAt: current.resetAt,
      retryAfterSeconds,
    }
  }

  const updated = await prisma.rateLimitBucket.update({
    where: { key },
    data: {
      count: {
        increment: 1,
      },
    },
  })

  return {
    allowed: true,
    limit: input.limit,
    remaining: Math.max(input.limit - updated.count, 0),
    resetAt: updated.resetAt,
    retryAfterSeconds: 0,
  }
}