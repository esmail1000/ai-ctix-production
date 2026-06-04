import { NextResponse } from 'next/server'
import { getUserByEmail, getUserByUsername, verifyPassword } from '@/lib/server/auth-db'
import { createSessionToken, getSessionCookieName } from '@/lib/auth-session'
import {
  checkRateLimit,
  getClientIp,
  getRateLimitHeaders,
} from '@/lib/server/rate-limit'

export async function POST(request: Request) {
  try {
    const body = await request.json()
    const username = String(body.username || '').trim()
    const password = String(body.password || '')
    const loginId = username.trim().toLowerCase()
    const clientIp = getClientIp(request)

    const rateLimit = await checkRateLimit({
      action: 'auth.login',
      identifier: `${clientIp}:${loginId || 'anonymous'}`,
      limit: 5,
      windowMs: 15 * 60 * 1000,
    })

    if (!rateLimit.allowed) {
      return NextResponse.json(
        { error: 'Too many login attempts. Please try again later.' },
        {
          status: 429,
          headers: getRateLimitHeaders(rateLimit),
        }
      )
    }

    const rateLimitHeaders = getRateLimitHeaders(rateLimit)

    if (!username || !password) {
      return NextResponse.json(
        { error: 'Username/email and password are required' },
        {
          status: 400,
          headers: rateLimitHeaders,
        }
      )
    }

    const user = loginId.includes('@')
      ? await getUserByEmail(loginId)
      : await getUserByUsername(loginId)

    if (!user || !verifyPassword(password, user.passwordHash)) {
      return NextResponse.json(
        { error: 'Invalid username or password' },
        {
          status: 401,
          headers: rateLimitHeaders,
        }
      )
    }

    if (!user.emailVerified && !user.phoneVerified) {
      return NextResponse.json(
        { error: 'Account is not verified yet' },
        {
          status: 403,
          headers: rateLimitHeaders,
        }
      )
    }

    const sessionToken = await createSessionToken({
      userId: user.id,
      username: user.username,
    })

    const response = NextResponse.json(
      {
        success: true,
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
        },
      },
      {
        headers: rateLimitHeaders,
      }
    )

    response.cookies.set(getSessionCookieName(), sessionToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 60 * 60 * 24,
      path: '/',
    })

    response.cookies.delete('session')

    return response
  } catch (error: any) {
    return NextResponse.json(
      { error: error.message || 'Login failed' },
      { status: 500 }
    )
  }
}