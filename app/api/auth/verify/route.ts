import {
  createSessionToken,
  getSessionCookieName,
  getSessionCookieOptions,
} from '@/lib/auth-session'
import { getUserById, verifyUserOtp } from '@/lib/server/auth-db'
import {
  checkRateLimit,
  getClientIp,
  getRateLimitHeaders,
} from '@/lib/server/rate-limit'
import { NextResponse } from 'next/server'

export async function POST(request: Request) {
  try {
    const body = await request.json()
    const userId = String(body.userId || '').trim()
    const otp = String(body.otp || '').trim()
    const clientIp = getClientIp(request)

    const rateLimit = await checkRateLimit({
      action: 'auth.verify',
      identifier: `${clientIp}:${userId || 'anonymous'}`,
      limit: 5,
      windowMs: 15 * 60 * 1000,
    })

    if (!rateLimit.allowed) {
      return NextResponse.json(
        { error: 'Too many verification attempts. Please try again later.' },
        {
          status: 429,
          headers: getRateLimitHeaders(rateLimit),
        }
      )
    }

    const rateLimitHeaders = getRateLimitHeaders(rateLimit)

    if (!userId || !otp) {
      return NextResponse.json(
        { error: 'Verification code is required' },
        {
          status: 400,
          headers: rateLimitHeaders,
        }
      )
    }

    const user = await getUserById(userId)
    if (!user) {
      return NextResponse.json(
        { error: 'User not found' },
        {
          status: 404,
          headers: rateLimitHeaders,
        }
      )
    }

    const verified = await verifyUserOtp(userId, otp)
    if (!verified) {
      return NextResponse.json(
        { error: 'Invalid or expired verification code' },
        {
          status: 400,
          headers: rateLimitHeaders,
        }
      )
    }

    const token = await createSessionToken({
      userId: user.id,
      username: user.username,
    })

    const response = NextResponse.json(
      {
        success: true,
        user: { id: user.id, username: user.username },
      },
      {
        headers: rateLimitHeaders,
      }
    )

    response.cookies.set(getSessionCookieName(), token, getSessionCookieOptions())

    response.cookies.set('session', '', {
      ...getSessionCookieOptions(),
      maxAge: 0,
      expires: new Date(0),
    })

    return response
  } catch (error: any) {
    return NextResponse.json(
      { error: error.message || 'Verification failed' },
      { status: 500 }
    )
  }
}