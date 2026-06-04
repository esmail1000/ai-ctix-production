import { NextResponse } from 'next/server'
import { resetPasswordWithToken } from '@/lib/server/auth-db'
import { sendPasswordChangedEmail } from '@/lib/server/mailer'
import { createSessionToken, getSessionCookieName } from '@/lib/auth-session'
import {
  checkRateLimit,
  getClientIp,
  getRateLimitHeaders,
} from '@/lib/server/rate-limit'

export async function POST(request: Request) {
  try {
    const body = await request.json()
    const token = String(body.token || '').trim()
    const password = String(body.password || '')
    const clientIp = getClientIp(request)

    const rateLimit = await checkRateLimit({
      action: 'auth.reset-password',
      identifier: clientIp,
      limit: 5,
      windowMs: 15 * 60 * 1000,
    })

    if (!rateLimit.allowed) {
      return NextResponse.json(
        { error: 'Too many password reset attempts. Please try again later.' },
        {
          status: 429,
          headers: getRateLimitHeaders(rateLimit),
        }
      )
    }

    const rateLimitHeaders = getRateLimitHeaders(rateLimit)

    if (!token) {
      return NextResponse.json(
        { error: 'Reset token is missing.' },
        {
          status: 400,
          headers: rateLimitHeaders,
        }
      )
    }

    if (password.length < 8) {
      return NextResponse.json(
        { error: 'Password must be at least 8 characters.' },
        {
          status: 400,
          headers: rateLimitHeaders,
        }
      )
    }

    const user = await resetPasswordWithToken(token, password)

    if (!user) {
      return NextResponse.json(
        { error: 'Reset link is invalid or expired.' },
        {
          status: 400,
          headers: rateLimitHeaders,
        }
      )
    }

    try {
      await sendPasswordChangedEmail({
        toEmail: user.email,
        username: user.username,
      })
    } catch (error) {
      console.error('[Password Changed Email Error]', error)
    }

    const sessionToken = await createSessionToken({
      userId: user.id,
      username: user.username,
    })

    const response = NextResponse.json(
      {
        success: true,
        message: 'Password changed successfully. Redirecting to your dashboard...',
        redirectTo: '/dashboard',
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
  } catch (error) {
    return NextResponse.json(
      {
        error:
          error instanceof Error
            ? error.message
            : 'Failed to reset password.',
      },
      { status: 500 }
    )
  }
}