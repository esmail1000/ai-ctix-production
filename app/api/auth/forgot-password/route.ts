import { NextResponse } from 'next/server'
import { createPasswordResetToken } from '@/lib/server/auth-db'
import { sendPasswordResetEmail } from '@/lib/server/mailer'
import {
  checkRateLimit,
  getClientIp,
  getRateLimitHeaders,
} from '@/lib/server/rate-limit'

export async function POST(request: Request) {
  try {
    const body = await request.json()
    const email = String(body.email || '').trim().toLowerCase()
    const clientIp = getClientIp(request)

    const rateLimit = await checkRateLimit({
      action: 'auth.forgot-password',
      identifier: `${clientIp}:${email || 'anonymous'}`,
      limit: 3,
      windowMs: 30 * 60 * 1000,
    })

    if (!rateLimit.allowed) {
      return NextResponse.json(
        { error: 'Too many password reset requests. Please try again later.' },
        {
          status: 429,
          headers: getRateLimitHeaders(rateLimit),
        }
      )
    }

    const rateLimitHeaders = getRateLimitHeaders(rateLimit)

    if (!email || !email.includes('@')) {
      return NextResponse.json(
        { error: 'Please enter a valid email address.' },
        {
          status: 400,
          headers: rateLimitHeaders,
        }
      )
    }

    const result = await createPasswordResetToken(email)

    if (result) {
      const baseUrl =
        process.env.APP_BASE_URL?.replace(/\/$/, '') || new URL(request.url).origin

      const resetLink = `${baseUrl}/reset-password?token=${encodeURIComponent(result.token)}`

      await sendPasswordResetEmail({
        toEmail: result.user.email,
        username: result.user.username,
        resetLink,
      })
    }

    return NextResponse.json(
      {
        success: true,
        message: 'If this email exists, a password reset link has been sent.',
        redirectTo: '/check-email',
      },
      {
        headers: rateLimitHeaders,
      }
    )
  } catch (error) {
    return NextResponse.json(
      {
        error:
          error instanceof Error
            ? error.message
            : 'Failed to process password reset request.',
      },
      { status: 500 }
    )
  }
}