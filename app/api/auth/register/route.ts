import { NextResponse } from 'next/server'
import { getUserByUsername, registerUser } from '@/lib/server/auth-db'
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
    const email = String(body.email || '').trim()
    const phone = String(body.phone || '').trim()
    const clientIp = getClientIp(request)

    const rateLimit = await checkRateLimit({
      action: 'auth.register',
      identifier: clientIp,
      limit: 3,
      windowMs: 30 * 60 * 1000,
    })

    if (!rateLimit.allowed) {
      return NextResponse.json(
        { error: 'Too many registration attempts. Please try again later.' },
        {
          status: 429,
          headers: getRateLimitHeaders(rateLimit),
        }
      )
    }

    const rateLimitHeaders = getRateLimitHeaders(rateLimit)

    if (!username || !password || !email || !phone) {
      return NextResponse.json(
        { error: 'All fields are required: username, password, email, phone.' },
        {
          status: 400,
          headers: rateLimitHeaders,
        }
      )
    }

    if (username.length < 3) {
      return NextResponse.json(
        { error: 'Username must be at least 3 characters.' },
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

    if (!email.includes('@')) {
      return NextResponse.json(
        { error: 'Please enter a valid email address.' },
        {
          status: 400,
          headers: rateLimitHeaders,
        }
      )
    }

    if (phone.length < 8) {
      return NextResponse.json(
        { error: 'Please enter a valid phone number.' },
        {
          status: 400,
          headers: rateLimitHeaders,
        }
      )
    }

    const existing = await getUserByUsername(username)
    if (existing) {
      return NextResponse.json(
        { error: 'Username is already taken.' },
        {
          status: 400,
          headers: rateLimitHeaders,
        }
      )
    }

    const { user, sentRealEmail } = await registerUser(
      username,
      password,
      email,
      phone,
      'email'
    )

    return NextResponse.json(
      {
        success: true,
        userId: user.id,
        verificationChannel: 'email',
        sentRealEmail,
        message: 'Verification code sent to your email.',
      },
      {
        headers: rateLimitHeaders,
      }
    )
  } catch (error: any) {
    return NextResponse.json(
      { error: error.message || 'Registration failed.' },
      { status: 500 }
    )
  }
}