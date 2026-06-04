import { getSessionCookieName, getSessionCookieOptions } from '@/lib/auth-session'
import { NextResponse } from 'next/server'

export async function POST() {
  try {
    const response = NextResponse.json({ success: true })

    response.cookies.set(getSessionCookieName(), '', {
      ...getSessionCookieOptions(),
      maxAge: 0,
      expires: new Date(0),
    })

    response.cookies.set('session', '', {
      ...getSessionCookieOptions(),
      maxAge: 0,
      expires: new Date(0),
    })

    return response
  } catch (error: any) {
    return NextResponse.json({ error: error.message || 'Logout failed' }, { status: 500 })
  }
}