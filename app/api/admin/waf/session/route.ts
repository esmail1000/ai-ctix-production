import { NextRequest, NextResponse } from 'next/server'
import { createWafAdminSession, WAF_ADMIN_COOKIE } from '../_shared'

export const dynamic = 'force-dynamic'

export async function POST(request: NextRequest) {
  const expected = process.env.WAF_ADMIN_TOKEN
  if (!expected) {
    return NextResponse.json({ error: 'WAF_ADMIN_TOKEN is not configured on the server.' }, { status: 503 })
  }

  const body = await request.json().catch(() => ({}))
  const token = typeof body.token === 'string' ? body.token : ''

  if (token !== expected) {
    return NextResponse.json({ error: 'Invalid WAF admin token.' }, { status: 401 })
  }

  const res = NextResponse.json({ ok: true })
  res.cookies.set(WAF_ADMIN_COOKIE, createWafAdminSession(expected), {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    path: '/',
    maxAge: 60 * 60 * 4,
  })
  return res
}

export async function DELETE() {
  const res = NextResponse.json({ ok: true })
  res.cookies.set(WAF_ADMIN_COOKIE, '', {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    path: '/',
    maxAge: 0,
  })
  return res
}
