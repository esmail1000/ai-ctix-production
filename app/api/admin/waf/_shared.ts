import crypto from 'crypto'
import { NextRequest, NextResponse } from 'next/server'
import path from 'path'

export const WAF_DIR = path.join(process.cwd(), 'waf_simulation')
export const BLOCKED_IPS_FILE = path.join(WAF_DIR, 'blocked_ips.json')
export const REPORTS_DIR = path.join(WAF_DIR, 'waf_reports')
export const PDF_REPORTS_DIR = path.join(WAF_DIR, 'waf_pdf_reports')

export const WAF_ADMIN_COOKIE = 'waf_admin_session'

function sessionSecret() {
  return process.env.WAF_SESSION_SECRET || process.env.NEXTAUTH_SECRET || process.env.WAF_ADMIN_TOKEN || 'ai-ctix-waf-session'
}

export function createWafAdminSession(token: string) {
  return crypto.createHmac('sha256', sessionSecret()).update(token).digest('hex')
}

export function isValidWafAdminSession(value?: string | null) {
  const expected = process.env.WAF_ADMIN_TOKEN
  if (!expected || !value) return false

  const expectedSession = createWafAdminSession(expected)
  try {
    return crypto.timingSafeEqual(Buffer.from(value), Buffer.from(expectedSession))
  } catch {
    return false
  }
}

export function requireWafAdmin(request: NextRequest) {
  const expected = process.env.WAF_ADMIN_TOKEN
  const provided = request.headers.get('x-waf-admin-token') || ''
  const cookieValue = request.cookies.get(WAF_ADMIN_COOKIE)?.value || ''

  if (!expected) {
    return NextResponse.json(
      { error: 'WAF_ADMIN_TOKEN is not configured on the server.' },
      { status: 503 }
    )
  }

  if (provided === expected || isValidWafAdminSession(cookieValue)) return null

  return NextResponse.json(
    { error: 'Invalid WAF admin session.' },
    { status: 401 }
  )
}

export function safeString(value: unknown, fallback = ''): string {
  return typeof value === 'string' && value.trim() ? value.trim() : fallback
}

export function safeTenant(value: unknown): string {
  return safeString(value, 'default_tenant').replace(/[^a-zA-Z0-9_-]/g, '') || 'default_tenant'
}

export function safeIncidentId(value: unknown): string {
  return safeString(value).replace(/[^a-zA-Z0-9_-]/g, '')
}
