import { NextRequest, NextResponse } from 'next/server'
import path from 'path'

export const WAF_DIR = path.join(process.cwd(), 'waf_simulation')
export const BLOCKED_IPS_FILE = path.join(WAF_DIR, 'blocked_ips.json')
export const REPORTS_DIR = path.join(WAF_DIR, 'waf_reports')
export const PDF_REPORTS_DIR = path.join(WAF_DIR, 'waf_pdf_reports')

export function requireWafAdmin(request: NextRequest) {
  const expected = process.env.WAF_ADMIN_TOKEN
  const provided = request.headers.get('x-waf-admin-token') || ''

  if (!expected) {
    return NextResponse.json(
      { error: 'WAF_ADMIN_TOKEN is not configured on the server.' },
      { status: 503 }
    )
  }

  if (!provided || provided !== expected) {
    return NextResponse.json(
      { error: 'Invalid WAF admin token.' },
      { status: 401 }
    )
  }

  return null
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
