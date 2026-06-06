import { promises as fs } from 'fs'
import path from 'path'
import { NextRequest, NextResponse } from 'next/server'
import { BLOCKED_IPS_FILE, requireWafAdmin, safeString } from '../_shared'

export const dynamic = 'force-dynamic'

export async function POST(request: NextRequest) {
  const authError = requireWafAdmin(request)
  if (authError) return authError

  const body = await request.json().catch(() => ({}))
  const ip = safeString(body.ip)
  const unblockAll = Boolean(body.all)

  let blockedIps: Record<string, unknown> = {}
  try {
    blockedIps = JSON.parse(await fs.readFile(BLOCKED_IPS_FILE, 'utf8'))
  } catch {
    blockedIps = {}
  }

  if (unblockAll) {
    blockedIps = {}
  } else if (ip) {
    delete blockedIps[ip]
  } else {
    return NextResponse.json({ error: 'Provide ip or all=true.' }, { status: 400 })
  }

  await fs.mkdir(path.dirname(BLOCKED_IPS_FILE), { recursive: true })
  await fs.writeFile(BLOCKED_IPS_FILE, JSON.stringify(blockedIps, null, 2), 'utf8')

  return NextResponse.json({ ok: true, blockedIps })
}
