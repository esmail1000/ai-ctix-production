import { promises as fs } from 'fs'
import path from 'path'
import { NextRequest, NextResponse } from 'next/server'
import { PDF_REPORTS_DIR, requireWafAdmin, safeIncidentId, safeTenant } from '../_shared'

export const dynamic = 'force-dynamic'

export async function POST(request: NextRequest) {
  const authError = requireWafAdmin(request)
  if (authError) return authError

  const body = await request.json().catch(() => ({}))
  const tenantId = safeTenant(body.tenantId)
  const incidentId = safeIncidentId(body.incidentId)

  if (!incidentId) {
    return NextResponse.json({ error: 'incidentId is required.' }, { status: 400 })
  }

  const pdfPath = path.join(PDF_REPORTS_DIR, tenantId, `${incidentId}.pdf`)

  try {
    const file = await fs.readFile(pdfPath)
    return new NextResponse(file, {
      status: 200,
      headers: {
        'Content-Type': 'application/pdf',
        'Content-Disposition': `inline; filename="${incidentId}.pdf"`,
        'Cache-Control': 'no-store',
      },
    })
  } catch {
    return NextResponse.json({ error: 'PDF report not found.' }, { status: 404 })
  }
}
