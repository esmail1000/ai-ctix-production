import { getSessionCookieName, readSessionToken } from '@/lib/auth-session'
import { cookies } from 'next/headers'
import { NextResponse } from 'next/server'

export async function GET() {
  try {
    const cookieStore = await cookies()
    const token = cookieStore.get(getSessionCookieName())?.value
    const session = await readSessionToken(token)

    if (!session) {
      return NextResponse.json({ user: null })
    }

    return NextResponse.json({
      user: {
        id: session.sub,
        username: session.username,
      },
    })
  } catch (error: any) {
    return NextResponse.json({ user: null, error: error.message })
  }
}