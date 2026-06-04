import { cookies } from 'next/headers'
import { getSessionCookieName, readSessionToken } from '@/lib/auth-session'

export async function getCurrentSessionFromCookies() {
  const cookieStore = await cookies()
  const token = cookieStore.get(getSessionCookieName())?.value
  const session = await readSessionToken(token)

  if (!session) {
    return null
  }

  return {
    userId: session.sub,
    username: session.username,
    session,
  }
}