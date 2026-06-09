import { NextRequest, NextResponse } from 'next/server'
import { getSessionCookieName, readSessionToken } from '@/lib/auth-session'

const publicPages = new Set([
  '/check-email',
  '/',
  '/login',
  '/register',
  '/forgot-password',
  '/reset-password',
  '/waf-admin-control',
])

const publicApiRoutes = new Set([
  '/api/auth/login',
  '/api/auth/logout',
  '/api/auth/me',
  '/api/auth/register',
  '/api/auth/verify',
  '/api/auth/forgot-password',
  '/api/auth/reset-password',
])

function applySecurityHeaders(response: NextResponse) {
  response.headers.set('X-Frame-Options', 'DENY')
  response.headers.set('X-Content-Type-Options', 'nosniff')
  response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin')
  response.headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
  return response
}


function getSafeNextPath(value: string | null) {
  if (!value) return '/dashboard'
  if (!value.startsWith('/') || value.startsWith('//')) return '/dashboard'
  if (value.startsWith('/api/')) return '/dashboard'
  return value
}

function isPublicPage(pathname: string) {
  if (publicPages.has(pathname)) return true
  if (pathname.startsWith('/reset-password')) return true
  return false
}

function isPublicApi(pathname: string) {
  if (publicApiRoutes.has(pathname)) return true

  // WAF owner APIs are protected by their own WAF admin cookie/token.
  // They must not require a normal application user account.
  if (pathname.startsWith('/api/admin/waf')) return true

  return false
}

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl

  const token = request.cookies.get(getSessionCookieName())?.value
  const session = token ? await readSessionToken(token) : null

  if (isPublicApi(pathname)) {
    return applySecurityHeaders(NextResponse.next())
  }

  if (isPublicPage(pathname)) {
    // Owner-only WAF page must remain outside normal user auth redirects.
    // The page itself shows the owner token login if no WAF admin session exists.
    if (pathname === '/waf-admin-control') {
      return applySecurityHeaders(NextResponse.next())
    }

    if (session && (pathname === '/login' || pathname === '/register')) {
      const nextPath = getSafeNextPath(request.nextUrl.searchParams.get('next'))
      const url = new URL(nextPath, request.url)
      return applySecurityHeaders(NextResponse.redirect(url))
    }

    return applySecurityHeaders(NextResponse.next())
  }

  if (!session) {
    if (pathname.startsWith('/api/')) {
      return applySecurityHeaders(
        NextResponse.json({ error: 'Authentication required.' }, { status: 401 })
      )
    }

    const url = request.nextUrl.clone()
    url.pathname = '/login'
    url.search = ''
    url.searchParams.set('next', `${pathname}${request.nextUrl.search}`)
    return applySecurityHeaders(NextResponse.redirect(url))
  }

  return applySecurityHeaders(NextResponse.next())
}

export const config = {
  matcher: [
    '/((?!_next/static|_next/image|favicon.ico|icon.png|apple-icon.png|.*\.(?:png|jpg|jpeg|gif|svg|ico|css|js|map|txt)$).*)',
  ],
}
