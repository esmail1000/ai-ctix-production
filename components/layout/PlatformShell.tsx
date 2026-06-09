'use client'

import Link from 'next/link'
import { usePathname, useRouter } from 'next/navigation'
import { useEffect, useMemo, useState } from 'react'

import Breadcrumbs from './Breadcrumbs'
import MobileNav from './MobileNav'
import { getCurrentNavItem } from './navigation-data'
import SidebarNav from './SidebarNav'

type User = {
  username?: string
  email?: string
} | null

function isAuthRoute(pathname: string) {
  return [
    '/login',
    '/register',
    '/forgot-password',
    '/reset-password',
    '/check-email',
    '/blocked',
  ].some((route) => pathname === route || pathname.startsWith(`${route}/`))
}

function isPublicRoute(pathname: string) {
  return pathname === '/' || isAuthRoute(pathname)
}

function PublicHeader({ user }: { user: User }) {
  const isSignedIn = Boolean(user)

  return (
    <header className="sticky top-0 z-50 border-b border-[#dff0e6] bg-white/95 backdrop-blur">
      <div className="mx-auto flex max-w-7xl items-center justify-between gap-4 px-6 py-4 lg:px-8">
        <Link href="/" className="flex items-center gap-3" aria-label="AI CTIX home">
          <div className="flex h-11 w-11 items-center justify-center rounded-2xl border border-[#cbe8d6] bg-[#f2fbf5]">
            <img src="/logo.jpeg" alt="AI CTIX logo" className="h-8 w-8 rounded-xl object-contain" />
          </div>

          <div className="leading-tight">
            <h1 className="text-[1.35rem] font-semibold tracking-tight text-[#0f2b1d]">
              AI CTIX
              <span className="ml-1 font-medium text-[#15803d]">Extractor</span>
            </h1>
            <p className="hidden text-sm text-[#5a7668] sm:block">
              Cyber threat report analysis
            </p>
          </div>
        </Link>

        <div className="flex items-center gap-3">
          {isSignedIn ? (
            <Link
              href="/dashboard"
              className="rounded-xl bg-[#15803d] px-4 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-[#166534]"
            >
              Dashboard
            </Link>
          ) : (
            <>
              <Link
                href="/login"
                className="rounded-xl border border-[#cbe8d6] bg-white px-4 py-2 text-sm font-semibold text-[#173128] transition hover:bg-[#edfdf3]"
              >
                Sign In
              </Link>

              <Link
                href="/register"
                className="hidden rounded-xl bg-[#15803d] px-4 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-[#166534] sm:inline-flex"
              >
                Create Account
              </Link>
            </>
          )}
        </div>
      </div>
    </header>
  )
}

export default function PlatformShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname()
  const router = useRouter()
  const [user, setUser] = useState<User>(null)

  const currentItem = useMemo(() => getCurrentNavItem(pathname), [pathname])
  const publicRoute = isPublicRoute(pathname)
  const showPlatformShell = Boolean(user) && !publicRoute

  useEffect(() => {
    let cancelled = false

    async function loadUser() {
      try {
        const response = await fetch('/api/auth/me', { cache: 'no-store' })

        if (!response.ok) {
          if (!cancelled) setUser(null)
          return
        }

        const data = await response.json()

        if (!cancelled) {
          setUser(data.user ?? null)
        }
      } catch {
        if (!cancelled) setUser(null)
      }
    }

    loadUser()

    return () => {
      cancelled = true
    }
  }, [pathname])

  async function handleLogout() {
    try {
      await fetch('/api/auth/logout', { method: 'POST' })
      setUser(null)
      router.push('/login')
      router.refresh()
    } catch {
      setUser(null)
      router.push('/login')
    }
  }

  if (!showPlatformShell) {
    return (
      <div className="min-h-screen bg-white text-[#0d2217]">
        <PublicHeader user={user} />
        {children}
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-[#f6fbf8] text-[#0d2217]">
      <SidebarNav
        pathname={pathname}
        userName={user?.username || user?.email || 'Analyst'}
        onLogout={handleLogout}
      />

      <MobileNav pathname={pathname} />

      <div className="lg:pl-72">
        <header className="sticky top-0 z-30 border-b border-[#dff0e6] bg-[#f6fbf8]/95 backdrop-blur">
          <div className="flex min-h-20 items-center justify-between gap-4 px-5 py-4 sm:px-6 lg:px-8">
            <div className="min-w-0">
              <Breadcrumbs />

              <div className="mt-1">
                <h1 className="truncate text-xl font-bold tracking-tight text-[#0f2b1d] sm:text-2xl">
                  {currentItem?.label || 'AI CTIX Platform'}
                </h1>

                {currentItem?.description ? (
                  <p className="mt-1 hidden text-sm text-[#5a7668] sm:block">
                    {currentItem.description}
                  </p>
                ) : null}
              </div>
            </div>

            <div className="flex items-center gap-3">
              <Link
                href="/analyzer"
                className="hidden rounded-xl bg-[#15803d] px-4 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-[#166534] sm:inline-flex"
              >
                Analyze Report
              </Link>

              <button
                type="button"
                onClick={handleLogout}
                className="rounded-xl border border-red-200 bg-red-50 px-3 py-2 text-sm font-semibold text-red-600 transition hover:bg-red-100"
              >
                Logout
              </button>
            </div>
          </div>
        </header>

        <main className="px-5 py-6 pb-28 sm:px-6 lg:px-8 lg:pb-10">
          {children}
        </main>
      </div>
    </div>
  )
}