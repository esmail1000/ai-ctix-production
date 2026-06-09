'use client'

import Link from 'next/link'
import { usePathname, useRouter } from 'next/navigation'
import { useEffect, useRef, useState } from 'react'

const mainNavItems = [
  { label: 'Home', href: '/' },
  { label: 'Dashboard', href: '/dashboard' },
  { label: 'Reports', href: '/reports' },
  { label: 'Findings', href: '/results' },
  { label: 'Analyze Report', href: '/analyzer' },
  { label: 'Export', href: '/export' },
]

const moreNavItems = [
  { label: 'Threat Intel', href: '/threat-intel' },
  { label: 'Knowledge Graph', href: '/graph' },
  { label: 'Attack Paths', href: '/attack-paths' },
  { label: 'Risk Scoring', href: '/risk-scoring' },
  { label: 'Summarization', href: '/summarization' },
  { label: 'Recommendations', href: '/recommendations' },
  { label: 'WAF Control', href: '/waf-admin-control' },
]

function isActivePath(pathname: string, href: string) {
  if (href === '/') return pathname === '/'
  if (href === '/dashboard') return pathname === '/dashboard' || pathname === '/dashboard/waf'
  return pathname === href || pathname.startsWith(`${href}/`)
}

function NavLink({
  href,
  label,
  pathname,
  onClick,
}: {
  href: string
  label: string
  pathname: string
  onClick?: () => void
}) {
  const isActive = isActivePath(pathname, href)

  return (
    <Link
      href={href}
      onClick={onClick}
      aria-current={isActive ? 'page' : undefined}
      className={`rounded-xl px-4 py-2 text-sm font-medium transition-all duration-200 ${
        isActive
          ? 'bg-[#15803d] text-white shadow-sm'
          : 'border border-[#cbe8d6] bg-white text-[#173128] hover:bg-[#edfdf3] hover:text-[#14532d]'
      }`}
    >
      {label}
    </Link>
  )
}

export default function Navigation() {
  const pathname = usePathname()
  const router = useRouter()
  const moreRef = useRef<HTMLDivElement | null>(null)

  const [isOpen, setIsOpen] = useState(false)
  const [isMoreOpen, setIsMoreOpen] = useState(false)
  const [user, setUser] = useState<{ username?: string; email?: string } | null>(null)

  const isAuthPage = [
    '/login',
    '/register',
    '/forgot-password',
    '/reset-password',
    '/check-email',
    '/blocked',
  ].some((route) => pathname === route || pathname.startsWith(`${route}/`))

  const hasUser = Boolean(user)

  useEffect(() => {
    setIsOpen(false)
    setIsMoreOpen(false)
  }, [pathname])

  useEffect(() => {
    async function fetchUser() {
      try {
        const res = await fetch('/api/auth/me', { cache: 'no-store' })

        if (!res.ok) {
          setUser(null)
          return
        }

        const data = await res.json()
        setUser(data.user ?? null)
      } catch {
        setUser(null)
      }
    }

    fetchUser()
  }, [pathname])

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        setIsOpen(false)
        setIsMoreOpen(false)
      }
    }

    function onPointerDown(event: PointerEvent) {
      if (!moreRef.current) return
      if (!moreRef.current.contains(event.target as Node)) {
        setIsMoreOpen(false)
      }
    }

    window.addEventListener('keydown', onKeyDown)
    window.addEventListener('pointerdown', onPointerDown)

    return () => {
      window.removeEventListener('keydown', onKeyDown)
      window.removeEventListener('pointerdown', onPointerDown)
    }
  }, [])

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

  return (
    <header className="sticky top-0 z-50 border-b border-[#dff0e6] bg-white/95 backdrop-blur">
      <div className="mx-auto flex max-w-7xl items-center justify-between gap-4 px-6 py-4 lg:px-8">
        <Link href="/" className="flex items-center gap-3" aria-label="AI CTIX home">
          <div className="logo-mark">
            <img src="/logo.jpeg" alt="AI CTIX logo" className="h-full w-full object-contain" />
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

        {hasUser && !isAuthPage ? (
          <nav
            className="hidden items-center gap-2 rounded-[22px] p-2 xl:flex"
            aria-label="Primary navigation"
          >
            {mainNavItems.map((item) => (
              <NavLink key={item.href} href={item.href} label={item.label} pathname={pathname} />
            ))}

            <div ref={moreRef} className="relative">
              <button
                type="button"
                onClick={() => setIsMoreOpen((value) => !value)}
                className={`rounded-xl px-4 py-2 text-sm font-medium transition-all duration-200 ${
                  moreNavItems.some((item) => isActivePath(pathname, item.href))
                    ? 'bg-[#15803d] text-white shadow-sm'
                    : 'border border-[#cbe8d6] bg-white text-[#173128] hover:bg-[#edfdf3] hover:text-[#14532d]'
                }`}
                aria-expanded={isMoreOpen}
                aria-haspopup="menu"
              >
                More
              </button>

              {isMoreOpen ? (
                <div
                  role="menu"
                  className="absolute right-0 top-full mt-3 w-64 rounded-2xl border border-[#dff0e6] bg-white p-2 shadow-xl"
                >
                  {moreNavItems.map((item) => {
                    const active = isActivePath(pathname, item.href)

                    return (
                      <Link
                        key={item.href}
                        href={item.href}
                        role="menuitem"
                        className={`block rounded-xl px-4 py-3 text-sm font-medium transition ${
                          active
                            ? 'bg-[#15803d] text-white'
                            : 'text-[#173128] hover:bg-[#edfdf3] hover:text-[#14532d]'
                        }`}
                      >
                        {item.label}
                      </Link>
                    )
                  })}
                </div>
              ) : null}
            </div>
          </nav>
        ) : null}

        <div className="flex items-center gap-3">
          {hasUser ? (
            <div className="flex items-center gap-4">
              <span className="hidden text-sm font-medium text-[#173128] sm:inline-block">
                Hello,{' '}
                <span className="font-semibold text-[#15803d]">
                  {user?.username || user?.email || 'Analyst'}
                </span>
              </span>

              <button
                type="button"
                onClick={handleLogout}
                className="rounded-xl border border-red-200 bg-red-50 px-4 py-2 text-sm font-medium text-red-600 transition-all duration-200 hover:bg-red-100"
              >
                Logout
              </button>
            </div>
          ) : (
            !isAuthPage && (
              <Link
                href="/login"
                className="rounded-xl bg-[#15803d] px-4 py-2 text-sm font-medium text-white shadow-sm transition-all duration-200 hover:bg-[#166534]"
              >
                Sign In
              </Link>
            )
          )}

          {hasUser && !isAuthPage ? (
            <button
              type="button"
              onClick={() => setIsOpen((current) => !current)}
              className="inline-flex h-11 w-11 items-center justify-center rounded-2xl border border-[#c4e3cf] bg-white text-[#173128] shadow-sm transition hover:bg-[#edfdf3] focus:outline-none focus:ring-2 focus:ring-emerald-500 focus:ring-offset-2 xl:hidden"
              aria-label="Toggle navigation menu"
              aria-expanded={isOpen}
            >
              <span aria-hidden="true" className="text-xl font-semibold">
                {isOpen ? '×' : '☰'}
              </span>
            </button>
          ) : null}
        </div>
      </div>

      {isOpen && hasUser && !isAuthPage ? (
        <div className="border-t border-[#dff0e6] bg-white px-6 py-4 shadow-lg xl:hidden">
          <nav className="mx-auto grid max-w-7xl gap-2" aria-label="Mobile navigation">
            {[...mainNavItems, ...moreNavItems].map((item) => (
              <NavLink
                key={item.href}
                href={item.href}
                label={item.label}
                pathname={pathname}
                onClick={() => setIsOpen(false)}
              />
            ))}
          </nav>
        </div>
      ) : null}
    </header>
  )
}