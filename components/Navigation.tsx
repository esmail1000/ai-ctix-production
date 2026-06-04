'use client'

import Link from 'next/link'
import { usePathname, useRouter } from 'next/navigation'
import { useEffect, useState } from 'react'

const navItems = [
  { label: 'Home', href: '/' },
  { label: 'Dashboard', href: '/dashboard' },
  { label: 'Reports', href: '/reports' },
  { label: 'Findings', href: '/results' },
  { label: 'Analyze Report', href: '/analyzer' },
  { label: 'Export', href: '/export' },
]

function isActivePath(pathname: string, href: string) {
  if (href === '/') return pathname === '/'
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
  const [isOpen, setIsOpen] = useState(false)
  const [user, setUser] = useState<{ username: string } | null>(null)

  useEffect(() => {
    setIsOpen(false)
  }, [pathname])

  const fetchUser = async () => {
    try {
      const res = await fetch('/api/auth/me')
      if (res.ok) {
        const data = await res.json()
        setUser(data.user)
      }
    } catch {}
  }

  useEffect(() => {
    fetchUser()
  }, [pathname])

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') setIsOpen(false)
    }

    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [])

  const handleLogout = async () => {
    try {
      await fetch('/api/auth/logout', { method: 'POST' })
      setUser(null)
      router.push('/login')
      router.refresh()
    } catch {}
  }

  const isAuthPage = pathname === '/login' || pathname === '/register' || pathname === '/blocked'

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
            <p className="hidden text-sm text-[#5a7668] sm:block">Cyber threat report analysis</p>
          </div>
        </Link>

        {user && !isAuthPage && (
          <nav
            className="hidden items-center gap-2 rounded-[22px] p-2 lg:flex"
            aria-label="Primary navigation"
          >
            {navItems.map((item) => (
              <NavLink key={item.href} href={item.href} label={item.label} pathname={pathname} />
            ))}
          </nav>
        )}

        <div className="flex items-center gap-3">
          {user ? (
            <div className="flex items-center gap-4">
              <span className="hidden text-sm font-medium text-[#173128] sm:inline-block">
                Hello, <span className="font-semibold text-[#15803d]">{user.username}</span>
              </span>
              <button
                onClick={handleLogout}
                className="rounded-xl border border-red-200 bg-red-50 px-4 py-2 text-sm font-medium text-red-600 hover:bg-red-100 transition-all duration-200"
              >
                Logout
              </button>
            </div>
          ) : (
            !isAuthPage && (
              <Link
                href="/login"
                className="rounded-xl bg-[#15803d] px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-[#166534] transition-all duration-200"
              >
                Sign In
              </Link>
            )
          )}

          {user && !isAuthPage && (
            <button
              type="button"
              onClick={() => setIsOpen((current) => !current)}
              className="inline-flex h-11 w-11 items-center justify-center rounded-2xl border border-[#c4e3cf] bg-white text-[#173128] shadow-sm transition hover:bg-[#edfdf3] focus:outline-none focus:ring-2 focus:ring-emerald-500 focus:ring-offset-2 lg:hidden"
              aria-label="Toggle navigation menu"
              aria-expanded={isOpen}
            >
              <span aria-hidden="true" className="text-xl font-semibold">
                {isOpen ? '×' : '☰'}
              </span>
            </button>
          )}
        </div>
      </div>

      {isOpen && user && !isAuthPage ? (
        <div className="border-t border-[#dff0e6] bg-white px-6 py-4 shadow-lg lg:hidden">
          <nav className="mx-auto grid max-w-7xl gap-2" aria-label="Mobile navigation">
            {navItems.map((item) => (
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
